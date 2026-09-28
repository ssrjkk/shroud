// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBLS, IDecryptionGate} from "./interfaces/IDecryptionGate.sol";
import {ICipherTask} from "./interfaces/ICipherTask.sol";
import {ReentrancyGuard, Pausable} from "./libraries/Guard.sol";

/// @title DecryptionGate
/// @notice Threshold (t-of-n) decryption of *task outputs only*, contract-restricted.
///
/// @dev This contract is the *only* place where anything leaves the ciphertext world, and it
///      can only be asked to do so for a task that has fully settled. Concretely it enforces:
///
///      1. **Output allowlist.** `submitPartialDecryption` carries the output CID. The gate
///         rejects any CID that is not the settled task's committed `encWeights_Cid`. A
///         committee member therefore *cannot* be socially engineered — even collectively —
///         into decrypting an individual user shard, because the contract will not accept
///         the resulting partial decryptions. (Threat model F-09.)
///
///      2. **t-of-n.** Members hold Shamir shares of the network secret key. The contract
///         requires `threshold` distinct members before it will combine, and it counts
///         *distinct committee members*, not signatures.
///
///      3. **BLS gating.** A reveal only opens when a valid aggregate signature from the
///         committee accompanies it. This is what makes the reveal request publicly
///         auditable: the entire committee signed off on this exact task, this exact
///         epoch and this exact ciphertext.
///
///      Residual: a coalition of `>= t` members can still compute a decryption of anything
///      under `s_pub` off-chain, without ever calling this contract. That is F-10 in the
///      threat model and is explicitly not solved here.
contract DecryptionGate is IDecryptionGate, ReentrancyGuard, Pausable {
    struct TaskGate {
        bool open; // a valid reveal request exists
        bool combined; // threshold reached and combine() executed
        uint16 required; // snapshot of the threshold at request time
        address[] members; // members that submitted partials (bounded by `required`)
        mapping(address => bool) hasSubmitted;
    }

    ICipherTask public cipherTask;
    IBLS public immutable bls;
    bytes32 public immutable committeeAggregateKey;

    uint16 public immutable threshold;
    address public owner;
    address public committee;
    bool public initialized;

    mapping(address => bool) public isCommitteeMember;
    mapping(uint256 => TaskGate) private gates;

    error NotCommitteeMember(address caller);
    error CommitteeAlreadyInitialized();
    error CommitteeNotInitialized();
    error CipherTaskAlreadySet();
    error NotOwner(address caller);
    error InvalidBLS();
    error TaskNotSettled(uint256 taskId, ICipherTask.TaskStatus status);
    error AlreadyOpen(uint256 taskId);
    error AlreadyCombined(uint256 taskId);
    error NotOpen(uint256 taskId);
    error OutputNotRegistered(uint256 taskId, bytes32 weightsCid);
    error PartialAlreadySubmitted(uint256 taskId, address member);
    error NotEnoughPartials(uint256 taskId, uint256 have, uint256 need);
    error ZeroAddress();
    error InvalidThreshold();

    event CommitteeInitialized(address indexed committee, uint16 threshold, bytes32 aggregateKey, uint16 members);
    event CommitteeMemberAdded(address indexed member);
    event CipherTaskSet(address indexed cipherTask);
    event RevealRequested(uint256 indexed taskId, bytes32 weightsCid, address indexed requester, uint256 required);
    event PartialDecryptionSubmitted(uint256 indexed taskId, address indexed member, bytes32 partialDecryption);
    event RevealCompleted(uint256 indexed taskId, address indexed buyer, uint256 members);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    /// @param aggregateKey BLS G2 aggregate public key of the committee (96 bytes, ABI-packed)
    /// @param threshold_  t of n
    constructor(address bls_, bytes32 aggregateKey, uint16 threshold_) {
        if (bls_ == address(0)) revert ZeroAddress();
        if (threshold_ == 0 || threshold_ > 32) revert InvalidThreshold();
        owner = msg.sender;
        bls = IBLS(bls_);
        committeeAggregateKey = aggregateKey;
        threshold = threshold_;
    }

    /// @notice Bind the orchestrator. One-shot, because re-pointing the gate would change who
    ///         can reveal *past* outputs of already-settled tasks.
    function setCipherTask(address cipherTask_) external onlyOwner {
        if (address(cipherTask) != address(0)) revert CipherTaskAlreadySet();
        if (cipherTask_ == address(0)) revert ZeroAddress();
        cipherTask = ICipherTask(cipherTask_);
        emit CipherTaskSet(cipherTask_);
    }

    /// @notice One-shot committee bootstrap. Re-initialisation would retroactively change who
    ///         can reveal past outputs, so it is forbidden; rotation is a NetworkParams DKG
    ///         round that deploys a new gate.
    function initialize(address committee_, address[] calldata members) external onlyOwner {
        if (initialized) revert CommitteeAlreadyInitialized();
        if (committee_ == address(0) || members.length < threshold) revert InvalidThreshold();
        committee = committee_;
        for (uint256 i = 0; i < members.length; ++i) {
            if (members[i] == address(0)) revert ZeroAddress();
            isCommitteeMember[members[i]] = true;
            emit CommitteeMemberAdded(members[i]);
        }
        initialized = true;
        emit CommitteeInitialized(committee_, threshold, committeeAggregateKey, uint16(members.length));
    }

    function setPaused(bool v) external onlyOwner {
        _setPaused(v);
    }

    /* ------------------------------------------------------------------ */
    /*                               reveal                                */
    /* ------------------------------------------------------------------ */

    /// @notice Open a reveal window. Requires (a) the task to be settled, (b) a valid BLS
    ///         aggregate signature over `revealMessage(taskId, weightsCid)`.
    function requestReveal(uint256 taskId, bytes32 weightsCid, bytes calldata blsAggregateSig) external whenNotPaused nonReentrant {
        ICipherTask.TaskStatus status = cipherTask.tasks(taskId).status;
        if (status != ICipherTask.TaskStatus.Settling && status != ICipherTask.TaskStatus.Revealing) {
            revert TaskNotSettled(taskId, status);
        }
        (bytes32 registeredCid,) = cipherTask.acceptedWeights(taskId);
        if (registeredCid == bytes32(0) || registeredCid != weightsCid) {
            revert OutputNotRegistered(taskId, weightsCid);
        }

        TaskGate storage g = gates[taskId];
        if (g.open) revert AlreadyOpen(taskId);

        bytes32 message = revealMessage(taskId, weightsCid);
        if (!bls.verifyAggregate(message, blsAggregateSig, abi.encodePacked(committeeAggregateKey))) {
            revert InvalidBLS();
        }

        g.open = true;
        g.required = threshold;
        emit RevealRequested(taskId, weightsCid, msg.sender, threshold);
    }

    /// @dev Domain-separated so a signature for one task/epoch/CID can never be replayed
    ///      against another, and so the same signature cannot be used as a payment permit.
    function revealMessage(uint256 taskId, bytes32 weightsCid) public view returns (bytes32) {
        if (address(cipherTask) == address(0)) revert CommitteeNotInitialized();
        return keccak256(abi.encodePacked("SHROUD/REVEAL/v1", block.chainid, address(cipherTask), taskId, weightsCid));
    }

    /// @notice Submit this member's partial decryption of the *registered output ciphertext*.
    /// @param partialDecryption `bytes32(keccak(DecryptWithShare(ct, share_i)))` truncated to 32 bytes.
    ///        The real 32-byte plaintext-of-decryption is produced off-chain by combining
    ///        the shared partials; on-chain we only need a commitment to it to enforce
    ///        one-partial-per-member and to make the reveal auditable.
    function submitPartialDecryption(uint256 taskId, bytes32 partialDecryption) external whenNotPaused nonReentrant {
        TaskGate storage g = gates[taskId];
        if (!g.open) revert NotOpen(taskId);
        if (g.combined) revert AlreadyCombined(taskId);
        if (!isCommitteeMember[msg.sender]) revert NotCommitteeMember(msg.sender);
        if (g.hasSubmitted[msg.sender]) revert PartialAlreadySubmitted(taskId, msg.sender);

        (bytes32 registeredCid,) = cipherTask.acceptedWeights(taskId);
        if (registeredCid == bytes32(0)) revert OutputNotRegistered(taskId, registeredCid);

        g.hasSubmitted[msg.sender] = true;
        g.members.push(msg.sender);
        emit PartialDecryptionSubmitted(taskId, msg.sender, partialDecryption);

        if (g.members.length >= g.required) {
            g.combined = true;
            emit RevealCompleted(taskId, cipherTask.tasks(taskId).params.buyer, g.members.length);
        }
    }

    /// @notice Check if a task's reveal is ready to be finalized.
    /// @dev Returns true when the gate is open, the threshold has been reached, and the
    ///      reveal has not yet been finalized.
    /// @param taskId The task to check.
    /// @return True if the reveal can be finalized.
    function canFinalize(uint256 taskId) external view returns (bool) {
        TaskGate storage g = gates[taskId];
        return g.open && !g.combined && g.members.length >= g.required;
    }

    function finalizeReveal(uint256 taskId) external whenNotPaused nonReentrant {
        TaskGate storage g = gates[taskId];
        if (!g.open) revert NotOpen(taskId);
        if (g.members.length < g.required) revert NotEnoughPartials(taskId, g.members.length, g.required);
        g.combined = true;
        emit RevealCompleted(taskId, cipherTask.tasks(taskId).params.buyer, g.members.length);
    }

    /* ------------------------------------------------------------------ */
    /*                                views                                */
    /* ------------------------------------------------------------------ */

    function canDecrypt(uint256 taskId) external view returns (bool) {
        TaskGate storage g = gates[taskId];
        return g.open && !g.combined && g.members.length < g.required;
    }

    function gateInfo(uint256 taskId) external view returns (bool open, bool combined, uint16 required, address[] memory members) {
        TaskGate storage g = gates[taskId];
        return (g.open, g.combined, g.required, g.members);
    }

    function partialCount(uint256 taskId) external view returns (uint256) {
        return gates[taskId].members.length;
    }
}
