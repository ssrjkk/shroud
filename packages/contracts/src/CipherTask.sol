// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE} from "@fhevm/solidity/lib/FHE.sol";
import {CoprocessorConfig} from "@fhevm/solidity/lib/Impl.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import "encrypted-types/EncryptedTypes.sol";

import {ICipherTask} from "./interfaces/ICipherTask.sol";
import {IDecryptionGate} from "./interfaces/IDecryptionGate.sol";
import {IProofVerifier} from "./zk/ProofVerifier.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {PaymentVault} from "./payments/PaymentVault.sol";
import {Dividend} from "./libraries/Dividend.sol";
import {ReentrancyGuard, Pausable} from "./libraries/Guard.sol";

/// @title CipherTask — Shroud FHE training orchestrator
/// @notice Escrows a buyer's budget, admits client-side-encrypted contributions, orchestrates
///         training epochs over the ciphertext dataset, verifies ZK proofs of compute, and
///         streams USDC to contributors, compute nodes and the decryption committee.
///
/// @dev ## Why the fhEVM usage here is small on purpose
///
///      The heavy ciphertext work happens off-chain in the Rust compute node: bootstrapping a
///      33-lane dot product on-chain is neither cheap nor necessary. What the coprocessor is
///      used for in *this* contract is the orchestration state — exactly the data that must not
///      be public but does not need to be computed on encrypted data:
///
///        - `euint32 _liveEpoch`     encrypted epoch counter, so a buyer can follow progress
///                                   without learning who contributed what, and when;
///        - `euint32 _sealFlag`      encrypted "dataset sealed" bit for cheap SDK polling;
///        - `euint32 _verifiedNodes` encrypted count of nodes with a valid STARK;
///        - `einput _encState`       the buyer's encrypted accumulator (loss, noise budget,
///                                   epoch checkpoint) attached to `openEpoch`. Nodes decrypt
///                                   it locally with their committee share, branch on it and
///                                   re-encrypt the result. The chain relays it opaquely.
///
///      None of these are decrypted by the protocol. They exist so the orchestration layer
///      inherits fhEVM confidentiality without a coprocessor call per row.
///
///      All money is plain ERC-20. FHE is used for data confidentiality, not for payments.
contract CipherTask is ICipherTask, ReentrancyGuard, Pausable {
    /* ------------------------------------------------------------------ */
    /*                               bounds                                */
    /* ------------------------------------------------------------------ */

    uint32 public constant MAX_EPOCHS = 365;
    uint32 public constant MAX_CONTRIBUTORS = 5_000;

    /// @dev Contributors paid per `settleFrom` call. Sized from measurement (~117k gas per
    ///      contributor including the vault call): 200 is ~23M gas at the low end and ~30M at the
    ///      high end, which is why the bound is a constant rather than "whatever fits". A task with
    ///      5000 contributors needs 25 pages, which is fine because settlement is permissionless and
    ///      each page is independently callable.
    uint256 public constant SETTLE_PAGE_SIZE = 200;
    uint32 public constant MAX_SHARDS = 65_535;
    uint32 public constant MAX_FEATURES = 512;
    uint32 public constant MAX_ROWS_PER_SHARD = 100_000;
    uint16 public constant BPS = 10_000;

    /// @dev Fraction of the open epoch's lock retained on abort, so a node that already
    ///      produced work stays solvent.
    uint16 public constant ABORT_LOCK_BPS = 2_000;

    /// @dev Distinct re-executors whose disagreement with the claimed digest is required to
    ///      reject an epoch. See docs/03-proof-of-compute.md §4.
    uint256 public constant DISPUTE_QUORUM = 3;

    bytes32 private constant _EMPTY_ROOT = keccak256("SHROUD/CTROOT/v1");
    bytes4 private constant _1271_MAGIC = 0x1626ba7e;

    /// @dev 4-byte reason codes for `TaskAborted`. Fixed on-chain so an abort is machine-readable
    ///      without trusting the caller's string.
    bytes4 private constant _REASON_EMERGENCY_UNWIND = 0x656d556e; // "emUn"
    bytes4 private constant _REASON_EPOCH_DISPUTED = 0x65706364; // "epcd"
    bytes4 private constant _REASON_STARK_REJECTED = 0x73746172; // "star"

    /* ------------------------------------------------------------------ */
    /*                              immutables                             */
    /* ------------------------------------------------------------------ */

    IERC20 private immutable _escrowToken;
    PaymentVault public immutable vault;
    IProofVerifier public immutable proofVerifier;
    IDecryptionGate public immutable decryptionGate;

    /// @dev Encrypted orchestration state. Allocated in the constructor, never re-encrypted.
    euint32 private _liveEpoch;
    euint32 private _sealFlag;
    euint32 private _verifiedNodes;
    euint64 private _encState;

    /* ------------------------------------------------------------------ */
    /*                              storage                                */
    /* ------------------------------------------------------------------ */

    address public owner;
    address public treasury;
    bool public shapeProofsRequired;

    uint256 public taskCount;

    mapping(uint256 => Task) private _tasks;
    mapping(uint256 => mapping(address => Contribution)) private _contributions;
    mapping(uint256 => mapping(uint256 => address)) private _contributionByLeaf;
    mapping(uint256 => mapping(uint32 => mapping(address => EpochCommit))) private _commits;
    mapping(uint256 => mapping(address => bool)) private _nodeRegistered;
    mapping(uint256 => address[]) private _contributorList;
    mapping(uint256 => mapping(uint32 => address)) private _epochWinner;
    mapping(uint256 => mapping(uint32 => uint256)) private _epochChannel;

    mapping(uint256 => bytes32) private _ctAcc;
    mapping(uint256 => uint256) private _totalWeight;
    /// @dev Keyed by epoch, not just by task: a quorum reached while disputing epoch 0 must not
    ///      carry over and auto-reject epoch 1, which would let one round of disputes poison every
    ///      later epoch of the same task.
    mapping(uint256 => mapping(uint32 => uint256)) private _disputeCount;
    mapping(uint256 => mapping(uint32 => mapping(address => bool))) private _disputeRecorded;
    mapping(uint256 => mapping(uint32 => address[])) private _epochReporters;
    mapping(uint256 => mapping(uint32 => bytes32)) private _claimedDigest;
    mapping(uint256 => bool) private _settled;
    /// @dev Settlement progress. `_settleCursor` is the first contributor not yet paid,
    ///      `_settleDistributed` accumulates amounts already credited so the dust is computed
    ///      against the whole pool across pages, and `_settleDustRecipient` carries the
    ///      deterministic dust sink forward so it does not depend on which page is running.
    mapping(uint256 => uint256) private _settleCursor;
    mapping(uint256 => uint256) private _settleDistributed;
    mapping(uint256 => address) private _settleDustRecipient;
    /// @dev The contributor pool, frozen by the first settlement page and reused by every later
    ///      one so per-contributor amounts cannot drift between pages.
    mapping(uint256 => uint128) private _settleUserPool;
    /// @dev Whether any settlement page has run. Distinguishes "pool not yet computed" from
    ///      "pool computed as zero", and gates `abort` so a partially settled task cannot be
    ///      unwound behind the contributors already paid.
    mapping(uint256 => bool) private _settleStarted;

    /// @dev Slices the contract has authorised, keyed by channel then sliceIndex. Consulted by
    ///      `isValidSignature` (ERC-1271) so a node can redeem an epoch reward without any
    ///      off-chain trusted signer.
    mapping(uint256 => mapping(uint256 => uint128)) private _authorizedSlice;

    /* ------------------------------------------------------------------ */
    /*                                events                                */
    /* ------------------------------------------------------------------ */

    event NodeRegistered(uint256 indexed taskId, address indexed node, bytes32 blsPubKey);
    event NodeRewardChannelOpened(uint256 indexed taskId, uint32 indexed epoch, address indexed node, uint256 channelId, uint128 maxCumulative, uint64 unlockAt, uint128 firstSlice);
    event EscrowSettled(uint256 indexed taskId, uint128 contributorsPool, uint128 committeePool, uint128 refunded);
    event OwnershipTransferred(address indexed from, address indexed to);
    event TreasuryChanged(address indexed from, address indexed to);
    event ShapeProofsRequiredChanged(bool required);
    event StateAccessGranted(uint256 indexed taskId, address indexed account);
    /// @dev Emitted for every settlement page that is not the last, so an operator can watch
    ///      progress and see that it is actually advancing.
    event SettleProgress(uint256 indexed taskId, uint256 paidUpTo, uint256 total);

    /* ------------------------------------------------------------------ */
    /*                                errors                                */
    /* ------------------------------------------------------------------ */

    error NotOwner(address caller);
    error NotUpdateManagerOrOwner(uint256 taskId, address caller);
    error BuyerMustBeCaller(address expected, address actual);
    error InvalidShares(uint16 user, uint16 node, uint16 committee);
    error NodeAlreadyRegistered(uint256 taskId, address node);
    error NodeNotRegistered(uint256 taskId, address node);
    error ZeroAddress();
    error ZeroContribution();
    error NarrowCast(address from);
    error NarrowCastId(uint256 id);
    error SliceNotAuthorized(uint256 channelId, uint256 sliceIndex);
    error SliceFieldsMismatch();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    constructor(
        address escrowToken_,
        address vault_,
        address proofVerifier_,
        address decryptionGate_,
        address treasury_,
        bool shapeProofsRequired_
    ) {
        if (
            escrowToken_ == address(0) ||
            vault_ == address(0) ||
            proofVerifier_ == address(0) ||
            decryptionGate_ == address(0) ||
            treasury_ == address(0)
        ) revert ZeroAddress();

        owner = msg.sender;
        treasury = treasury_;
        _escrowToken = IERC20(escrowToken_);
        vault = PaymentVault(vault_);
        proofVerifier = IProofVerifier(proofVerifier_);
        decryptionGate = IDecryptionGate(decryptionGate_);
        shapeProofsRequired = shapeProofsRequired_;

        // fhEVM's coprocessor/ACL/KMS addresses live in a fixed storage slot of *this* contract,
        // and `FHE.*` reads them from there. They must be written before the first FHE opcode,
        // otherwise every call reverts against a zero address. `ZamaConfig` resolves them per
        // chain id (mainnet / sepolia / 31337 local-devnet), so the same bytecode works on the
        // fhEVM L3 and against the in-process mock coprocessor used by the tests.
        CoprocessorConfig memory fhevmConfig = ZamaConfig.getEthereumCoprocessorConfig();
        FHE.setCoprocessor(fhevmConfig);

        _liveEpoch = FHE.asEuint32(0);
        _sealFlag = FHE.asEuint32(0);
        _verifiedNodes = FHE.asEuint32(0);
        _encState = FHE.asEuint64(0);

        // Every handle this contract owns must be ACL'd to `address(this)` before it can be
        // used as an operand again. `FHE.*` checks the ACL against the *calling* contract, so
        // without these the first `FHE.add` reverts with `ACLNotAllowed`.
        FHE.allow(_liveEpoch, address(this));
        FHE.allow(_sealFlag, address(this));
        FHE.allow(_verifiedNodes, address(this));
        FHE.allow(_encState, address(this));

        emit TreasuryChanged(address(0), treasury_);
        emit ShapeProofsRequiredChanged(shapeProofsRequired_);
    }

    /* ------------------------------------------------------------------ */
    /*                            governance                               */
    /* ------------------------------------------------------------------ */

    function transferOwnership(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, to);
        owner = to;
    }

    function setTreasury(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        emit TreasuryChanged(treasury, to);
        treasury = to;
    }

    function setShapeProofsRequired(bool required) external onlyOwner {
        shapeProofsRequired = required;
        emit ShapeProofsRequiredChanged(required);
    }

    function setPaused(bool v) external onlyOwner {
        _setPaused(v);
    }

    /// @notice Kick a genuinely stuck task out of its epoch so funds can be recovered.
    /// @dev Deliberately narrow: the task must be past its epoch deadline *and* past the
    ///      dispute window, so the owner cannot use this to censor a live task.
    function emergencyUnwind(uint256 taskId) external onlyOwner nonReentrant {
        Task storage t = _tasks[taskId];
        if (t.status == TaskStatus.None) revert InvalidParams("unknown");
        if (t.status == TaskStatus.Disclosed || t.status == TaskStatus.Aborted) revert InvalidParams("terminal");
        if (block.timestamp < t.epochDeadline + t.params.disputeWindow) revert InvalidParams("stale epoch");
        _setStatus(taskId, TaskStatus.Aborted);
        emit TaskAborted(taskId, _REASON_EMERGENCY_UNWIND);
    }

    /* ================================================================== */
    /*                        1. BUYER: CREATE + ESCROW                    */
    /* ================================================================== */

    /// @notice Create a task and escrow the buyer's whole approved balance as the budget.
    /// @dev The budget is *not* a `TaskParams` field: the budget is whatever was actually
    ///      transferred. That removes any possibility of the contract accounting for a budget
    ///      the buyer did not deposit, and it means the SDK only needs one `approve` per
    ///      buyer, not one per task.
    ///
    ///      Escrow is up-front and total, which is what makes per-epoch settlement pure
    ///      bookkeeping and guarantees a node is always solvent for work it delivered.
    function createTask(uint128 budget, TaskParams calldata p) external whenNotPaused nonReentrant returns (uint256 taskId) {
        if (p.buyer != msg.sender) revert BuyerMustBeCaller(msg.sender, p.buyer);
        TaskParams memory pm = p;
        if (pm.updateManager == address(0)) pm.updateManager = msg.sender;

        _validateParams(pm);
        _requireShares(pm.userShareBps, pm.nodeShareBps, pm.committeeShareBps);

        if (budget == 0) revert BudgetTooSmall(1, 0);

        taskId = ++taskCount;
        vault.fundTask(taskId, budget, msg.sender);
        uint128 escrowed = uint128(vault.taskBalance(taskId));
        if (escrowed != budget) revert EscrowMismatch(taskId, budget);

        _tasks[taskId] = Task({
            params: pm,
            budget: escrowed,
            locked: 0,
            createdAt: uint64(block.timestamp),
            windowEnd: uint64(block.timestamp) + pm.contributionWindow,
            sealAt: 0,
            epochDeadline: 0,
            contributors: 0,
            shards: 0,
            nextEpoch: 0,
            ctRoot: _EMPTY_ROOT,
            lastWeightsCid: bytes32(0),
            lastWeightsDigest: bytes32(0),
            status: TaskStatus.Opening,
            isSealed: false
        });

        emit TaskCreated(taskId, pm.buyer, escrowed, pm.epochs);
        _setStatus(taskId, TaskStatus.Opening);
    }

    function _validateParams(TaskParams memory p) private pure {
        if (p.updateManager == address(0)) revert InvalidParams("manager");
        if (p.epochs == 0 || p.epochs > MAX_EPOCHS) revert InvalidParams("epochs");
        if (p.minContributors == 0 || p.maxContributors < p.minContributors) revert InvalidParams("contributors");
        if (p.maxContributors > MAX_CONTRIBUTORS) revert InvalidParams("contrib cap");
        if (p.minRowsPerShard == 0 || p.minRowsPerShard > MAX_ROWS_PER_SHARD) revert InvalidParams("rows");
        if (p.features == 0 || p.features > MAX_FEATURES) revert InvalidParams("features");
        if (p.labelBits != 8 && p.labelBits != 16) revert InvalidParams("labelBits");
        if (p.contributionWindow < 1 hours || p.contributionWindow > 30 days) revert InvalidParams("window");
        if (p.epochDuration < 5 minutes || p.epochDuration > 1 days) revert InvalidParams("epochDur");
        if (p.disputeWindow < 1 minutes || p.disputeWindow > 1 hours) revert InvalidParams("disputeWindow");
        if (p.reexecutionBps > 5_000) revert InvalidParams("reexec");
        if (p.modelSpecCid == bytes32(0)) revert InvalidParams("modelSpecCid");
        if (p.shapeRoot == bytes32(0)) revert InvalidParams("shapeRoot");
    }

    function _requireShares(uint16 user, uint16 node, uint16 committee) private pure {
        if (user == 0) revert InvalidShares(user, node, committee);
        if (uint256(user) + uint256(node) + uint256(committee) != BPS) revert InvalidShares(user, node, committee);
    }

    /* ================================================================== */
    /*                     2. USERS: ENCRYPTED CONTRIBUTIONS              */
    /* ================================================================== */

    /// @notice Register an encrypted shard produced entirely client-side.
    /// @param ciphertextCid content-addressed DA object holding the FHE ciphertexts
    /// @param ctDigest       keccak256 of the DA object bytes (pins the payload)
    /// @param shapeProof     Groth16 proof that the decrypted shard holds >= minRowsPerShard
    ///                       rows, each matching the buyer's `shapeRoot`. Only its
    ///                       `keccak256` is kept on-chain: a Groth16 proof is 128-256 bytes and
    ///                       must never be stored in a state slot. The proof itself goes to the
    ///                       DA alongside the ciphertext, and a dispute re-execution checks the
    ///                       stored digest against the bytes it fetched.
    /// @param rowCommitment  commitment to the row Merkle root, so a re-execution can check the
    ///                       decrypted structure matches the pin
    /// @param rows           row count the client claims
    function submitContribution(
        uint256 taskId,
        bytes32 ciphertextCid,
        bytes32 ctDigest,
        bytes calldata shapeProof,
        bytes32 rowCommitment,
        uint32 rows
    ) external whenNotPaused nonReentrant {
        Task storage t = _tasks[taskId];
        if (t.status != TaskStatus.Opening && t.status != TaskStatus.Collecting) {
            revert InvalidTaskStatus(taskId, t.status, TaskStatus.Collecting);
        }
        if (block.timestamp > t.windowEnd) revert ContributionWindowClosed(taskId);
        if (_contributions[taskId][msg.sender].accepted) revert AlreadyContributed(taskId, msg.sender);
        if (ciphertextCid == bytes32(0) || ctDigest == bytes32(0)) revert ZeroContribution();
        if (rows < t.params.minRowsPerShard) revert ShardTooSmall(rows, t.params.minRowsPerShard);
        if (rows > MAX_ROWS_PER_SHARD) revert ShardTooLarge(rows, MAX_ROWS_PER_SHARD);
        if (t.contributors >= t.params.maxContributors) revert CapReached(taskId, t.params.maxContributors);
        if (t.shards >= MAX_SHARDS) revert CapReached(taskId, MAX_SHARDS);
        bytes32 shapeProofDigest = keccak256(shapeProof);
        if (shapeProofsRequired && shapeProof.length == 0) revert ShapeProofInvalid(taskId, msg.sender);
        if (rowCommitment == bytes32(0)) revert RowCommitmentInvalid(taskId, msg.sender);

        uint32 leafIndex = t.shards;
        uint96 w = uint96(Dividend.weight(rows, Dividend.liveness(t.createdAt, t.windowEnd, uint64(block.timestamp))));
        if (w == 0) revert ZeroContribution();

        _contributions[taskId][msg.sender] = Contribution({
            ciphertextCid: ciphertextCid,
            ctDigest: ctDigest,
            shapeProof: shapeProofDigest,
            rows: rows,
            leafIndex: leafIndex,
            submittedAt: uint64(block.timestamp),
            weightQ16: w,
            accepted: true,
            slashed: false
        });

        _contributionByLeaf[taskId][leafIndex] = msg.sender;
        _totalWeight[taskId] += w;
        _ctAcc[taskId] = _appendLeaf(_ctAcc[taskId], leafIndex, ciphertextCid);
        t.ctRoot = _ctAcc[taskId];
        _contributorList[taskId].push(msg.sender);

        unchecked {
            t.shards += 1;
            t.contributors += 1;
        }

        // One batched encrypted counter, so a buyer's dashboard can show collection progress
        // without any per-contribution metadata becoming public on-chain.
        _verifiedNodes = FHE.add(_verifiedNodes, FHE.asEuint32(1));
        _grant32(_verifiedNodes, t);

        if (t.status == TaskStatus.Opening) _setStatus(taskId, TaskStatus.Collecting);

        emit ContributionSubmitted(taskId, msg.sender, leafIndex, ciphertextCid, rows);
    }

    /// @notice Seal the dataset so `ctRoot` freezes. Callable by the buyer/update manager once
    ///         `minContributors` is met, or by anyone once `contributionWindow` has expired.
    function sealTask(uint256 taskId) external whenNotPaused nonReentrant {
        Task storage t = _tasks[taskId];
        if (t.isSealed) revert InvalidTaskStatus(taskId, t.status, TaskStatus.Sealed);
        if (t.contributors == 0) revert InvalidParams("no shards");
        if (t.contributors < t.params.minContributors) revert CapReached(taskId, t.params.minContributors);

        if (block.timestamp < t.windowEnd) {
            // Before the deadline only the buyer/update manager may force a seal.
            if (msg.sender != t.params.buyer && msg.sender != t.params.updateManager) {
                revert NotUpdateManagerOrOwner(taskId, msg.sender);
            }
        }

        t.isSealed = true;
        t.sealAt = uint64(block.timestamp);
        t.ctRoot = _ctAcc[taskId];
        t.epochDeadline = 0;

        _sealFlag = FHE.asEuint32(1);
        _grant32(_sealFlag, t);

        _setStatus(taskId, TaskStatus.Sealed);
        emit TaskSealed(taskId, t.ctRoot, t.shards, t.contributors);
    }

    /* ================================================================== */
    /*                    3. NODES: EPOCH ORCHESTRATION                   */
    /* ================================================================== */

    /// @notice Compute nodes register once per task before the first epoch opens.
    function registerNode(uint256 taskId, bytes32 blsPubKey) external whenNotPaused {
        if (_tasks[taskId].status == TaskStatus.None) revert InvalidParams("unknown");
        if (_nodeRegistered[taskId][msg.sender]) revert NodeAlreadyRegistered(taskId, msg.sender);
        _nodeRegistered[taskId][msg.sender] = true;
        emit NodeRegistered(taskId, msg.sender, blsPubKey);
    }

    /// @notice Buyer publishes the encrypted weight vector for epoch `nextEpoch` plus a fresh
    ///         encrypted state accumulator.
    /// @dev `encStateHandle` / `encStateProof` are the fhEVM external ciphertext handle and the
    ///      gateway input proof for it (encrypted loss, noise budget, epoch checkpoint). The
    ///      gateway verifies that the handle was produced by the network public key for
    ///      `msg.sender`, so the buyer cannot pass off someone else's ciphertext. Nodes decrypt
    ///      it locally with their committee share, branch on it and re-encrypt the result — the
    ///      chain only relays it opaquely.
    function openEpoch(
        uint256 taskId,
        bytes32 encWeightsCid,
        bytes32 weightsDigest,
        externalEuint64 encStateExternal,
        bytes calldata encStateProof
    ) external whenNotPaused nonReentrant {
        Task storage t = _tasks[taskId];
        // The "epoch locked" case is checked before the status guard: a task
        // waiting on `finalizeEpoch` sits in `EpochOpen`, and `InvalidParams("previous epoch not
        // finalized")` tells the caller far more than a bare status mismatch would.
        if (t.locked != 0) revert InvalidParams("epoch locked");
        if (t.status != TaskStatus.Sealed && t.status != TaskStatus.EpochSettled) {
            revert InvalidTaskStatus(taskId, t.status, TaskStatus.Sealed);
        }
        if (msg.sender != t.params.updateManager && msg.sender != t.params.buyer && msg.sender != owner) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        if (encWeightsCid == bytes32(0) || weightsDigest == bytes32(0)) {
            revert WeightPinMismatch(taskId, weightsDigest, encWeightsCid);
        }

        uint32 epoch = t.nextEpoch;
        if (epoch >= t.params.epochs) revert InvalidParams("epochs done");

        uint128 epochLock = _epochLock(t);
        if (t.budget - t.locked < epochLock) revert EscrowMismatch(taskId, t.budget - t.locked);

        t.locked = epochLock;
        t.lastWeightsCid = encWeightsCid;
        t.lastWeightsDigest = weightsDigest;
        t.epochDeadline = uint64(block.timestamp) + t.params.epochDuration;

        _liveEpoch = FHE.asEuint32(epoch);
        _grant32(_liveEpoch, t);

        _encState = FHE.fromExternal(encStateExternal, encStateProof);
        _grant64(_encState, t);

        _setStatus(taskId, TaskStatus.EpochOpen);
        emit EpochOpened(taskId, epoch, encWeightsCid, weightsDigest);
        emit FheStateCheckpoint(taskId, FHE.toBytes32(_encState));
    }

    /// @notice Submit a ZK-STARK proof of compute for epoch `epoch` plus the encrypted weights
    ///         for epoch `epoch + 1`.
    /// @dev The money-critical entry point. The proof must verify against a public input that
    ///      binds chain id, this contract, the task, the epoch, the dataset root and the
    ///      previous weights digest, so a proof from any other task or dataset is rejected.
    function commitEpoch(
        uint256 taskId,
        uint32 epoch,
        bytes32 proof,
        bytes32 encWeightsCid,
        bytes32 weightsDigest,
        bytes32 metricsCid,
        bytes32 traceDigest
    ) external whenNotPaused nonReentrant {
        Task storage t = _tasks[taskId];
        if (t.status != TaskStatus.EpochOpen && t.status != TaskStatus.EpochCommitting) {
            revert InvalidTaskStatus(taskId, t.status, TaskStatus.EpochOpen);
        }
        if (!_nodeRegistered[taskId][msg.sender]) revert NodeNotRegistered(taskId, msg.sender);
        if (epoch != t.nextEpoch) revert InvalidParams("epoch order");
        if (block.timestamp > t.epochDeadline) revert InvalidParams("window expired");
        if (encWeightsCid == bytes32(0) || weightsDigest == bytes32(0) || traceDigest == bytes32(0)) {
            revert WeightPinMismatch(taskId, weightsDigest, encWeightsCid);
        }
        EpochCommit storage c = _commits[taskId][epoch][msg.sender];
        if (c.committedAt != 0) revert DuplicateCommit(taskId, epoch, msg.sender);

        // `proof` is a 32-byte *reference* to the proof, never the proof itself: a single-segment
        // STARK is far larger than 32 bytes, and a segmented proof is summarised by the Merkle
        // root over its segment proofs. Which of the two it is cannot be inferred from a fixed-size
        // field, so the verifier behind `proofVerifier` resolves it (it may be a STARK digest, a
        // segmented Merkle root, or an indirection to off-chain storage).
        if (proof == bytes32(0)) revert ProofReferenceMissing(taskId, epoch, msg.sender);

        bytes32 transcript = proofTranscript(taskId, epoch, traceDigest);
        bytes memory publicInput = abi.encode(
            transcript,
            epoch,
            t.shards,
            traceDigest,
            t.ctRoot,
            t.lastWeightsDigest,
            block.chainid
        );

        bool ok = proofVerifier.verifyProof(publicInput, abi.encodePacked(proof));
        emit EpochVerified(taskId, epoch, msg.sender, ok);
        if (!ok) revert ProofRejected(taskId, epoch, _REASON_STARK_REJECTED);

        c.proof = proof;
        c.encWeightsCid = encWeightsCid;
        c.weightsDigest = weightsDigest;
        c.metricsCid = metricsCid;
        c.traceDigest = traceDigest;
        c.committedAt = uint64(block.timestamp);
        c.revealNonce = 1;
        c.verified = true;

        // First verified commit is the candidate winner; ties resolve to the lower address,
        // which is fixed before the dispute window opens so nobody can buy the tie-break.
        address incumbent = _epochWinner[taskId][epoch];
        if (incumbent == address(0) || msg.sender < incumbent) {
            _epochWinner[taskId][epoch] = msg.sender;
            _claimedDigest[taskId][epoch] = traceDigest;
        }

        _setStatus(taskId, TaskStatus.EpochCommitting);
        emit EpochCommitted(taskId, epoch, msg.sender, traceDigest);

        // The new handle must be ACL'd to this contract as well as the reader: the *next*
        // `commitEpoch` is an FHE operand on `_verifiedNodes`, and without the self-grant the
        // second epoch reverts with `ACLNotAllowed`. Mirrors the grant in `registerNode`.
        _verifiedNodes = FHE.add(_verifiedNodes, FHE.asEuint32(1));
        _grant32(_verifiedNodes, t);
    }

    /// @notice Re-execute epoch `epoch` and report the digest you independently obtain.
    /// @dev Deterministic given the public inputs, so an honest reporter necessarily
    ///      disagrees with a lying claimant. Reaching quorum rejects the epoch.
    function reportDispute(uint256 taskId, uint32 epoch, bytes32 reexecutedDigest) external whenNotPaused {
        if (!_nodeRegistered[taskId][msg.sender]) revert NodeNotRegistered(taskId, msg.sender);
        Task storage t = _tasks[taskId];
        if (t.status != TaskStatus.EpochCommitting) revert InvalidTaskStatus(taskId, t.status, TaskStatus.EpochCommitting);
        if (_disputeRecorded[taskId][epoch][msg.sender]) revert DuplicateCommit(taskId, epoch, msg.sender);
        if (reexecutedDigest == _claimedDigest[taskId][epoch]) revert InvalidParams("digest=claim");

        _disputeRecorded[taskId][epoch][msg.sender] = true;
        _disputeCount[taskId][epoch] += 1;
        _epochReporters[taskId][epoch].push(msg.sender);
        emit DisputeReported(taskId, epoch, msg.sender, reexecutedDigest);
    }

    /// @notice Close the epoch once its dispute window expired, or immediately once the
    ///         dispute quorum is reached. Releases the lock and pays the winner.
    function finalizeEpoch(uint256 taskId, uint32 epoch) external whenNotPaused nonReentrant {
        Task storage t = _tasks[taskId];
        if (t.status != TaskStatus.EpochCommitting) revert InvalidTaskStatus(taskId, t.status, TaskStatus.EpochCommitting);
        if (epoch != t.nextEpoch) revert InvalidParams("epoch order");

        bool quorum = _disputeCount[taskId][epoch] >= DISPUTE_QUORUM;
        if (!quorum && block.timestamp < t.epochDeadline + t.params.disputeWindow) {
            revert DisputeBelowQuorum(taskId, epoch, _disputeCount[taskId][epoch], DISPUTE_QUORUM);
        }

        uint128 lock = _epochLock(t);
        address winner = _epochWinner[taskId][epoch];
        t.locked = 0;
        unchecked {
            t.nextEpoch = epoch + 1;
        }

        if (quorum) {
            // The claimant lied: no node is paid for this epoch, and the lock returns to the
            // task sub-balance to be refunded at settlement. Reporters are paid out of the lock
            // so that reporting is rational.
            _payReporters(taskId, epoch, lock);
            emit TaskAborted(taskId, _REASON_EPOCH_DISPUTED);
        } else if (winner != address(0)) {
                // `lock` is *already* this epoch's slice of the node pool (`_epochLock` divides
                // `budget * nodeShareBps` across the epochs), so the node share must not be taken
                // a second time here. Re-applying `nodeShareBps` would hand the winner 15% of
                // their own pool and quietly refund the other 85% to the buyer at settlement.
                uint128 reward = lock;
                if (reward > 0) _payNode(taskId, epoch, winner, reward);
                emit EpochSettled(taskId, epoch, winner, reward);
            }

        _liveEpoch = FHE.asEuint32(t.nextEpoch);
        // Grant this contract too: without it, any FHE operation on the fresh handle before the
        // next `openEpoch` would revert with `ACLNotAllowed`.
        _grant32(_liveEpoch, t);
        _setStatus(taskId, TaskStatus.EpochSettled);
    }

    /* ================================================================== */
    /*                    4. SETTLEMENT + REVEAL                          */
    /* ================================================================== */

    /// @notice Distribute the escrow once every epoch has settled.
    /// @dev Payout legs are staged in `PaymentVault.creditFromTask` (pull-based). A recipient
    ///      therefore cannot block settlement with a reverting transfer, and each contributor
    ///      claims with their own transaction, which is also how a user with a broken wallet
    ///      integration is handled without stalling everyone else.
    function settle(uint256 taskId) external whenNotPaused nonReentrant {
        _settleFrom(taskId, 0);
    }

    /// @notice Settle the next page of contributors.
    /// @dev `settle` used to distribute the whole contributor pool in a single call, which is O(n)
    ///      in gas with an external call per contributor. Measured at ~117k gas per contributor, a
    ///      task at the then-current `MAX_CONTRIBUTORS` of 5000 needed ~584M gas — roughly 19x a
    ///      30M block limit. Such a task could complete every epoch and then be *permanently
    ///      un-settleable*: `settle` is the only call that pays contributors, so their funds would
    ///      sit in the vault with no recourse.
    ///
    ///      Settlement is therefore paged. `cursor` is the index of the first contributor this call
    ///      has not yet paid, and the final page is the one that reaches the end of the list; that
    ///      page also pays the dust, the committee and the buyer, and only then sets `_settled`.
    ///      Paging is permissionless because it moves money only to the addresses the task already
    ///      committed to paying — the amounts come from the frozen escrow and the recorded weights,
    ///      not from the caller.
    ///
    ///      Ordering matters for correctness: `userPool` and `totalWeight` are recomputed from
    ///      `t.budget` and `_totalWeight`, both of which are immutable once the contribution window
    ///      closes, so every page computes identical per-contributor amounts and no contributor is
    ///      paid twice or underpaid by paging.
    function settleFrom(uint256 taskId, uint256 cursor) external whenNotPaused nonReentrant {
        _settleFrom(taskId, cursor);
    }

    /// @notice Index of the first contributor `settleFrom` has not yet paid.
    function settleCursor(uint256 taskId) external view returns (uint256) {
        return _settleCursor[taskId];
    }

    /// @notice The contributor pool frozen by the first settlement page, for monitoring.
    function settleUserPool(uint256 taskId) external view returns (uint128) {
        return _settleUserPool[taskId];
    }

    /// @notice Whether any settlement page has run.
    function isFullySettled(uint256 taskId) external view returns (bool) {
        return _settled[taskId];
    }

    function _settleFrom(uint256 taskId, uint256 cursor) private {
        Task storage t = _tasks[taskId];
        // A page may only continue an unfinished settlement; `_settled` is set by the last page.
        if (_settled[taskId]) revert InvalidTaskStatus(taskId, t.status, TaskStatus.Settling);
        if (t.status != TaskStatus.EpochSettled) revert InvalidTaskStatus(taskId, t.status, TaskStatus.EpochSettled);
        if (t.locked != 0) revert InvalidParams("epoch locked");
        // `finalizeEpoch` leaves the task in `EpochSettled` with `locked == 0` after *each* epoch,
        // so without this a caller could settle after epoch 0 of 3 and take the whole escrow while
        // two epochs of paid-for work were still owed.
        if (t.nextEpoch < t.params.epochs) revert InvalidParams("epochs remain");
        // Only an orderly continuation: no page may skip ahead and strand the ones before it.
        if (cursor != _settleCursor[taskId]) revert InvalidParams("settle cursor");

        // Return every un-redeemed reward lock to the sub-balance first, so the split below
        // is computed against the vault's real balance rather than an assumption. Idempotent: the
        // sweep is a no-op once the channels are closed, so repeated pages are safe.
        vault.sweepTaskChannels(taskId);
        uint256 available = vault.taskBalance(taskId);

        uint128 userPool;
        uint128 committeePool = (t.budget * t.params.committeeShareBps) / BPS;
        if (_settleStarted[taskId]) {
            // Reuse the pool frozen by the first page. Recomputing it here would be wrong: the
            // `available` clamp below depends on a balance that *shrinks* as pages pay
            // contributors, so a later page could see a smaller pool and pay its contributors a
            // smaller share of a smaller pie. That would make amounts page-dependent — the exact
            // thing the paging invariant forbids — and the drift would land on whichever
            // contributors happened to be in the later pages.
            userPool = _settleUserPool[taskId];
        } else {
            uint256 available = vault.taskBalance(taskId);
            userPool = (t.budget * t.params.userShareBps) / BPS;
            if (userPool > available) userPool = uint128(available);
            _settleUserPool[taskId] = userPool;
            _settleStarted[taskId] = true;
        }

        uint256 totalWeight = _totalWeight[taskId];
        uint256 start = cursor;
        // A page is bounded so the call always fits in a block regardless of how many
        // contributors a task accumulated.
        uint256 end = start + SETTLE_PAGE_SIZE;
        if (end < start || end > _contributorList[taskId].length) end = _contributorList[taskId].length;
        uint256 distributed = _settleDistributed[taskId];
        address dustRecipient = _settleDustRecipient[taskId];

        for (uint256 i = start; i < end; ++i) {
            address a = _contributorList[taskId][i];
            Contribution memory c = _contributions[taskId][a];
            if (!c.accepted || c.slashed) continue;
            uint128 amount = Dividend.shareOf(userPool, c.weightQ16, totalWeight);
            if (amount > 0) {
                distributed += amount;
                vault.creditFromTask(taskId, a, amount);
                emit Withdrawn(taskId, a, amount);
            }
            if (a > dustRecipient) dustRecipient = a; // deterministic dust sink
        }

        _settleDistributed[taskId] = distributed;
        _settleDustRecipient[taskId] = dustRecipient;

        // Not the last page: record progress and stop. The escrow legs below must not run yet,
        // because they are computed against the whole pool being distributed.
        if (end < _contributorList[taskId].length) {
            _settleCursor[taskId] = end;
            emit SettleProgress(taskId, end, _contributorList[taskId].length);
            return;
        }
        _settleCursor[taskId] = end;
        _settled[taskId] = true;

        uint128 dust = userPool > uint128(distributed) ? uint128(userPool) - uint128(distributed) : 0;
        if (dust > 0 && dustRecipient != address(0)) {
            vault.creditFromTask(taskId, dustRecipient, dust);
            emit Withdrawn(taskId, dustRecipient, dust);
        }

        if (committeePool > 0) {
            uint256 left = vault.taskBalance(taskId);
            uint128 cpool = committeePool > left ? uint128(left) : committeePool;
            if (cpool > 0) {
                vault.creditFromTask(taskId, treasury, cpool);
                emit Withdrawn(taskId, treasury, cpool);
            }
        }

        // Everything still in the sub-balance (node pool for unopened/disputed epochs, plus
        // integer-division dust) goes back to the buyer.
        uint256 finalBalance = vault.taskBalance(taskId);
        if (finalBalance > 0) {
            vault.creditFromTask(taskId, t.params.buyer, finalBalance);
            emit Withdrawn(taskId, t.params.buyer, uint128(finalBalance));
        }

        emit EscrowSettled(taskId, userPool, committeePool, uint128(finalBalance));
        _setStatus(taskId, TaskStatus.Settling);
        emit TaskSettled(taskId, userPool, nodePoolOf(taskId), committeePool);
    }

    /// @notice Buyer requests the final weights be revealed. Gated by a valid BLS aggregate
    ///         signature from the decryption committee (threat model F-05).
    function requestReveal(uint256 taskId, bytes calldata blsAggregateSig) external nonReentrant {
        Task storage t = _tasks[taskId];
        if (msg.sender != t.params.buyer && msg.sender != t.params.updateManager && msg.sender != owner) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        if (t.status != TaskStatus.Settling) revert RevealNotAllowed(taskId, t.status);
        _setStatus(taskId, TaskStatus.Revealing);
        decryptionGate.requestReveal(taskId, t.lastWeightsCid, blsAggregateSig);
        emit RevealRequested(taskId, t.lastWeightsCid, bytes32(0));
    }

    function submitPartialDecryption(uint256 taskId, bytes32 partialDecryption) external nonReentrant {
        decryptionGate.submitPartialDecryption(taskId, partialDecryption);
    }

    /// @notice Buyer finalises the reveal once the gate has combined `threshold` partials.
    /// @dev The plaintext weights themselves are delivered off-chain (Lagrange combination
    ///      over the members' partials); this call is the on-chain, auditable state transition
    ///      that releases the task to `Disclosed`.
    /// @dev The gate is consulted because `Disclosed` is the protocol's attestation that the
    ///      committee actually decrypted this task's output. Checking only `status == Revealing`
    ///      let the buyer reach `Disclosed` immediately after `requestReveal`, with zero partials
    ///      submitted, which made the status meaningless as evidence and left no on-chain record
    ///      that the threshold was ever met.
    function withdraw(uint256 taskId) external nonReentrant returns (uint128 amount) {
        Task storage t = _tasks[taskId];
        if (msg.sender != t.params.buyer && msg.sender != t.params.updateManager && msg.sender != owner) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        if (t.status != TaskStatus.Revealing) revert RevealNotAllowed(taskId, t.status);
        if (!decryptionGate.revealCompleted(taskId)) revert RevealNotAllowed(taskId, t.status);

        uint128 due = pendingPayout(t.params.buyer);
        _setStatus(taskId, TaskStatus.Disclosed);
        amount = due;
        if (due > 0) emit Withdrawn(taskId, t.params.buyer, due);
        emit RevealCompleted(taskId, msg.sender);
    }

    /* ------------------------------------------------------------------ */
    /*                              abort path                             */
    /* ------------------------------------------------------------------ */

    /// @notice Unwind an unfinished task and refund the buyer, net of committed epochs.
    /// @dev Callable by the buyer/update manager while the task is not yet settled. The open
    ///      epoch's lock is retained so a node that already produced work stays solvent.
    function abort(uint256 taskId, bytes4 reason) external nonReentrant {
        Task storage t = _tasks[taskId];
        if (msg.sender != t.params.buyer && msg.sender != owner && msg.sender != t.params.updateManager) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        if (t.status == TaskStatus.Aborted || t.status == TaskStatus.Disclosed) {
            revert InvalidTaskStatus(taskId, t.status, TaskStatus.Aborted);
        }
        if (_settled[taskId]) revert InvalidParams("settled");
        // Settlement is a commitment to the contributors, so it cannot be unwound once begun.
        // Before paging existed this was unreachable because `settle` was atomic; with paging, a
        // buyer could run one page — paying contributors in list order at their full pro-rata
        // share — then `abort` and recover everything the remaining contributors were owed.
        // That turns contributor ordering, which is only submission order, into a selective-payment
        // lever: pay the addresses you like, claw back the rest.
        //
        // Freezing here cannot strand funds. Settlement is permissionless, every page is
        // independently callable, and the total credited can never exceed the pool frozen by the
        // first page, so finishing is always possible.
        if (_settleStarted[taskId]) revert InvalidParams("settlement started");

        // A node that already committed a *verified* epoch did real work, so it keeps a slice of
        // the open epoch's lock. Everyone else is refunded in full.
        //
        // `abort` is terminal, so anything not paid out here is stranded in the vault forever:
        // no later call can move it. The previous version always withheld `ABORT_LOCK_BPS` of
        // the lock and then never paid it to anyone, so every abort silently burned 20% of the
        // epoch lock. Gating the retention on an actual verified commit closes that.
        address worker = _epochWinner[taskId][t.nextEpoch];
        uint128 keep = (t.locked > 0 && worker != address(0)) ? (t.locked * ABORT_LOCK_BPS) / BPS : 0;

        // Un-redeemed reward locks return to the sub-balance before the refund is computed.
        vault.sweepTaskChannels(taskId);
        uint256 available = vault.taskBalance(taskId);
        t.locked = 0;

        if (keep > 0) _openChannel(taskId, t.nextEpoch, worker, keep);

        uint128 refund = uint128(available > keep ? available - keep : 0);
        if (refund > 0) {
            // Pull-based, like every other payout leg in this contract (see `settle`): the
            // refund is credited to the buyer, who claims it. `PaymentVault.refundFromTask` would
            // instead push an ERC-20 transfer during the abort, which reverts the whole unwind if
            // the buyer's token hook fails and leaves two different payout models for the SDK.
            vault.creditFromTask(taskId, t.params.buyer, refund);
            emit Withdrawn(taskId, t.params.buyer, refund);
        }
        _setStatus(taskId, TaskStatus.Aborted);
        emit TaskAborted(taskId, reason);
    }

    /// @notice Return the escrow belonging to epochs that will never run back to the buyer.
    /// @dev `settle` already refunds whatever is left in the sub-balance, so this is the early
    ///      path: the buyer gets the unspent node pool back as soon as the last epoch is done,
    ///      instead of waiting for the reveal handshake to complete. It is deliberately strict —
    ///      it only fires once `nextEpoch == epochs`, so it can never take money that a node is
    ///      still going to earn, and it never mutates `budget`, so the share splits recorded in
    ///      `TaskSettled` keep referring to the original escrow.
    /// @dev Only the unspent node pool is returned. The contributor and committee pools are
    ///      reserved for `settle`, so a buyer cannot drain funds owed to data contributors by
    ///      calling this before settlement.
    function reclaimUnspentEpochs(uint256 taskId) external whenNotPaused nonReentrant returns (uint128 amount) {
        Task storage t = _tasks[taskId];
        if (msg.sender != t.params.buyer) revert NotUpdateManagerOrOwner(taskId, msg.sender);
        if (t.status == TaskStatus.None) revert InvalidParams("unknown");
        if (_settled[taskId]) revert InvalidParams("settled");
        if (t.locked != 0) revert InvalidParams("epoch locked");
        if (t.nextEpoch < t.params.epochs) revert InvalidParams("epochs remain");

        // Un-redeemed reward locks return to the sub-balance before the refund is computed.
        vault.sweepTaskChannels(taskId);

        uint256 available = vault.taskBalance(taskId);
        if (available == 0) return 0;

        uint128 userPool = (t.budget * t.params.userShareBps) / BPS;
        uint128 committeePool = (t.budget * t.params.committeeShareBps) / BPS;
        uint256 reserved = uint256(userPool) + uint256(committeePool);
        if (available <= reserved) return 0;

        amount = uint128(available - reserved);
        // Pull-based, consistent with `settle` and `abort`.
        vault.creditFromTask(taskId, t.params.buyer, amount);
        emit Withdrawn(taskId, t.params.buyer, amount);
    }

    /* ------------------------------------------------------------------ */
    /*                     ERC-1271: epoch reward slices                  */
    /* ------------------------------------------------------------------ */

    /// @notice ERC-1271 signature validation for node reward slices.
    /// @dev The contract is the channel's streamer, so it authorises slices itself. A node
    ///      presents `abi.encode(channelId, sliceIndex, amount, deadline)` as the "signature"
    ///      and the vault checks it against the EIP-712 digest of those same fields. Only
    ///      slices recorded by `finalizeEpoch` can ever be authorised, so there is no signer
    ///      to phish and no off-chain key that could sign a payout for a non-existent epoch.
    ///
    ///      The encoding is duplicated in `PaymentVault`; both sides hash the identical
    ///      `REDEEM_TYPEHASH` struct, so a mismatch is impossible as long as the vault's
    ///      `domainSeparator` is used, which `PaymentVault.redeem` guarantees.
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4) {
        return _isValidSignature(digest, signature);
    }

    function isValidSignatureNow(bytes32 digest, bytes calldata signature) external view returns (bytes4) {
        return _isValidSignature(digest, signature);
    }

    function _isValidSignature(bytes32 digest, bytes calldata signature) internal view returns (bytes4) {
        if (signature.length != 96) return 0xffffffff;
        (uint256 channelId, uint256 sliceIndex, uint128 amount) = _decodeSlice(signature);
        uint128 authorized = _authorizedSlice[channelId][sliceIndex];
        if (authorized == 0 || authorized != amount) return 0xffffffff;
        if (digest != _sliceDigest(signature)) return 0xffffffff;
        return _1271_MAGIC;
    }

    function sliceDigest(uint256 channelId, address streamer, address node, uint128 maxCumulative, uint64 unlockAt, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        return vault.redeemDigest(channelId, streamer, node, maxCumulative, unlockAt, deadline);
    }

    function _decodeSlice(bytes calldata s) private pure returns (uint256 channelId, uint256 sliceIndex, uint128 amount) {
        (channelId, sliceIndex, amount,) = _decodeSliceFull(s);
    }

    /// @notice Digest the vault will check for a slice. Mirrors `PaymentVault.redeemDigest`,
    ///         reading the channel parameters from the vault so the two can never drift.
    function _sliceDigest(bytes calldata signature) private view returns (bytes32) {
        if (signature.length != 96) return bytes32(0);
        (uint256 channelId,,, uint256 deadline) = _decodeSliceFull(signature);
        PaymentVault.Channel memory ch = vault.channelInfo(channelId);
        if (ch.node == address(0)) return bytes32(0);
        return vault.redeemDigest(channelId, address(this), ch.node, ch.maxCumulative, ch.unlockAt, deadline);
    }

    function _decodeSliceFull(bytes calldata s) private pure returns (uint256 channelId, uint256 sliceIndex, uint128 amount, uint256 deadline) {
        if (s.length != 96) revert SliceFieldsMismatch();
        channelId = uint256(bytes32(s[0:32]));
        sliceIndex = uint256(bytes32(s[32:64]));
        amount = uint128(uint256(bytes32(s[64:96])));
        // Authorised slices never expire: `finalizeEpoch` is the only authoriser, and the
        // vault's monotonicity plus the channel cap are what bound the value at risk. A
        // deadline here would only add a liveness failure mode for a node with no cost
        // control over when it comes online to redeem.
        deadline = type(uint256).max;
    }

    /* ------------------------------------------------------------------ */
    /*                        FHE decryption handles                      */
    /* ------------------------------------------------------------------ */

    function liveEpochHandle() external view returns (euint32) {
        return _liveEpoch;
    }

    function sealFlagHandle() external view returns (euint32) {
        return _sealFlag;
    }

    function verifiedNodesHandle() external view returns (euint32) {
        return _verifiedNodes;
    }

    /// @notice The buyer's encrypted state accumulator, as a raw fhEVM handle. Callers that
    ///         already hold an input proof (the buyer, the update manager, a registered node)
    ///         must re-verify it with `FHE.fromExternal` before use; the raw handle alone grants
    ///         nothing, because the ACL is not extended to arbitrary readers.
    function encStateHandle() external view returns (externalEuint64) {
        return externalEuint64.wrap(FHE.toBytes32(_encState));
    }

    /// @notice Grant `account` the right to decrypt the shared orchestration state.
    /// @dev Restricted to the parties already ACL'd by `_grant32`/`_grant64` — the buyer, the
    ///      update manager, and nodes registered for this task. This was previously callable by
    ///      anyone with an arbitrary `account`, which handed a third party a decryption grant on
    ///      `_encState`: the buyer's encrypted loss curve, remaining noise budget and epoch
    ///      checkpoint. That is not the model weights and not any user's rows, but it is a buyer
    ///      telemetry leak reachable by an unprivileged caller, so the grant is now bounded to the
    ///      set of parties the protocol already trusts with these handles.
    function grantStateAccess(uint256 taskId, address account) external whenNotPaused {
        Task storage t = _tasks[taskId];
        if (t.status == TaskStatus.None) revert InvalidParams("unknown");
        // Checked before the role test: the zero address is not a buyer, manager, owner or node,
        // so testing the role first would make `ZeroAddress` unreachable for the only input it
        // exists to reject.
        if (account == address(0)) revert ZeroAddress();
        if (account != t.params.buyer && account != t.params.updateManager && account != owner) {
            if (!_nodeRegistered[taskId][account]) revert InvalidParams("not a task party");
        }
        FHE.allow(_liveEpoch, account);
        FHE.allow(_sealFlag, account);
        FHE.allow(_verifiedNodes, account);
        FHE.allow(_encState, account);
        emit StateAccessGranted(taskId, account);
    }

    /// @notice ACL a fresh `euint32` handle to the three parties that must be able to read it.
    ///         Every handle is re-created on mutation, and each `FHE.allow` inlines library code,
    ///         so consolidating the repeated triple-grant here keeps bytecode and ACL semantics in
    ///         one place (granting `address(this)` is what lets the *next* operation use it).
    function _grant32(euint32 h, Task storage t) private {
        FHE.allow(h, t.params.buyer);
        FHE.allow(h, t.params.updateManager);
        FHE.allow(h, address(this));
    }

    /// @notice Same as `_grant32` for the `euint64` state accumulator.
    function _grant64(euint64 h, Task storage t) private {
        FHE.allow(h, t.params.buyer);
        FHE.allow(h, t.params.updateManager);
        FHE.allow(h, address(this));
    }

    /* ================================================================== */
    /*                                 views                               */
    /* ================================================================== */

    function tasks(uint256 taskId) external view returns (Task memory) {
        return _tasks[taskId];
    }

    function contributions(uint256 taskId, address contributor) external view returns (Contribution memory) {
        return _contributions[taskId][contributor];
    }

    function contributionOf(uint256 taskId, uint256 leafIndex) external view returns (address) {
        return _contributionByLeaf[taskId][leafIndex];
    }

    function commits(uint256 taskId, uint32 epoch, address node) external view returns (EpochCommit memory) {
        return _commits[taskId][epoch][node];
    }

    function acceptedWeights(uint256 taskId) external view returns (bytes32 encWeightsCid, bytes32 weightsDigest) {
        Task storage t = _tasks[taskId];
        return (t.lastWeightsCid, t.lastWeightsDigest);
    }

    function pendingPayout(address account) public view returns (uint128) {
        uint256 v = vault.pendingWithdrawal(account);
        if (v > type(uint128).max) revert NarrowCast(account);
        unchecked {
            return uint128(v);
        }
    }

    function divisorFor(uint256 taskId) external view returns (uint128) {
        uint256 w = _totalWeight[taskId];
        if (w > type(uint128).max) revert NarrowCastId(taskId);
        unchecked {
            return uint128(w);
        }
    }

    function escrowToken() external view returns (address) {
        return address(_escrowToken);
    }

    function disputeQuorum(uint256 taskId) external view returns (uint256 need, uint256 have) {
        return (DISPUTE_QUORUM, _disputeCount[taskId][_tasks[taskId].nextEpoch]);
    }

    function proofTranscript(uint256 taskId, uint32 epoch, bytes32 traceDigest) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                "SHROUD/PoC/v1",
                block.chainid,
                address(this),
                taskId,
                epoch,
                _tasks[taskId].ctRoot,
                _tasks[taskId].lastWeightsDigest,
                traceDigest
            )
        );
    }

    function statusOf(uint256 taskId) external view returns (TaskStatus) {
        return _tasks[taskId].status;
    }

    function isSettled(uint256 taskId) external view returns (bool) {
        return _settled[taskId];
    }

    function nodeRegistered(uint256 taskId, address node) external view returns (bool) {
        return _nodeRegistered[taskId][node];
    }

    function epochWinner(uint256 taskId, uint32 epoch) external view returns (address) {
        return _epochWinner[taskId][epoch];
    }

    function epochChannel(uint256 taskId, uint32 epoch) external view returns (uint256) {
        return _epochChannel[taskId][epoch];
    }

    function contributorsOf(uint256 taskId) external view returns (address[] memory) {
        return _contributorList[taskId];
    }

    function ctRootOf(uint256 taskId) external view returns (bytes32) {
        return _tasks[taskId].ctRoot;
    }

    function nodePoolOf(uint256 taskId) public view returns (uint128) {
        Task storage t = _tasks[taskId];
        return (t.budget * t.params.nodeShareBps) / BPS;
    }

    /// @dev How long a node's reward channel stays open before the node may reclaim it.
    ///      Long enough to survive a multi-day chain outage, short enough that the buyer's
    ///      funds are not tied up indefinitely after a task ends.
    function rewardChannelWindow() public pure returns (uint64) {
        return 7 days;
    }

    /* ================================================================== */
    /*                               internals                             */
    /* ================================================================== */

    /// @dev Escrow locked per epoch: the node pool split across `epochs`, so every epoch is
    ///      fully solvent no matter how the buyer behaves afterwards.
    function _epochLock(Task storage t) private view returns (uint128) {
        uint128 pool = (t.budget * t.params.nodeShareBps) / BPS;
        return pool / t.params.epochs;
    }

    /// @dev Open the winner's reward channel and authorise its first slice. The contract is
    ///      the streamer, so the node can redeem without any off-chain signer.
    function _payNode(uint256 taskId, uint32 epoch, address node, uint128 reward) private {
        uint256 channelId = _openChannel(taskId, epoch, node, reward);
        if (channelId != 0) _epochChannel[taskId][epoch] = channelId;
    }

    /// @dev Open a reward channel without recording it as the epoch's headline channel. Used for
    ///      reporter bounties, which must not overwrite `_epochChannel[epoch]` — that slot is the
    ///      winner's, and an indexer reading it would otherwise conclude a bounty recipient won
    ///      the epoch it just disputed.
    function _openChannel(uint256 taskId, uint32 epoch, address node, uint128 reward) private returns (uint256 channelId) {
        if (reward == 0) return 0;
        uint64 unlockAt = uint64(block.timestamp) + rewardChannelWindow();
        channelId = vault.openTaskChannel(taskId, node, reward, unlockAt);
        _authorizedSlice[channelId][0] = reward;
        emit NodeRewardChannelOpened(taskId, epoch, node, channelId, reward, unlockAt, reward);
    }

    /// @dev Pay the nodes that re-executed and disagreed with the claimed digest.
    ///
    ///      The docstring on `finalizeEpoch` promises reporters are paid out of the disputed
    ///      lock; without this they would spend real gas and re-execution compute for nothing,
    ///      and the only rational strategy would be to accept every claim unchallenged. The
    ///      bounty is `reexecutionBps` of the lock split equally, with the division remainder to
    ///      the first reporter so the whole bounty is always paid out and nothing is stranded in
    ///      the sub-balance. The remainder of the lock is *not* paid here: it stays in the task
    ///      sub-balance and is refunded to the buyer at settlement.
    function _payReporters(uint256 taskId, uint32 epoch, uint128 lock) private {
        address[] memory reporters = _epochReporters[taskId][epoch];
        uint256 n = reporters.length;
        if (n == 0 || lock == 0) return;
        uint128 bounty = (uint128(lock) * _tasks[taskId].params.reexecutionBps) / BPS;
        if (bounty == 0) return;
        uint128 each = bounty / uint128(uint256(n));
        if (each == 0) return;
        uint128 total = each * uint128(uint256(n));
        for (uint256 i = 0; i < n; ++i) {
            _openChannel(taskId, epoch, reporters[i], each);
        }
        if (total < bounty) {
            _openChannel(taskId, epoch, reporters[0], bounty - total);
        }
    }

    function _setStatus(uint256 taskId, TaskStatus to) private {
        Task storage t = _tasks[taskId];
        TaskStatus from = t.status;
        if (from == to) return;
        t.status = to;
        emit TaskStatusChanged(taskId, from, to);
    }

    /// @dev `keccak(prev ‖ leafIndex ‖ ciphertextCid)`, byte-identical to
    ///      `node/src/fhe/dataset.rs::ct_root_step`. Keeping the two implementations
    ///      byte-for-byte equal is what makes `ctRoot` usable as a STARK public input, so the
    ///      encoding is spelled out here rather than left to a struct hash.
    function _appendLeaf(bytes32 acc, uint32 leafIndex, bytes32 ciphertextCid) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(acc, leafIndex, ciphertextCid));
    }
}
