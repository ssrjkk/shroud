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
import {TaskParamsLib} from "./libraries/TaskParamsLib.sol";
import {ReentrancyGuard, Pausable} from "./libraries/Guard.sol";
import {StateAcl} from "./libraries/StateAcl.sol";
import {SettlementLib} from "./libraries/SettlementLib.sol";
import {DisputeLib} from "./libraries/DisputeLib.sol";
import {BondLib, PopLib} from "./libraries/BondLib.sol";
import {RewardLib, CommitLib, ContributeLib, UnwindLib} from "./libraries/EpochLib.sol";

/// @title CipherTask — Shroud FHE training orchestrator
/// @notice Escrows a buyer's budget, admits client-side-encrypted contributions, orchestrates
///         training epochs over the ciphertext dataset, verifies ZK proofs of compute, and
///         streams USDC to contributors, compute nodes and the decryption committee.
///
/// @dev ## Why the fhEVM usage here is small on purpose
///
///      The heavy ciphertext work happens off-chain in the Rust compute node: bootstrapping a
///      33-lane dot product on-chain is neither cheap nor necessary. What the coprocessor is
///      used for in *this* contract is one thing: the buyer's encrypted model state, stored
///      **per task** (`TaskFheState`), not as a contract singleton.
///
///        - `euint64 encState` the buyer's encrypted accumulator attached to `openEpoch`. Nodes
///          decrypt it locally with their committee share, branch on it and re-encrypt the
///          result. The chain relays it opaquely and never decrypts it.
///
///      Three further handles (`liveEpoch`, `sealFlag`, `verifiedCommits`) used to mirror
///      orchestration progress into encrypted counters. They are gone: no caller ever read them,
///      nothing in the protocol decrypts them, and each one was a coprocessor round trip plus an
///      ACL grant on every epoch transition. The same three quantities are public and indexed off
///      `EpochOpened`, `EpochCommitted`, `TaskSealed` and the `tasks()` view, so the encrypted
///      copies only obscured data the protocol already discloses. Removing them is also what
///      brought `CipherTask` back under the 24 576-byte deployment limit.
///
///      All money is plain ERC-20. FHE is used for data confidentiality, not for payments.
contract CipherTask is ICipherTask, ReentrancyGuard, Pausable {
    /* ------------------------------------------------------------------ */
    /*                               bounds                                */
    /* ------------------------------------------------------------------ */

    /// @dev Re-exported from `TaskParamsLib` so the ABI an SDK reads is unchanged while the
    ///      checks themselves link out of this contract.
    uint32 public constant MAX_EPOCHS = TaskParamsLib.MAX_EPOCHS;
    uint32 public constant MAX_CONTRIBUTORS = TaskParamsLib.MAX_CONTRIBUTORS;
    uint32 public constant MAX_FEATURES = TaskParamsLib.MAX_FEATURES;
    uint32 public constant MAX_ROWS_PER_SHARD = TaskParamsLib.MAX_ROWS_PER_SHARD;
    uint16 public constant BPS = TaskParamsLib.BPS;

    /// @dev Contributors paid per `settleFrom` call. Sized from measurement (~117k gas per
    ///      contributor including the vault call): 200 is ~23M gas at the low end and ~30M at the
    ///      high end, which is why the bound is a constant rather than "whatever fits". A task with
    ///      5000 contributors needs 25 pages, which is fine because settlement is permissionless and
    ///      each page is independently callable.
    uint256 public constant SETTLE_PAGE_SIZE = 200;
    uint32 public constant MAX_SHARDS = 65_535;
    /// @dev Distinct nodes that may register on one task. `finalizeEpoch` opens one reward
    ///      channel per reporter in a single transaction and `sweepTaskChannels` iterates every
    ///      channel of the task, so unbounded registration lets anyone grief finalization into
    ///      the block gas limit with no recourse but `abort`. Contributors are capped at 5000
    ///      with paged settlement; reporter payout cannot page, so the node cap is tighter.
    uint32 public constant MAX_NODES = 200;

    /// @dev Fraction of the open epoch's lock retained on abort, so a node that already
    ///      produced work stays solvent.
    uint16 public constant ABORT_LOCK_BPS = 2_000;

    /// @dev Upper bound on the per-contributor bond a buyer may require (1000 USDC at 6 dp).
    ///      The bond is anti-spam, not a buyer revenue stream (slashes go to the treasury),
    ///      and without a cap a malicious buyer could set a prohibitive bond to censor the
    ///      contribution window shut.
    uint128 public constant MAX_CONTRIBUTION_BOND = 1_000_000_000;

    /// @dev Distinct re-executors whose disagreement with the claimed digest is required to
    ///      reject an epoch. See docs/03-proof-of-compute.md §4.
    uint256 public constant DISPUTE_QUORUM = 3;

    bytes32 private constant _EMPTY_ROOT = keccak256("SHROUD/CTROOT/v1");
    bytes4 private constant _1271_MAGIC = 0x1626ba7e;

    /// @dev 4-byte reason codes for `TaskAborted`. Fixed on-chain so an abort is machine-readable
    ///      without trusting the caller's string.
    bytes4 private constant _REASON_EMERGENCY_UNWIND = 0x656d556e; // "emUn"
    bytes4 private constant _REASON_STARK_REJECTED = 0x73746172; // "star"

    /* ------------------------------------------------------------------ */
    /*                              immutables                             */
    /* ------------------------------------------------------------------ */

    IERC20 private immutable _escrowToken;
    PaymentVault public immutable vault;
    IProofVerifier public immutable proofVerifier;
    IDecryptionGate public immutable decryptionGate;

    /// @dev The buyer's encrypted accumulator, **one per task**. This was a contract-level singleton
    ///      before, which broke two ways: `openEpoch` on task B overwrote the accumulator that task
    ///      A's nodes were reading, and `grantStateAccess(taskId, node)` extended the ACL of
    ///      *every* task's state to any address registered for *any* task. A task's buyer, update
    ///      manager and nodes must not be able to read another buyer's encrypted loss curve, so the
    ///      handle lives in the task's own slot.
    struct TaskFheState {
        euint64 encState;
    }

    /// @dev FHE coprocessor calls are only worth making in the places that need a fresh handle;
    ///      `createTask` allocates the handle once and every later mutation re-grants it.
    mapping(uint256 => TaskFheState) private _fhe;

    /* ------------------------------------------------------------------ */
    /*                              storage                                */
    /* ------------------------------------------------------------------ */

    address public owner;
    address public pendingOwner;
    address public treasury;
    bool public shapeProofsRequired;

    uint256 public taskCount;

    mapping(uint256 => Task) private _tasks;
    mapping(uint256 => mapping(address => Contribution)) private _contributions;
    mapping(uint256 => mapping(uint256 => address)) private _contributionByLeaf;
    mapping(uint256 => mapping(bytes32 => bool)) private _shardSeen;
    mapping(uint256 => mapping(uint32 => mapping(address => EpochCommit))) private _commits;
    mapping(uint256 => mapping(address => bool)) private _nodeRegistered;
    mapping(uint256 => uint32) private _nodeCount;
    /// @dev A running commitment to the registered node set, in registration order. It
    ///      enters the epoch's dispute sortition seed, so the sequencer cannot choose the
    ///      committee; see `_registerNode`.
    mapping(uint256 => bytes32) public nodeSetHash;
    mapping(uint256 => address[]) private _contributorList;
    mapping(uint256 => mapping(uint32 => address)) private _epochWinner;
    mapping(uint256 => mapping(uint32 => uint256)) private _epochChannel;

    mapping(uint256 => uint256) private _totalWeight;
    /// @dev Dispute state (counts, reporters, commitments), keyed by epoch, not just by task:
    ///      a quorum reached while disputing epoch 0 must not carry over and auto-reject
    ///      epoch 1. The type lives with the code that moves it (`DisputeLib`).
    DisputeLib.State private _disputes;
    /// @dev Contributor anti-spam bonds (F-01). Zero requirement (default) = none: fully
    ///      backward compatible. Custodied here, not in the vault — bonds are contributor
    ///      money, never task escrow. The type lives with the code (`BondLib`).
    BondLib.State private _bonds;
    mapping(uint256 => mapping(uint32 => bytes32)) private _claimedDigest;
    /// @dev Settlement progress, keyed by task: the first contributor not yet paid, the amounts
    ///      credited so far (so the dust is computed against the whole pool across pages), the
    ///      dust sink carried forward so it does not depend on which page is running, the pool
    ///      frozen by the first page, and whether settlement has begun.
    ///
    ///      The type lives with the code that moves this state (`SettlementLib`), which keeps the
    ///      two from drifting apart; `CipherTask` owns one instance and passes it by pointer.
    SettlementLib.State private _settlement;

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
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);
    event TreasuryChanged(address indexed from, address indexed to);
    event ShapeProofsRequiredChanged(bool required);
    event StateAccessGranted(uint256 indexed taskId, address indexed account);
    /// @dev Emitted for every settlement page that is not the last, so an operator can watch
    ///      progress and see that it is actually advancing.
    event SettleProgress(uint256 indexed taskId, uint256 paidUpTo, uint256 total);
    // Dispute/bond lifecycle events are declared in `ICipherTask` (ABI) and redeclared in
    // `DisputeLib`/`BondLib`, which log them from this address by DELEGATECALL.

    /* ------------------------------------------------------------------ */
    /*                                errors                                */
    /* ------------------------------------------------------------------ */

    error NotOwner(address caller);
    error NodeAlreadyRegistered(uint256 taskId, address node);
    error NarrowCast(address from);
    error NarrowCastId(uint256 id);
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

        emit TreasuryChanged(address(0), treasury_);
        emit ShapeProofsRequiredChanged(shapeProofsRequired_);
    }

    /* ------------------------------------------------------------------ */
    /*                            governance                               */
    /* ------------------------------------------------------------------ */

    /// @notice Begin a two-step ownership handover.
    /// @dev Two-step because a single-step transfer to a wrong or incapable address is both silent
    ///      and unrecoverable: the previous owner stops being able to act, and no key remains that
    ///      can undo it. This owner can pause the protocol, abort and unwind tasks, and set the
    ///      treasury that receives the committee leg, so losing it is not a cosmetic problem. The
    ///      recipient has to accept, which proves it can sign.
    function transferOwnership(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        emit OwnershipTransferStarted(owner, to);
        pendingOwner = to;
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner(msg.sender);
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
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
    /// @dev Unwinds through the same path as `abort`, which is what actually recovers the money.
    ///      It used to only set the status: `Aborted` then blocked `abort` (terminal-status guard),
    ///      `settle` (requires `EpochSettled`) and `reclaimUnspentEpochs` (requires every epoch to
    ///      have run), so the owner's emergency lever permanently stranded the whole escrow in the
    ///      vault with no call left that could move it.
    function emergencyUnwind(uint256 taskId) external onlyOwner nonReentrant {
        Task storage t = _tasks[taskId];
        if (t.status == TaskStatus.None) revert UnknownTask(taskId);
        if (t.status == TaskStatus.Disclosed || t.status == TaskStatus.Aborted) revert AlreadyTerminal(taskId, t.status);
        // No epoch ever opened (`epochDeadline == 0`): there is no deadline to be past, so the
        // timestamp check below would always pass and let the owner kill a live contribution
        // phase. Recovery there belongs to the buyer (`abort` needs no deadline).
        if (t.epochDeadline == 0) revert NoEpochOpened(taskId);
        if (block.timestamp < t.epochDeadline + t.params.disputeWindow) revert EpochStillLive(taskId, t.epochDeadline);
        // H4 fix: A task in EpochSettled with t.locked == 0 is simply waiting for the buyer to
        // open the next epoch — it is NOT stuck. emergencyUnwind should only run when an epoch
        // is genuinely stuck (locked > 0). This prevents the owner from killing healthy tasks
        // between epochs and leaving contributors with no payout.
        if (t.status == TaskStatus.EpochSettled && t.locked == 0) revert TaskNotStuck(taskId);
        _unwind(taskId, _REASON_EMERGENCY_UNWIND);
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

        TaskParamsLib.validate(p);
        TaskParamsLib.requireShares(p.userShareBps, p.nodeShareBps, p.committeeShareBps);

        if (budget == 0) revert BudgetTooSmall(1, 0);

        TaskParams memory pm = p;
        // An absent update manager means the buyer runs the epochs themselves.
        if (pm.updateManager == address(0)) pm.updateManager = msg.sender;

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
        _initFheState(taskId, pm);
    }

    /// @dev Allocate this task's encrypted state handle and ACL it to the parties that must read
    ///      it. Called from `createTask` only: a handle cannot be re-typed, and `grantStateAccess`
    ///      must have a valid handle to grant even for a task that has not run its first epoch.
    function _initFheState(uint256 taskId, TaskParams memory pm) private {
        TaskFheState storage s = _fhe[taskId];
        s.encState = FHE.asEuint64(0);
        StateAcl.grant64(s.encState, pm.buyer, pm.updateManager, address(this));
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
        // Checked here rather than in the library: it is a host-level capacity bound on the
        // leaf index space, not contribution validation.
        if (_tasks[taskId].shards >= MAX_SHARDS) revert CapReached(taskId, MAX_SHARDS);
        ContributeLib.submit(
            _bonds,
            _tasks[taskId],
            _contributions[taskId],
            _contributionByLeaf[taskId],
            _shardSeen[taskId],
            _contributorList[taskId],
            _totalWeight,
            _escrowToken,
            taskId,
            msg.sender,
            ciphertextCid,
            ctDigest,
            shapeProof,
            shapeProofsRequired,
            rowCommitment,
            rows,
            MAX_ROWS_PER_SHARD
        );
    }

    /// @notice Seal the dataset so `ctRoot` freezes. Callable by the buyer/update manager once
    ///         `minContributors` is met, or by anyone once `contributionWindow` has expired.
    /// @dev An aborted task is terminal and cannot be sealed: `abort` leaves `isSealed` false
    ///      (the task was never sealed), so without this check the task could be sealed again
    ///      after the window expired - moving it out of `Aborted` and reopening the two things
    ///      the abort deliberately closed: the slash path on a contributor who had already been
    ///      refunded, and the release of that contributor's bond.
    function sealTask(uint256 taskId) external whenNotPaused nonReentrant {
        Task storage t = _tasks[taskId];
        if (t.isSealed) revert InvalidTaskStatus(taskId, t.status, TaskStatus.Sealed);
        if (t.status == TaskStatus.Aborted || t.status == TaskStatus.Disclosed) {
            revert AlreadyTerminal(taskId, t.status);
        }
        if (t.contributors == 0) revert NoContributions(taskId);
        if (t.contributors < t.params.minContributors) {
            revert BelowMinContributors(taskId, t.params.minContributors, t.contributors);
        }

        if (block.timestamp < t.windowEnd) {
            // Before the deadline only the buyer/update manager may force a seal.
            if (msg.sender != t.params.buyer && msg.sender != t.params.updateManager) {
                revert NotUpdateManagerOrOwner(taskId, msg.sender);
            }
        }

        t.isSealed = true;
        t.sealAt = uint64(block.timestamp);
        t.epochDeadline = 0;

        _setStatus(taskId, TaskStatus.Sealed);
        emit TaskSealed(taskId, t.ctRoot, t.shards, t.contributors);
    }

    /* ================================================================== */
    /*                    3. NODES: EPOCH ORCHESTRATION                   */
    /* ================================================================== */

    /// @notice Compute nodes register once per task before the first epoch opens, posting a
    ///         bond that is slashed if a dispute quorum rejects their epoch and returned once the
    ///         task can no longer slash it.
    /// @dev The bond is pulled by the vault, not pledged: `approve` the vault then
    ///      `registerNode` in one operator flow — the same two-step pattern as the buyer's escrow
    ///      (approve the vault, `createTask`). Custody is the vault's `nodeBond` ledger (a
    ///      first-class term of its accounting invariant, not sub-balance money: sub-balances are
    ///      buyer-refundable, and a bond swept into a refund would pay the buyer with the node's
    ///      money). BLS-key uniqueness is enforced there too.
    function registerNode(uint256 taskId, bytes32 blsPubKey) external whenNotPaused {
        _registerNode(taskId, msg.sender, blsPubKey);
    }

    /// @notice Register with proof-of-possession of the node's signing key over its BLS key.
    /// @dev See the interface for the signed message. Verification is EIP-191 personal-message
    ///      ECDSA with low-s enforcement: malleated signatures must not produce two
    ///      registrations for one signer, and a 65-byte check keeps the ABI honest.
    function registerNodeWithPop(uint256 taskId, bytes32 blsPubKey, bytes calldata sig) external whenNotPaused {
        PopLib.verify(taskId, blsPubKey, msg.sender, block.chainid, address(this), sig);
        _registerNode(taskId, msg.sender, blsPubKey);
    }

    function _registerNode(uint256 taskId, address node, bytes32 blsPubKey) private {
        if (_tasks[taskId].status == TaskStatus.None) revert UnknownTask(taskId);
        if (_nodeRegistered[taskId][node]) revert NodeAlreadyRegistered(taskId, node);
        if (_nodeCount[taskId] >= MAX_NODES) revert CapReached(taskId, MAX_NODES);
        _nodeRegistered[taskId][node] = true;
        unchecked {
            _nodeCount[taskId] += 1;
        }
        // A running commitment to the registered node set, in registration order. The
        // epoch's dispute sortition draws its committee from a seed that includes it, so
        // the sequencer cannot pick the committee: the set is fixed by the registrations,
        // and every registration posts a bond. Without this the seed was the block's
        // randomness alone, which a sequencer that proposes the blocks can grind in a
        // handful of hashes until it draws its own Sybil identities (threat model F-04).
        nodeSetHash[taskId] = keccak256(abi.encode(nodeSetHash[taskId], node, blsPubKey));
        vault.takeBond(taskId, node, blsPubKey);
        emit NodeRegistered(taskId, node, blsPubKey);
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
        // The "epoch locked" case is checked before the status guard: a task waiting on
        // `finalizeEpoch` sits in `EpochOpen`, and `EpochLocked(taskId)` tells the caller far more
        // than a bare status mismatch would.
        if (t.locked != 0) revert EpochLocked(taskId);
        if (t.status != TaskStatus.Sealed && t.status != TaskStatus.EpochSettled) {
            revert InvalidTaskStatus(taskId, t.status, TaskStatus.Sealed);
        }
        // Buyer or update manager only. The owner is deliberately *not* on this list: epoch
        // contents steer what every node executes and what the buyer pays for, so letting a
        // third key publish epochs would hand it quiet control of the training trajectory.
        // The owner's emergency lever is `emergencyUnwind`, which is rate-limited by the
        // epoch deadline plus the dispute window instead.
        if (msg.sender != t.params.updateManager && msg.sender != t.params.buyer) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        if (encWeightsCid == bytes32(0) || weightsDigest == bytes32(0)) {
            revert WeightPinMismatch(taskId, weightsDigest, encWeightsCid);
        }

        uint32 epoch = t.nextEpoch;
        if (epoch >= t.params.epochs) revert AllEpochsRun(taskId, epoch);

        uint128 epochLock = _epochLock(t);
        if (t.budget - t.locked < epochLock) revert BudgetExhausted(taskId, uint128(t.budget - t.locked), epochLock);

        t.locked = epochLock;
        t.lastWeightsCid = encWeightsCid;
        t.lastWeightsDigest = weightsDigest;
        t.epochDeadline = uint64(block.timestamp) + t.params.epochDuration;

        TaskFheState storage s = _fhe[taskId];
        s.encState = FHE.fromExternal(encStateExternal, encStateProof);
        StateAcl.grant64(s.encState, t.params.buyer, t.params.updateManager, address(this));

        _setStatus(taskId, TaskStatus.EpochOpen);
        emit EpochOpened(taskId, epoch, encWeightsCid, weightsDigest);
        emit FheStateCheckpoint(taskId, FHE.toBytes32(s.encState));
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
        _commit(taskId, epoch, proof, encWeightsCid, weightsDigest, metricsCid, traceDigest, false);
    }

    /// @notice Submit a segmented STARK for epoch `epoch` (see the interface).
    function commitEpochSegmented(
        uint256 taskId,
        uint32 epoch,
        bytes32 segmentedRoot,
        bytes32 encWeightsCid,
        bytes32 weightsDigest,
        bytes32 metricsCid,
        bytes32 traceDigest
    ) external whenNotPaused nonReentrant {
        _commit(taskId, epoch, segmentedRoot, encWeightsCid, weightsDigest, metricsCid, traceDigest, true);
    }

    function _commit(
        uint256 taskId,
        uint32 epoch,
        bytes32 proof,
        bytes32 encWeightsCid,
        bytes32 weightsDigest,
        bytes32 metricsCid,
        bytes32 traceDigest,
        bool segmented
    ) private {
        // Verification + winner recording live in `CommitLib` (host size limit). The transcript
        // binding is identical: chain, this contract, task, epoch, dataset root, prior weights.
        CommitLib.commit(
            _tasks[taskId],
            _commits,
            _epochWinner,
            _claimedDigest,
            _nodeRegistered,
            proofVerifier,
            _tasks[taskId].ctRoot,
            _tasks[taskId].lastWeightsDigest,
            taskId,
            epoch,
            msg.sender,
            proof,
            encWeightsCid,
            weightsDigest,
            metricsCid,
            traceDigest,
            segmented
        );
    }

    /// @notice Commit to a dispute digest before revealing it (front-run resistance).
    /// @dev `commitment = keccak256(abi.encode(digest, salt, msg.sender))`. See `DisputeLib`.
    function commitDispute(uint256 taskId, uint32 epoch, bytes32 commitment) external whenNotPaused {
        DisputeLib.commit(_disputes, _nodeRegistered, _tasks[taskId], taskId, epoch, msg.sender, commitment);
    }

    /// @notice Reveal a committed dispute digest.
    function reportDisputeWithSalt(uint256 taskId, uint32 epoch, bytes32 reexecutedDigest, bytes32 salt) external whenNotPaused {
        DisputeLib.reveal(
            _disputes, _nodeRegistered, _tasks[taskId], _commits, _claimedDigest,
            nodeSetHash[taskId],
            taskId, epoch, msg.sender, reexecutedDigest, salt,
            vault.taskBondTotal(taskId), vault.nodeBond(taskId, msg.sender)
        );
    }

    /// @notice Re-execute epoch `epoch` and report the digest you independently obtain.
    /// @dev Deterministic given the public inputs, so an honest reporter necessarily
    ///      disagrees with a lying claimant. Reaching quorum rejects the epoch.
    ///
    ///      A report is only counted from an address that *itself* holds a verified commit for
    ///      that epoch whose `traceDigest` is the digest it reports, AND that was drawn into
    ///      the epoch's dispute committee (`isCommitteeEligible`). Without that requirement a
    ///      dispute costs nothing but two transactions — `registerNode` is permissionless —
    ///      while `_payReporters` pays `reexecutionBps` of the epoch lock out of the
    ///      buyer's escrow to whoever reports. Re-execution now has to produce a proof that
    ///      verifies, which is the work the bounty is meant to pay for.
    ///
    ///      Prefer `commitDispute` + `reportDisputeWithSalt` when the mempool is adversarial:
    ///      a bare report can be copied by any other registered node that also holds a verified
    ///      commit. Once this reporter has an open commitment, this bare path reverts.
    function reportDispute(uint256 taskId, uint32 epoch, bytes32 reexecutedDigest) external whenNotPaused {
        DisputeLib.report(
            _disputes, _nodeRegistered, _tasks[taskId], _commits, _claimedDigest,
            nodeSetHash[taskId],
            taskId, epoch, msg.sender, reexecutedDigest,
            vault.taskBondTotal(taskId), vault.nodeBond(taskId, msg.sender)
        );
    }

    /// @notice Close the epoch once its dispute window expired, or immediately once the
    ///         dispute quorum is reached. Releases the lock and pays the winner.
    function finalizeEpoch(uint256 taskId, uint32 epoch) external whenNotPaused nonReentrant {
        Task storage t = _tasks[taskId];
        if (t.status != TaskStatus.EpochCommitting) revert InvalidTaskStatus(taskId, t.status, TaskStatus.EpochCommitting);
        if (epoch != t.nextEpoch) revert EpochOutOfOrder(taskId, epoch);

        bool quorum = _disputes.count[taskId][epoch] >= DISPUTE_QUORUM;
        if (!quorum && block.timestamp < t.epochDeadline + t.params.disputeWindow) {
            revert DisputeBelowQuorum(taskId, epoch, _disputes.count[taskId][epoch], DISPUTE_QUORUM);
        }

        uint128 lock = _epochLock(t);
        address winner = _epochWinner[taskId][epoch];
        t.locked = 0;
        unchecked {
            t.nextEpoch = epoch + 1;
        }

        if (quorum) {
            // The claimant is contradicted by `DISPUTE_QUORUM` independently verified competing
            // proofs: no node is paid for this epoch, and the lock returns to the task sub-balance
            // to be refunded at settlement. Reporters are paid out of the lock so that reporting
            // is rational.
            //
            // `EpochRejected`, not `TaskAborted`: the task continues with the next epoch, and an
            // abort is terminal. Emitting the terminal event for a recoverable one made every
            // indexer watching `TaskAborted` treat a live task as dead.
            SettlementLib.payReporters(
                vault,
                taskId,
                epoch,
                _disputes.reporters[taskId][epoch],
                t.params.reexecutionBps,
                lock,
                uint64(block.timestamp) + rewardChannelWindow(),
                _authorizedSlice
            );
            // Forfeit a rejected epoch's winner bond into the task sub-balance (buyer refund at
            // settlement); custody and rationale live in `PaymentVault.slashBond`, here only the
            // call remains so this contract stays inside the deployment limit.
            vault.slashBond(taskId, epoch, winner);
            emit EpochRejected(taskId, epoch, _disputes.reporters[taskId][epoch].length);
        } else if (winner != address(0)) {
            // `lock` is *already* this epoch's slice of the node pool (`_epochLock` divides
            // `budget * nodeShareBps` across the epochs), so the node share must not be taken
            // a second time here. Re-applying `nodeShareBps` would hand the winner 15% of
            // their own pool and quietly refund the other 85% to the buyer at settlement.
            uint128 reward = lock;
            if (reward > 0) _payNode(taskId, epoch, winner, reward);
            emit EpochSettled(taskId, epoch, winner, reward);
        }

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
    ///      Ordering matters for correctness: `userPool` is frozen by the first page and
    ///      `totalWeight` moves only downward on pre-settlement slashes — and slashing is
    ///      forbidden once settlement starts (`SettlementBegun`) — so the denominator is
    ///      constant across pages: every page computes identical per-contributor amounts
    ///      and no contributor is paid twice or underpaid by paging.
    function settleFrom(uint256 taskId, uint256 cursor) external whenNotPaused nonReentrant {
        _settleFrom(taskId, cursor);
    }

    /// @notice Index of the first contributor `settleFrom` has not yet paid.
    function settleCursor(uint256 taskId) external view returns (uint256) {
        return _settlement.cursor[taskId];
    }

    /// @notice The contributor pool frozen by the first settlement page, for monitoring.
    function settleUserPool(uint256 taskId) external view returns (uint128) {
        return _settlement.userPool[taskId];
    }

    /// @notice Whether any settlement page has run.
    function isFullySettled(uint256 taskId) external view returns (bool) {
        return _settlement.settled[taskId];
    }

    function _settleFrom(uint256 taskId, uint256 cursor) private {
        Task storage t = _tasks[taskId];
        // A page may only continue an unfinished settlement; `settled` is set by the last page.
        if (_settlement.settled[taskId]) revert AlreadySettled(taskId);
        if (t.status != TaskStatus.EpochSettled) revert InvalidTaskStatus(taskId, t.status, TaskStatus.EpochSettled);
        if (t.locked != 0) revert EpochLocked(taskId);
        // `finalizeEpoch` leaves the task in `EpochSettled` with `locked == 0` after *each* epoch,
        // so without this a caller could settle after epoch 0 of 3 and take the whole escrow while
        // two epochs of paid-for work were still owed.
        if (t.nextEpoch < t.params.epochs) revert EpochsRemain(taskId);
        // Only an orderly continuation: no page may skip ahead and strand the ones before it.
        if (cursor != _settlement.cursor[taskId]) revert SettleCursorMismatch(taskId, cursor);

        // The distribution itself is `SettlementLib`, which runs here by `DELEGATECALL`: the vault
        // still sees this contract as its task manager, the state it writes is the state above, and
        // the events it emits are emitted from this address.
        SettlementLib.Outcome memory o = SettlementLib.payPage(
            vault,
            taskId,
            t,
            _contributorList[taskId],
            _contributions[taskId],
            _totalWeight,
            _settlement,
            treasury,
            SETTLE_PAGE_SIZE
        );
        if (!o.finished) return;

        // The transition is the orchestrator's own, and `TaskSettled` reports the node pool from the
        // task's parameters, so neither belongs in the library.
        _setStatus(taskId, TaskStatus.Settling);
        emit TaskSettled(taskId, o.userPool, nodePoolOf(taskId), o.committeePool);
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
        emit RevealRequested(taskId, t.lastWeightsCid, keccak256(blsAggregateSig));
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
    /// @dev This moves no money and emits no `Withdrawn`: settlement already credited the buyer's
    ///      refund to `PaymentVault`, and `PaymentVault.claim` is the call that pays it. Returning
    ///      a pending balance here — or emitting a withdrawal event for it — described money as
    ///      paid when it had only been accounted.
    function withdraw(uint256 taskId) external nonReentrant {
        Task storage t = _tasks[taskId];
        if (msg.sender != t.params.buyer && msg.sender != t.params.updateManager && msg.sender != owner) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        if (t.status != TaskStatus.Revealing) revert RevealNotAllowed(taskId, t.status);
        if (!decryptionGate.revealCompleted(taskId)) revert RevealNotAllowed(taskId, t.status);

        _setStatus(taskId, TaskStatus.Disclosed);
        emit RevealCompleted(taskId, msg.sender);
    }

    /* ------------------------------------------------------------------ */
    /*                              abort path                             */
    /* ------------------------------------------------------------------ */

    /// @notice Unwind an unfinished task and refund the buyer, net of committed epochs.
    /// @dev Callable by the buyer/update manager while the task is not yet settled. A node holding
    ///      a verified commit for the open epoch keeps a slice of that epoch's lock.
    function abort(uint256 taskId, bytes4 reason) external nonReentrant {
        Task storage t = _tasks[taskId];
        if (msg.sender != t.params.buyer && msg.sender != owner && msg.sender != t.params.updateManager) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        if (t.status == TaskStatus.Aborted || t.status == TaskStatus.Disclosed) {
            revert AlreadyTerminal(taskId, t.status);
        }
        // No `WorkInProgress` guard here by design: abort during an open epoch is a
        // supported path, and `UnwindLib.unwind` already retains a redeemable slice for a
        // node holding a verified commit (`keep`) while refunding the rest. The case that
        // must never abort — every epoch ran, so the task belongs to `settle` — is guarded
        // inside `unwind` by `SettleReady` (`nextEpoch >= epochs`).
        _unwind(taskId, reason);
    }

    /// @dev The refund half of both terminal paths, shared so the two cannot disagree about what a
    ///      buyer is owed.
    ///
    ///      A node that already produced a *verified* commit did real work, so it keeps a slice of
    ///      the open epoch's lock; everyone else is refunded in full. `abort` is terminal, so
    ///      anything not paid out here is stranded in the vault forever: the previous version
    ///      withheld `ABORT_LOCK_BPS` of the lock unconditionally and then paid it to nobody, so
    ///      every abort silently burned 20% of the epoch lock even when no node had committed
    ///      anything. Gating retention on an actual winner closes that.
    function _unwind(uint256 taskId, bytes4 reason) private {
        // The refund logic lives in `UnwindLib` (host size limit); the guards deciding whether
        // an unwind may run stay here with the state machine.
        UnwindLib.unwind(
            vault,
            _tasks[taskId],
            _settlement,
            _epochWinner,
            _authorizedSlice,
            rewardChannelWindow(),
            taskId,
            reason
        );
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
        // Buyer or update manager: both already control the epoch loop (`openEpoch`), so both
        // must be able to recover the unspent node pool. Restricting this to the buyer alone
        // stranded the refund behind a key the task may no longer use.
        if (msg.sender != t.params.buyer && msg.sender != t.params.updateManager) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        if (t.status == TaskStatus.None) revert UnknownTask(taskId);
        if (_settlement.settled[taskId]) revert AlreadySettled(taskId);
        // Settlement in flight owns the pools now: a reclaim racing the pages would
        // compute against a moving balance. Wait for the final page instead.
        if (_settlement.started[taskId]) revert SettlementBegun(taskId);
        if (t.locked != 0) revert EpochLocked(taskId);
        if (t.nextEpoch < t.params.epochs) revert EpochsRemain(taskId);
        return SettlementLib.reclaim(vault, taskId, t);
    }

    /* ------------------------------------------------------------------ */
    /*                    contribution bonds (F-01)                        */
    /* ------------------------------------------------------------------ */

    /// @notice Set (or clear with 0) the bond every contributor must post with their shard.
    /// @dev Bond requirement may only be set while the task is still `Opening` (before the
    ///      first shard). Allowing changes during `Collecting` would let the buyer/update
    ///      manager front-run a contributor's `submitContribution` with a higher bond and
    ///      censor it. Set the bond before opening contributions; after the first shard it
    ///      is frozen for the task.
    function setContributionBondRequirement(uint256 taskId, uint128 amount) external whenNotPaused {
        Task storage t = _tasks[taskId];
        if (t.status == TaskStatus.None) revert UnknownTask(taskId);
        if (msg.sender != t.params.buyer && msg.sender != t.params.updateManager) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        if (t.status != TaskStatus.Opening) revert InvalidTaskStatus(taskId, t.status, TaskStatus.Opening);
        if (amount > MAX_CONTRIBUTION_BOND) revert BondRequirementInvalid(taskId, amount);
        _bonds.required[taskId] = amount;
        emit ContributionBondRequirementSet(taskId, amount);
    }

    /// @notice Release a contributor's bond to them. Permissionless: the money can only go to
    ///         the contributor, so the caller has no discretion — mirroring `releaseBond`.
    /// @dev Releasable once the task can no longer slash it: terminal (`Aborted`/`Disclosed`)
    ///      or fully settled. Deliberately NOT `whenNotPaused`: a pause freezes protocol
    ///      progress, not exits.
    ///
    ///      The event is declared in `BondLib` (DELEGATECALL logs from here with the same topic).
    function releaseContributionBond(uint256 taskId, address contributor) external nonReentrant {
        Task storage t = _tasks[taskId];
        bool releasable = t.status == TaskStatus.Aborted ||
            t.status == TaskStatus.Disclosed ||
            _settlement.settled[taskId];
        BondLib.release(_bonds, _escrowToken, taskId, contributor, releasable);
    }

    /// @notice Slash a contributor's bond to the treasury and mark the contribution slashed
    ///         (so `settle` skips its reward share).
    /// @dev The slash goes to the treasury, never to the buyer: the buyer must gain nothing
    ///      from slashing, or slashing becomes a revenue stream and every contributor is at
    ///      the buyer's mercy.
    function slashContributionBond(uint256 taskId, address contributor) external nonReentrant {
        Task storage t = _tasks[taskId];
        if (msg.sender != t.params.buyer && msg.sender != t.params.updateManager && msg.sender != owner) {
            revert NotUpdateManagerOrOwner(taskId, msg.sender);
        }
        // The bond secures the contribution phase, not the aftermath: once the task is
        // settled or terminal, release is the only path. Without this a buyer could wait
        // until honest contributors are paid and then burn their unreleased bonds anyway —
        // grief with no fraud behind it, indistinguishable on chain from a real slash.
        if (_settlement.settled[taskId]) revert AlreadySettled(taskId);
        // No slashing once settlement began: mid-paging slashes turn honest contributors'
        // shares into dust for the dust recipient, breaking page-independence. Release is
        // the only path after this point.
        if (_settlement.started[taskId]) revert SettlementBegun(taskId);
        if (t.status == TaskStatus.Aborted || t.status == TaskStatus.Disclosed) {
            revert AlreadyTerminal(taskId, t.status);
        }
        BondLib.slash(_bonds, _contributions, _totalWeight, _escrowToken, treasury, taskId, contributor);
    }

    /// @notice Bond required of new contributions to `taskId` (0 = none).
    function contributionBondRequired(uint256 taskId) external view returns (uint128) {
        return _bonds.required[taskId];
    }

    /// @notice Bond currently posted by `contributor` on `taskId`.
    function contributionBondOf(uint256 taskId, address contributor) external view returns (uint128) {
        return _bonds.posted[taskId][contributor];
    }

    /* ------------------------------------------------------------------ */
    /*                     ERC-1271: epoch reward slices                  */
    /* ------------------------------------------------------------------ */

    /// @notice ERC-1271 signature validation for node reward slices.
    /// @dev The contract is the channel's streamer, so it authorises slices itself. A node
    ///      presents `abi.encode(channelId, sliceIndex, amount, padding)` as the "signature"
    ///      and the vault checks it against the EIP-712 digest of those same fields. Only
    ///      slices recorded by `finalizeEpoch` can ever be authorised, so there is no signer
    ///      to phish and no off-chain key that could sign a payout for a non-existent epoch.
    ///
    ///      The encoding is duplicated in `PaymentVault`; both sides hash the identical
    ///      `REDEEM_TYPEHASH` struct, so a mismatch is impossible as long as the vault's
    ///      `domainSeparator` is used, which `PaymentVault.redeem` guarantees.
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4) {
        if (signature.length != 96) return 0xffffffff;
        (uint256 channelId, uint256 sliceIndex, uint128 amount) = _decodeSlice(signature);
        uint128 authorized = _authorizedSlice[channelId][sliceIndex];
        if (authorized == 0 || authorized != amount) return 0xffffffff;
        if (digest != _sliceDigest(signature)) return 0xffffffff;
        return _1271_MAGIC;
    }

    /// @notice Digest the vault will check for a slice. Mirrors `PaymentVault.redeemDigest`,
    ///         reading the channel parameters from the vault so the two can never drift.
    function _sliceDigest(bytes calldata signature) private view returns (bytes32) {
        (uint256 channelId,,, uint256 deadline) = _decodeSliceFull(signature);
        PaymentVault.Channel memory ch = vault.channelInfo(channelId);
        if (ch.node == address(0)) return bytes32(0);
        return vault.redeemDigest(channelId, address(this), ch.node, ch.maxCumulative, ch.unlockAt, deadline);
    }

    function _decodeSlice(bytes calldata s) private pure returns (uint256 channelId, uint256 sliceIndex, uint128 amount) {
        (channelId, sliceIndex, amount,) = _decodeSliceFull(s);
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

    /// @notice The task's encrypted state accumulator, as a raw fhEVM handle. Callers that
    ///         already hold an input proof (the buyer, the update manager, a registered node)
    ///         must re-verify it with `FHE.fromExternal` before use; the raw handle alone grants
    ///         nothing, because the ACL is not extended to arbitrary readers.
    function encStateHandle(uint256 taskId) external view returns (externalEuint64) {
        return externalEuint64.wrap(FHE.toBytes32(_fhe[taskId].encState));
    }

    /// @notice Grant `account` the right to decrypt *this task's* encrypted state.
    /// @dev Restricted to the parties already ACL'd by `StateAcl.grant64` — the buyer, the
    ///      update manager, and nodes registered for this task. This was previously callable by
    ///      anyone with an arbitrary `account`, which handed a third party a decryption grant on
    ///      the buyer's encrypted loss curve, remaining noise budget and epoch checkpoint. That is
    ///      not the model weights and not any user's rows, but it is a buyer telemetry leak
    ///      reachable by an unprivileged caller, so the grant is now bounded to the set of parties
    ///      the protocol already trusts with this handle.
    /// @dev Handles, not contract singletons: with a single shared accumulator, registering as a
    ///      node on any task granted read access to every buyer's encrypted state.
    function grantStateAccess(uint256 taskId, address account) external whenNotPaused {
        Task storage t = _tasks[taskId];
        if (t.status == TaskStatus.None) revert UnknownTask(taskId);
        // Checked before the role test: the zero address is not a buyer, manager, owner or node,
        // so testing the role first would make `ZeroAddress` unreachable for the only input it
        // exists to reject.
        if (account == address(0)) revert ZeroAddress();
        if (account != t.params.buyer && account != t.params.updateManager && account != owner) {
            if (!_nodeRegistered[taskId][account]) revert NotTaskParty(taskId, account);
        }
        StateAcl.allow64(_fhe[taskId].encState, account);
        emit StateAccessGranted(taskId, account);
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
        return (DISPUTE_QUORUM, _disputes.count[taskId][_tasks[taskId].nextEpoch]);
    }

    /// @notice Expected dispute-committee seats per epoch (see `DisputeLib`).
    /// @dev Single definition lives in the library; this getter keeps clients
    ///      (tests, SDK, node) pinned to it without duplicating the number.
    function committeeSize() external pure returns (uint256) {
        return DisputeLib.COMMITTEE_SIZE;
    }

    /// @notice Sortition seed for an epoch's dispute committee (zero before the first report).
    function committeeSeed(uint256 taskId, uint32 epoch) external view returns (bytes32) {
        return _disputes.seed[taskId][epoch];
    }

    /// @notice Whether `reporter` may dispute in this epoch: drawn members of the
    ///         committee fixed by the epoch seed, weighted by posted bond. False before
    ///         the first report (no seed yet) and for stake the lottery did not pick.
    function isCommitteeEligible(uint256 taskId, uint32 epoch, address reporter)
        external
        view
        returns (bool)
    {
        return DisputeLib.isEligibleSeed(
            _disputes.seed[taskId][epoch],
            vault.taskBondTotal(taskId),
            vault.nodeBond(taskId, reporter),
            reporter
        );
    }

    /// @notice STARK transcript bound to the node. H2 fix: `node` is a public input so a
    ///         proof cannot be replayed under a different address.
    function proofTranscript(uint256 taskId, uint32 epoch, bytes32 traceDigest, address node) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                "SHROUD/PoC/v1",
                block.chainid,
                address(this),
                taskId,
                epoch,
                _tasks[taskId].ctRoot,
                _tasks[taskId].lastWeightsDigest,
                traceDigest,
                node
            )
        );
    }

    function statusOf(uint256 taskId) external view returns (TaskStatus) {
        return _tasks[taskId].status;
    }

    function nodeRegistered(uint256 taskId, address node) external view returns (bool) {
        return _nodeRegistered[taskId][node];
    }

    function nodeCount(uint256 taskId) external view returns (uint32) {
        return _nodeCount[taskId];
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
        return RewardLib.epochLock(t);
    }

    /// @dev Open the winner's reward channel and authorise its first slice. The contract is
    ///      the streamer, so the node can redeem without any off-chain signer.
    function _payNode(uint256 taskId, uint32 epoch, address node, uint128 reward) private {
        RewardLib.payNode(
            vault, _epochChannel, _authorizedSlice, rewardChannelWindow(), taskId, epoch, node, reward
        );
    }

    function _setStatus(uint256 taskId, TaskStatus to) private {
        Task storage t = _tasks[taskId];
        TaskStatus from = t.status;
        if (from == to) return;
        t.status = to;
        emit TaskStatusChanged(taskId, from, to);
    }
}
