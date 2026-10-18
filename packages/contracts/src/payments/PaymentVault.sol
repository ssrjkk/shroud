// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "../interfaces/IERC20.sol";
import {ICipherTask} from "../interfaces/ICipherTask.sol";
import {ReentrancyGuard, Pausable} from "../libraries/Guard.sol";

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magic);
}

/// @title PaymentVault
/// @notice Per-task escrow and EIP-712 signed streaming payment channels for Shroud.
///
/// @dev ## Accounting model
///
///      The vault keeps a **sub-balance per task**, so a bug in one task's accounting can never
///      overdraw another task's escrow:
///
///        totalLocked == Σ taskBalance[i] + Σ channel[i].locked + Σ nodeBond[i]
///
///      Registration bonds are the third term: custodied here but never sub-balance money, so a
///      bond can never be swept into a buyer refund.
///
///      `CipherTask` is the only address allowed to move funds between a task sub-balance, a
///      reward channel, and a pending claim. Everything else is either a pull by the earner or
///      an owner-level governance action.
///
/// @dev ## Why signed slices, and who signs
///
///      Compute nodes earn per epoch, and a node must not depend on a single RPC endpoint
///      being alive to collect. So a reward is a *channel*: `CipherTask` opens the channel at
///      `finalizeEpoch` (after the STARK verified) and simultaneously signs an EIP-1271 slice
///      authorising the first redemption. The node then redeems slices on its own schedule.
///
///      This is deliberately **not** an off-chain signer: the streamer is the contract, so the
///      signature is only produced after on-chain proof verification, and the byte-for-byte
///      equivalence of the Solidity and Rust encodings is directly auditable.
///
///      A channel's `streamer` is always `msg.sender` of `openTaskChannel`, i.e. the task
///      manager. In the standard deployment that is `CipherTask`, so `redeem` validates the slice
///      through ERC-1271. An EOA task manager (a private instance running its own epoch loop,
///      which `setTaskManager` permits) is supported by the same function through the ECDSA
///      branch, and `closeChannel` is that configuration's recovery path: an EOA manager can
///      close its own channels and return the remainder to the task, which a contract manager
///      does through `sweepTaskChannels` instead.
contract PaymentVault is ReentrancyGuard, Pausable {
    struct Channel {
        address node; // earner
        address streamer; // signer (CipherTask, or an EOA buyer delegate)
        uint128 maxCumulative; // hard cap locked from the task sub-balance
        uint128 withdrawn; // cumulative of the last redeemed slice
        uint256 taskId; // sub-balance this lock belongs to
        uint64 consumed; // next sliceIndex the channel expects (slices are redeemed in order)
        uint64 unlockAt; // after this, the node may reclaim the whole lock
        bool closed;
    }

    bytes32 public constant REDEEM_TYPEHASH =
        keccak256(
        "Redeem(uint256 channelId,address streamer,address node,uint128 maxCumulative,uint64 unlockAt,uint256 deadline)"
    );
    bytes32 private constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _UPPER_S =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    bytes4 private constant _1271_MAGIC = 0x1626ba7e;

    string public constant name = "ShroudPaymentVault";
    string public constant version = "1";

    IERC20 public immutable token;
    bytes32 public immutable domainSeparator;

    address public owner;
    address public pendingOwner;
    address public taskManager; // CipherTask.sol — the only address allowed to move escrow

    /// @dev How long a task-manager rotation must be visible before it takes effect.
    uint64 public constant TASK_MANAGER_DELAY = 7 days;
    address public proposedTaskManager;
    uint64 public taskManagerEta;

    uint256 public channelNonce;
    mapping(uint256 => Channel) public channels;
    mapping(address => uint256) public pendingWithdrawal;

    /// @notice Sum of all `pendingWithdrawal` balances, maintained incrementally.
    /// @dev Needed by `rescueStrayTokens`: credited-but-unclaimed amounts are no longer part of
    ///      `totalLocked` (the debit already happened) yet their tokens are still inside the
    ///      vault, so they must be excluded from what counts as stray.
    uint256 public pendingTotal;

    /// @notice Escrow funded for, and still owned by, a task.
    mapping(uint256 => uint256) public taskBalance;
    /// @notice Sum of funds ever locked into channels of a task (for audit/reporting).
    mapping(uint256 => uint256) public taskChannelLocked;
    /// @notice Channel ids opened per task, for reclamation.
    mapping(uint256 => uint256[]) public taskChannels;

    uint256 public totalLocked; // = subBalancesTotal + channelLocksTotal + bondTotal
    uint256 public subBalancesTotal; // Σ taskBalance
    uint256 public channelLocksTotal; // Σ open (maxCumulative - withdrawn)
    uint256 public totalWithdrawn;
    /// @notice Sum of all registration bonds held, maintained incrementally.
    /// @dev Bonds are a first-class term of the accounting invariant, not sub-balance money:
    ///      sub-balances are buyer-refundable at settlement by construction, and a bond swept
    ///      into a refund would pay the buyer with the node's money.
    uint256 public bondTotal;
    /// @dev Registration bond per node per task, in escrow-token base units (10 CMUSD at 6 dp).
    ///      Flat protocol constant, not per-task math, so operators know what to approve without
    ///      reading the task: `REGISTRATION_BOND()` is the number. Sized at ~20% of a typical
    ///      epoch lock, so a 3-address ring locks 3× the bond for the task's whole life — a real
    ///      spam cost, not a fee, and not a Sybil *proof*: locked capital returns to the attacker
    ///      afterwards (see F-04).
    uint128 public constant REGISTRATION_BOND = 10_000_000;
    /// @notice Bonds posted, keyed by task then node. Released by `releaseBond`, forfeited by
    ///         `slashBond`; never counted toward any task sub-balance until slashed.
    mapping(uint256 => mapping(address => uint128)) public nodeBond;
    /// @notice Sum of `nodeBond` per task: the stake weight the dispute sortition draws
    ///         against (`DisputeLib`). Maintained incrementally on every bond movement
    ///         (take/release/slash/top-up); it is a view over `nodeBond`, not new money,
    ///         so the accounting invariant below does not contain it as a separate term.
    mapping(uint256 => uint256) public taskBondTotal;
    /// @dev BLS keys already taken for a task. Keys are self-declared, so this stops accidents
    ///      and lazy key reuse, not a determined Sybil — generating fresh keys is free, and the
    ///      bond is what makes fresh identities cost.
    mapping(uint256 => mapping(bytes32 => bool)) public blsKeyUsed;

    error InvalidSignature();
    error NotStreamer(address caller);
    error NotNode(address caller, uint256 channelId);
    error NotOwner(address caller);
    error NotTaskManager(address caller);
    error SliceNotMonotonic(uint256 channelId, uint256 provided, uint256 consumed);
    error SliceIndexOutOfRange(uint256 channelId, uint256 sliceIndex);
    error ExceedsCap(uint256 channelId, uint256 amount, uint256 cap);
    error InsufficientTaskBalance(uint256 taskId, uint256 available, uint256 required);
    error ChannelClosed(uint256 channelId);
    error TooEarly(uint256 channelId, uint64 unlockAt);
    error DeadlineExpired(uint256 deadline);
    error NothingToClaim(address account);
    error ZeroAmount();
    error ZeroAddress();
    error TransferFailed(address token, address to, uint256 amount);
    error InvariantViolated(uint256 totalLocked, uint256 accounted);
    error TaskManagerAlreadySet();
    error NoPendingTaskManager();
    error PendingRotationExists(address proposed, uint64 eta);
    error TaskManagerUnchanged(address proposed);
    error TaskManagerNotReady(uint64 eta);
    error NothingToRescue();
    // Bond errors are declared in `ICipherTask` (same selectors) so reverts propagating through
    // `CipherTask.registerNode` resolve against the orchestrator ABI; redeclared here for
    // compilation.
    error BondInsufficient(uint256 taskId, address node, uint128 required);
    error BlsKeyAlreadyUsed(uint256 taskId, bytes32 blsPubKey);
    error ZeroBlsKey(uint256 taskId, address node);
    error BondNotReleasable(uint256 taskId, address node);

    event TaskFunded(uint256 indexed taskId, address indexed from, uint256 amount, uint256 newBalance);
    event ChannelOpened(
        uint256 indexed channelId,
        uint256 indexed taskId,
        address indexed node,
        address streamer,
        uint128 maxCumulative,
        uint64 unlockAt
    );
    event SliceRedeemed(uint256 indexed channelId, address indexed node, uint128 cumulative, uint128 amount, uint256 sliceIndex);
    event ChannelReclaimed(uint256 indexed channelId, address indexed node, uint128 amount);
    event ChannelClosedByStreamer(uint256 indexed channelId, uint128 returned, uint256 indexed taskId);
    event WithdrawalCredited(address indexed account, uint256 amount, uint256 indexed taskId);
    event WithdrawalClaimed(address indexed account, uint256 amount);
    event TaskManagerChanged(address indexed from, address indexed to);
    event TaskManagerProposed(address indexed to, uint64 indexed eta);
    event TaskManagerRotationCancelled(address indexed proposed);
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);
    event StrayTokensRescued(address indexed to, uint256 amount);
    // Bond events are declared in `ICipherTask` (identical topics); redeclared here for
    // compilation — a vault log decodes the same through the orchestrator ABI.
    event NodeBondSlashed(uint256 indexed taskId, uint32 indexed epoch, address indexed node, uint128 amount);
    event NodeBondWithdrawn(uint256 indexed taskId, address indexed node, uint128 amount);
    event NodeBondToppedUp(uint256 indexed taskId, address indexed node, uint128 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    modifier onlyTaskManager() {
        if (msg.sender != taskManager) revert NotTaskManager(msg.sender);
        _;
    }

    constructor(address token_) {
        if (token_ == address(0)) revert ZeroAddress();
        owner = msg.sender;
        token = IERC20(token_);
        domainSeparator = keccak256(
            abi.encode(_DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, address(this))
        );
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /* ------------------------------------------------------------------ */
    /*                              governance                             */
    /* ------------------------------------------------------------------ */

    /// @notice Begin a two-step ownership handover.
    /// @dev Two-step because a single-step transfer to a wrong or incapable address is
    ///      unrecoverable *and* silent: the old owner simply stops being able to act, and there is
    ///      no remaining key that can undo it. `pendingOwner` must accept.
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

    /// @notice Install the orchestrator, once.
    /// @dev Only usable while `taskManager` is unset. This function used to repoint the manager at
    ///      any time, and `taskManager` is the single address allowed to move every task's
    ///      escrow: `creditFromTask`, `openTaskChannel` and `sweepTaskChannels` together transfer
    ///      the whole vault to whoever holds the slot. One owner transaction was therefore enough
    ///      to take everyone's funds, with no notice and no window for anyone else to react. The
    ///      bootstrap stays immediate (no funds exist yet) and every later change goes through the
    ///      timelock below.
    function setTaskManager(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (taskManager != address(0)) revert TaskManagerAlreadySet();
        emit TaskManagerChanged(taskManager, to);
        taskManager = to;
    }

    /// @notice Queue a task-manager rotation, effective `TASK_MANAGER_DELAY` after it is proposed.
    /// @dev The delay is what makes a hostile rotation useless: escrow only moves through
    ///      `onlyTaskManager` calls, and anyone watching `TaskManagerProposed` has a week to
    ///      `setPaused(true)`, which blocks `fundTask`, `creditFromTask`, `openTaskChannel` and
    ///      `sweepTaskChannels` — every path that could drain anything — before the new manager is
    ///      installed. A malicious manager installed behind a pause can move no funds.
    /// @dev Re-proposing while a rotation is live reverts: the queued candidate and its `eta`
    ///      are what observers rely on, and silently swapping the candidate mid-timelock would
    ///      let the owner present one address to watchers and install another. Cancel first —
    ///      the cancellation itself is an event — then propose the new candidate.
    function proposeTaskManager(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (to == taskManager) revert TaskManagerUnchanged(to);
        if (proposedTaskManager != address(0)) {
            revert PendingRotationExists(proposedTaskManager, taskManagerEta);
        }
        proposedTaskManager = to;
        taskManagerEta = uint64(block.timestamp) + TASK_MANAGER_DELAY;
        emit TaskManagerProposed(to, taskManagerEta);
    }

    /// @notice Execute the queued rotation. Callable by anyone once the delay has elapsed, so a
    ///         rotated-in manager is not hostage to a lost owner key.
    function executeTaskManager() external {
        address to = proposedTaskManager;
        if (to == address(0)) revert NoPendingTaskManager();
        if (block.timestamp < taskManagerEta) revert TaskManagerNotReady(taskManagerEta);
        emit TaskManagerChanged(taskManager, to);
        taskManager = to;
        proposedTaskManager = address(0);
        taskManagerEta = 0;
    }

    function cancelTaskManager() external onlyOwner {
        address dropped = proposedTaskManager;
        if (dropped == address(0)) revert NoPendingTaskManager();
        proposedTaskManager = address(0);
        taskManagerEta = 0;
        emit TaskManagerRotationCancelled(dropped);
    }

    function setPaused(bool v) external onlyOwner {
        _setPaused(v);
    }

    /* ================================================================== */
    /*                        ORCHESTRATOR: ESCROW IN                     */
    /* ================================================================== */

    /// @notice Fund the sub-balance of `taskId` by pulling `amount` from `from`.
    /// @dev Fee-on-transfer safe: the ledger records what actually arrived (balance diff),
    ///      never what was requested. A fee-taking token therefore fails closed at the
    ///      orchestrator's `EscrowMismatch` check instead of silently under-collateralising
    ///      the task.
    function fundTask(uint256 taskId, uint256 amount, address from) external onlyTaskManager whenNotPaused nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (from == address(0)) revert ZeroAddress();
        uint256 received = _pull(from, amount);
        taskBalance[taskId] += received;
        subBalancesTotal += received;
        totalLocked += received;
        emit TaskFunded(taskId, from, received, taskBalance[taskId]);
    }

    /// @notice Move `amount` from a task's sub-balance into `account`'s pending balance.
    function creditFromTask(uint256 taskId, address account, uint256 amount) external onlyTaskManager whenNotPaused nonReentrant {
        if (amount == 0) revert ZeroAmount();
        _debitTask(taskId, amount);
        pendingWithdrawal[account] += amount;
        pendingTotal += amount;
        _assertInvariant();
        emit WithdrawalCredited(account, amount, taskId);
    }

    /* ================================================================== */
    /*                        NODE BONDS (REGISTRATION)                   */
    /* ================================================================== */

    /// @notice Pull the registration bond from `node` and record its BLS key. Called by the
    ///         orchestrator from `registerNode`; nodes approve this vault (the same two-step
    ///         pattern as the buyer's escrow: approve the vault, then register).
    /// @dev Bonds are custodied here but are NOT sub-balance money: `nodeBond` is its own term
    ///      of the accounting invariant, so a bond can never be swept into a buyer refund. The
    ///      orchestrator's `registerNode` has already checked the task exists and the node is
    ///      not yet registered; key validity and payment are checked here.
    function takeBond(uint256 taskId, address node, bytes32 blsPubKey) external onlyTaskManager whenNotPaused nonReentrant {
        if (blsPubKey == bytes32(0)) revert ZeroBlsKey(taskId, node);
        if (blsKeyUsed[taskId][blsPubKey]) revert BlsKeyAlreadyUsed(taskId, blsPubKey);
        if (token.allowance(node, address(this)) < REGISTRATION_BOND) {
            revert BondInsufficient(taskId, node, REGISTRATION_BOND);
        }
        blsKeyUsed[taskId][blsPubKey] = true;
        nodeBond[taskId][node] = REGISTRATION_BOND;
        bondTotal += REGISTRATION_BOND;
        taskBondTotal[taskId] += REGISTRATION_BOND;
        totalLocked += REGISTRATION_BOND;
        // Fail closed on fee-on-transfer tokens: the bond must arrive whole, otherwise the
        // quorum price the threat model (F-04) assumes is not actually posted.
        uint256 received = _pull(node, REGISTRATION_BOND);
        if (received != REGISTRATION_BOND) revert BondInsufficient(taskId, node, REGISTRATION_BOND);
        _assertInvariant();
    }

    /// @notice Add to your own registration bond, raising your dispute-sortition weight.
    /// @dev Only the bond owner tops up their own position (`msg.sender == node`): the
    ///      money trail stays unambiguous, and funding someone else's weight is pointless
    ///      anyway (weight is per node). Requires an existing bond — top-up is not a
    ///      backdoor registration (no BLS key, no node count). Fail-closed on
    ///      fee-on-transfer tokens, mirroring `takeBond`; checked arithmetic guards
    ///      the `uint128` position on absurd inputs.
    function topUpNodeBond(uint256 taskId, uint128 amount) external whenNotPaused nonReentrant {
        address node = msg.sender;
        if (amount == 0) revert ZeroAmount();
        if (nodeBond[taskId][node] == 0) revert BondNotReleasable(taskId, node);
        if (token.allowance(node, address(this)) < amount) {
            revert BondInsufficient(taskId, node, amount);
        }
        nodeBond[taskId][node] += amount;
        bondTotal += amount;
        taskBondTotal[taskId] += amount;
        totalLocked += amount;
        uint256 received = _pull(node, amount);
        if (received != amount) revert BondInsufficient(taskId, node, amount);
        _assertInvariant();
        emit NodeBondToppedUp(taskId, node, amount);
    }

    /// @notice Release `node`'s bond to it, once the task can no longer slash it: terminal
    ///         (`Aborted`/`Disclosed`) or fully settled. Permissionless — the money can only go
    ///         to the bond's owner — so a node never depends on anyone else to exit.
    /// @dev Deliberately NOT `whenNotPaused` (like `claim`): a pause freezes protocol progress,
    ///      not exits. Trapping bonds behind an emergency pause would turn a safety lever into a
    ///      hostage mechanism.
    function releaseBond(uint256 taskId, address node) external nonReentrant {
        uint128 bond = nodeBond[taskId][node];
        if (bond == 0) revert BondNotReleasable(taskId, node);
        ICipherTask manager = ICipherTask(taskManager);
        ICipherTask.TaskStatus status = manager.statusOf(taskId);
        if (
            status != ICipherTask.TaskStatus.Aborted &&
            status != ICipherTask.TaskStatus.Disclosed &&
            !manager.isFullySettled(taskId)
        ) {
            revert BondNotReleasable(taskId, node);
        }
        nodeBond[taskId][node] = 0;
        bondTotal -= bond;
        taskBondTotal[taskId] -= bond;
        totalLocked -= bond;
        _assertInvariant();
        _push(node, bond);
        emit NodeBondWithdrawn(taskId, node, bond);
    }

    /// @notice Forfeit a rejected epoch's `winner` bond into the task sub-balance, where it joins
    ///         the buyer refund at settlement. Called by the orchestrator from the dispute-quorum
    ///         branch of `finalizeEpoch`.
    /// @dev The winner is the address three independently verified proofs disagree with — the
    ///      strongest on-chain signal of a lying claimant the protocol has. Reporters keep their
    ///      bonds: the chain cannot tell a lying winner from a lying quorum, so punishing
    ///      reporters would tax honest disputes (see F-04). A griefing quorum can still burn an
    ///      honest winner's bond; the bond prices that grief, it does not prevent it. A missing
    ///      bond (never posted, already released) is a silent no-op, never a revert: slashing is
    ///      a consequence of rejection, not a precondition of it.
    function slashBond(uint256 taskId, uint32 epoch, address winner) external onlyTaskManager nonReentrant {
        uint128 bond = nodeBond[taskId][winner];
        if (bond == 0) return;
        nodeBond[taskId][winner] = 0;
        bondTotal -= bond;
        taskBondTotal[taskId] -= bond;
        // Reclassification, not movement: the tokens stay in the vault while the ledger moves
        // them from the bond term to the sub-balance term. `totalLocked` is untouched, so the
        // invariant holds by construction rather than by recomputation.
        taskBalance[taskId] += bond;
        subBalancesTotal += bond;
        _assertInvariant();
        emit NodeBondSlashed(taskId, epoch, winner, bond);
    }

    /* ================================================================== */
    /*                     ORCHESTRATOR: CHANNELS OUT                     */
    /* ================================================================== */

    /// @notice Lock `maxCumulative` of a task's sub-balance for `node`, with `msg.sender`
    ///         (the orchestrator) as the signing streamer.
    function openTaskChannel(
        uint256 taskId,
        address node,
        uint128 maxCumulative,
        uint64 unlockAt
    ) external onlyTaskManager whenNotPaused nonReentrant returns (uint256 channelId) {
        if (node == address(0)) revert ZeroAddress();
        if (maxCumulative == 0) revert ZeroAmount();
        uint256 bal = taskBalance[taskId];
        if (bal < maxCumulative) revert InsufficientTaskBalance(taskId, bal, maxCumulative);
        unchecked {
            taskBalance[taskId] = bal - maxCumulative;
            subBalancesTotal -= maxCumulative;
        }

        channelId = ++channelNonce;
        uint64 unlock = unlockAt == 0 ? uint64(block.timestamp + 30 days) : unlockAt;
        channels[channelId] = Channel({
            node: node,
            streamer: msg.sender,
            maxCumulative: maxCumulative,
            withdrawn: 0,
            taskId: taskId,
            consumed: 0,
            unlockAt: unlock,
            closed: false
        });
        taskChannels[taskId].push(channelId);
        taskChannelLocked[taskId] += maxCumulative;
        channelLocksTotal += maxCumulative; // `totalLocked` unchanged: sub-balance -> channel
        _assertInvariant();
        emit ChannelOpened(channelId, taskId, node, msg.sender, maxCumulative, unlock);
    }

    /// @notice Close every open channel of a task, returning all unconsumed locks to the
    ///         task sub-balance. No funds leave the vault.
    /// @dev Called by the orchestrator at settlement so the sub-balance reflects reality
    ///      before it computes the contributor/committee/buyer split.
    /// @dev A channel whose reward window has not matured yet is left open. Sweeping it would
    ///      hand a node that already delivered a valid proof nothing at all, purely because
    ///      settlement ran before it claimed, and the orchestrator would then refund its money
    ///      to the buyer. The window exists to bound exactly that race, so it is honoured here.
    function sweepTaskChannels(uint256 taskId) external onlyTaskManager whenNotPaused nonReentrant returns (uint128 recovered) {
        uint256[] memory ids = taskChannels[taskId];
        for (uint256 i = 0; i < ids.length; ++i) {
            Channel storage ch = channels[ids[i]];
            if (ch.closed) continue;
            if (ch.unlockAt > block.timestamp) continue; // still claimable
            ch.closed = true;
            uint128 amount = ch.maxCumulative - ch.withdrawn;
            uint128 freed = ch.maxCumulative;
            taskChannelLocked[taskId] -= freed;
            channelLocksTotal -= amount;
            if (amount == 0) continue;
            taskBalance[taskId] += amount;
            subBalancesTotal += amount;
            recovered += amount;
        }
        _assertInvariant();
    }

    /* ================================================================== */
    /*                          EARNEER: SLICES                           */
    /* ================================================================== */

    /// @notice Redeem slice `sliceIndex` authorised by the channel's streamer.
    /// @dev Accepts an EIP-1271 signature when the streamer is a contract (CipherTask) and a
    ///      plain ECDSA signature when it is an EOA. `amount` is cumulative, so nothing can be
    ///      claimed twice, and `sliceIndex` must strictly increase, so a replay is worthless.
    function redeem(
        uint256 channelId,
        uint256 sliceIndex,
        uint128 amount,
        uint256 deadline,
        bytes calldata signature
    ) external whenNotPaused nonReentrant returns (uint128 paid) {
        if (block.timestamp > deadline) revert DeadlineExpired(deadline);

        // `consumed` is a `uint64`, and `uint64(sliceIndex)` truncates rather than reverting. An
        // index of `2**64` therefore folded to 0 and set `consumed` back to 1, silently rewinding
        // the monotonic counter F-14 relies on. No profit follows from it (`withdrawn` only ever
        // grows, and it is what bounds the money), but the index is the replay guard, so the
        // counter must never move backwards. Bounding the index here also guarantees the `+ 1`
        // below cannot overflow.
        if (sliceIndex >= type(uint64).max) revert SliceIndexOutOfRange(channelId, sliceIndex);

        Channel storage ch = channels[channelId];
        if (ch.node == address(0) || ch.node != msg.sender) revert NotNode(msg.sender, channelId);
        if (ch.closed) revert ChannelClosed(channelId);
        // `consumed` holds the *next* expected slice index, so the first slice (index 0) is
        // redeemable. Comparing with `<=` against a "highest index used" counter would lock
        // out slice 0 forever, because the counter starts at 0.
        if (sliceIndex < ch.consumed) revert SliceNotMonotonic(channelId, sliceIndex, ch.consumed);
        if (amount > ch.maxCumulative) revert ExceedsCap(channelId, amount, ch.maxCumulative);
        bytes32 structHash =
            keccak256(abi.encode(REDEEM_TYPEHASH, channelId, ch.streamer, ch.node, ch.maxCumulative, ch.unlockAt, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        if (!_authorize(digest, signature, ch.streamer)) revert InvalidSignature();

        if (amount <= ch.withdrawn) {
            // Nothing new to pay. The index is still consumed, so the same signature cannot later
            // be replayed against a different amount, and a larger slice stays redeemable. The
            // consumption happens *after* `_authorize` rather than before it: `consumed` is the
            // replay guard, and a path that mutates it without authenticating the caller first is
            // a path where the guard stops being evidence that the streamer signed something.
            ch.consumed = uint64(sliceIndex) + 1;
            return 0;
        }

        ch.consumed = uint64(sliceIndex) + 1;
        paid = amount - ch.withdrawn;
        ch.withdrawn = amount;

        totalLocked -= paid;
        channelLocksTotal -= paid;
        totalWithdrawn += paid;
        _assertInvariant();
        _push(msg.sender, paid);
        emit SliceRedeemed(channelId, msg.sender, amount, paid, sliceIndex);
    }

    /// @notice Reclaim the remaining lock after `unlockAt` (streamer went silent).
    function reclaim(uint256 channelId) external nonReentrant returns (uint128 amount) {
        Channel storage ch = channels[channelId];
        if (ch.node == address(0) || ch.node != msg.sender) revert NotNode(msg.sender, channelId);
        if (ch.closed) revert ChannelClosed(channelId);
        if (block.timestamp < ch.unlockAt) revert TooEarly(channelId, ch.unlockAt);

        ch.closed = true;
        amount = ch.maxCumulative - ch.withdrawn;
        uint128 freed = ch.maxCumulative;
        // The remaining lock goes to the earner, not back to the task sub-balance: the funds
        // leave the vault, so `totalLocked` shrinks and the channel's contribution to
        // `channelLocksTotal` is removed. Touching `taskBalance`/`subBalancesTotal` here would
        // double-count the amount (it would be both a channel release and a sub-balance credit
        // with no backing tokens).
        taskChannelLocked[ch.taskId] -= freed;
        channelLocksTotal -= amount;
        totalLocked -= amount; // funds leave the vault to the earner
        totalWithdrawn += amount;
        _push(msg.sender, amount);
        _assertInvariant();
        emit ChannelReclaimed(channelId, msg.sender, amount);
    }

    /// @notice EOA streamer closes a channel and recovers the unconsumed remainder.
    function closeChannel(uint256 channelId) external nonReentrant returns (uint128 amount) {
        Channel storage ch = channels[channelId];
        if (ch.streamer != msg.sender) revert NotStreamer(msg.sender);
        if (ch.closed) revert ChannelClosed(channelId);
        ch.closed = true;
        amount = ch.maxCumulative - ch.withdrawn;
        uint128 freed = ch.maxCumulative;
        taskBalance[ch.taskId] += amount;
        subBalancesTotal += amount;
        taskChannelLocked[ch.taskId] -= freed;
        channelLocksTotal -= amount;
        _assertInvariant();
        emit ChannelClosedByStreamer(channelId, amount, ch.taskId);
    }

    /* ================================================================== */
    /*                             PULL-BASED OUT                          */
    /* ================================================================== */

    function claim() external nonReentrant returns (uint256 amount) {
        amount = pendingWithdrawal[msg.sender];
        if (amount == 0) revert NothingToClaim(msg.sender);
        pendingWithdrawal[msg.sender] = 0;
        pendingTotal -= amount;
        _push(msg.sender, amount);
        emit WithdrawalClaimed(msg.sender, amount);
    }

    /// @notice Send tokens that are in the vault but owed to nobody back to the owner.
    /// @dev ERC-20 transfers arrive from *anyone*, including users who skip `fundTask` and send
    ///      USDC straight to the vault address. Such a transfer is invisible to the accounting
    ///      model — it joins neither a task sub-balance nor a channel — so before this existed it
    ///      simply sat here forever with no function anywhere in the contract able to move it.
    /// @dev What is *not* stray is precisely what the vault owes: `totalLocked` (task sub-balances,
    ///      channel locks and bonds) plus `pendingTotal` (credited and awaiting `claim`). Both are
    ///      maintained on every movement, so the subtraction cannot be talked into releasing
    ///      escrowed funds; a mistaken deposit is recoverable, an escrowed one never is.
    function rescueStrayTokens() external onlyOwner nonReentrant returns (uint256 amount) {
        uint256 owed = totalLocked + pendingTotal;
        uint256 balance = token.balanceOf(address(this));
        if (balance <= owed) revert NothingToRescue();
        amount = balance - owed;
        _push(owner, amount);
        emit StrayTokensRescued(owner, amount);
    }

    /* ------------------------------------------------------------------ */
    /*                                views                                */
    /* ------------------------------------------------------------------ */

    function channelInfo(uint256 channelId) external view returns (Channel memory) {
        return channels[channelId];
    }

    function channelIds(uint256 taskId) external view returns (uint256[] memory) {
        return taskChannels[taskId];
    }

    /// @notice Whether `taskId` still has an open reward channel whose window has not matured.
    /// @dev Read by the orchestrator's settlement path: the final page must wait until every
    ///      channel has either been redeemed/reclaimed or swept back, otherwise the committee
    ///      leg is capped against an incomplete balance and the shortfall is permanent
    ///      (threat model F-22). Earlier pages are unaffected — contributor shares come from
    ///      the frozen pool, which node locks can never eat into — only the last page gates.
    function hasImmatureChannels(uint256 taskId) external view returns (bool) {
        uint256[] memory ids = taskChannels[taskId];
        for (uint256 i = 0; i < ids.length; ++i) {
            Channel storage ch = channels[ids[i]];
            if (!ch.closed && ch.unlockAt > block.timestamp) return true;
        }
        return false;
    }

    /// @notice EIP-712 digest a streamer must sign for a slice.
    function redeemDigest(
        uint256 channelId,
        address streamer,
        address node,
        uint128 maxCumulative,
        uint64 unlockAt,
        uint256 deadline
    ) external view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    domainSeparator,
                    keccak256(abi.encode(REDEEM_TYPEHASH, channelId, streamer, node, maxCumulative, unlockAt, deadline))
                )
            );
    }

    /// @notice `totalLocked` must always equal sub-balances plus open channel locks plus bonds.
    function accountedLocked() public view returns (uint256) {
        return subBalancesTotal + channelLocksTotal + bondTotal;
    }

    /* ------------------------------------------------------------------ */
    /*                              internals                              */
    /* ------------------------------------------------------------------ */

    function _debitTask(uint256 taskId, uint256 amount) private {
        uint256 bal = taskBalance[taskId];
        if (bal < amount) revert InsufficientTaskBalance(taskId, bal, amount);
        unchecked {
            taskBalance[taskId] = bal - amount;
            subBalancesTotal -= amount;
        }
        totalLocked -= amount; // funds leave the vault
    }

    function _authorize(bytes32 digest, bytes calldata signature, address streamer) private view returns (bool) {
        // Contract streamers (the orchestrator) authorise slices themselves via ERC-1271.
        if (streamer.code.length > 0) {
            (bool ok, bytes memory ret) = streamer.staticcall(abi.encodeCall(IERC1271.isValidSignature, (digest, signature)));
            if (!ok || ret.length < 32) return false;
            return abi.decode(ret, (bytes4)) == _1271_MAGIC;
        }
        if (signature.length != 65) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        if (v != 27 && v != 28) return false;
        if (s > _UPPER_S) return false; // reject malleable signatures (F-14)
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == streamer;
    }

    function _pull(address from, uint256 amount) private returns (uint256 received) {
        // Balance-diff accounting: fee-on-transfer / rebasing tokens may deliver less (or, for
        // rebasing, more) than `amount`. Recording the diff instead of `amount` keeps
        // `totalLocked` equal to tokens actually held, so the invariant tripwire stays exact.
        // Defensive against non-standard tokens (USDT returns no data on success).
        uint256 before = token.balanceOf(address(this));
        (bool ok, bytes memory ret) = address(token).call(abi.encodeCall(IERC20.transferFrom, (from, address(this), amount)));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed(address(token), from, amount);
        uint256 afterBal = token.balanceOf(address(this));
        received = afterBal > before ? afterBal - before : 0;
    }

    function _push(address to, uint256 amount) private {
        if (amount == 0) return;
        (bool ok, bytes memory ret) = address(token).call(abi.encodeCall(IERC20.transfer, (to, amount)));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed(address(token), to, amount);
    }

    /// @dev O(1): `channelLocksTotal` is maintained incrementally on every channel movement,
    ///      `subBalancesTotal` on every sub-balance movement and `bondTotal` on every bond
    ///      movement, so `totalLocked == subBalancesTotal + channelLocksTotal + bondTotal` is
    ///      checkable in constant time. This is the tripwire that catches an accounting bug before
    ///      it becomes a drainable one; it is cheap enough to sit on the orchestrator hot path.
    function _assertInvariant() private view {
        if (totalLocked != subBalancesTotal + channelLocksTotal + bondTotal) {
            revert InvariantViolated(totalLocked, subBalancesTotal + channelLocksTotal + bondTotal);
        }
    }
}
