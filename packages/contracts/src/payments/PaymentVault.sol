// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "../interfaces/IERC20.sol";
import {ReentrancyGuard, Pausable} from "../libraries/Guard.sol";

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magic);
}

/// @title PaymentVault
/// @notice Per-task escrow and EIP-712 signed streaming payment channels for CipherMesh.
///
/// @dev ## Accounting model
///
///      The vault keeps a **sub-balance per task**, so a bug in one task's accounting can never
///      overdraw another task's escrow:
///
///        totalLocked == Σ taskBalance[i] + Σ channel[i].locked
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
///      equivalence of the Solidity and Rust encodings is directly auditable. `ERC-1271` is
///      supported in `redeem` so an EOA streamer (a buyer running their own epoch loop) works
///      through exactly the same code path.
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

    string public constant name = "CipherMeshPaymentVault";
    string public constant version = "1";

    IERC20 public immutable token;
    bytes32 public immutable domainSeparator;

    address public owner;
    address public taskManager; // CipherTask.sol — the only address allowed to move escrow

    uint256 public channelNonce;
    mapping(uint256 => Channel) public channels;
    mapping(address => uint256) public pendingWithdrawal;

    /// @notice Escrow funded for, and still owned by, a task.
    mapping(uint256 => uint256) public taskBalance;
    /// @notice Sum of funds ever locked into channels of a task (for audit/reporting).
    mapping(uint256 => uint256) public taskChannelLocked;
    /// @notice Channel ids opened per task, for reclamation.
    mapping(uint256 => uint256[]) public taskChannels;

    uint256 public totalLocked; // = subBalancesTotal + channelLocksTotal
    uint256 public subBalancesTotal; // Σ taskBalance
    uint256 public channelLocksTotal; // Σ open (maxCumulative - withdrawn)
    uint256 public totalWithdrawn;
    uint256 public totalReturned;

    error InvalidSignature();
    error NotStreamer(address caller);
    error NotNode(address caller, uint256 channelId);
    error NotOwner(address caller);
    error NotTaskManager(address caller);
    error SliceNotMonotonic(uint256 channelId, uint256 provided, uint256 consumed);
    error ExceedsCap(uint256 channelId, uint256 amount, uint256 cap);
    error InsufficientTaskBalance(uint256 taskId, uint256 available, uint256 required);
    error ChannelClosed(uint256 channelId);
    error TooEarly(uint256 channelId, uint64 unlockAt);
    error DeadlineExpired(uint256 deadline);
    error NothingToClaim(address account);
    error ChannelNotInTask(uint256 channelId, uint256 taskId);
    error ZeroAmount();
    error ZeroAddress();
    error UnsafeSignatureS();
    error TransferFailed(address token, address to, uint256 amount);
    error InvariantViolated(uint256 totalLocked, uint256 accounted);

    event TaskFunded(uint256 indexed taskId, address indexed from, uint256 amount, uint256 newBalance);
    event TaskRefunded(uint256 indexed taskId, address indexed to, uint256 amount);
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
    event OwnershipTransferred(address indexed from, address indexed to);

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
    }

    /* ------------------------------------------------------------------ */
    /*                              governance                             */
    /* ------------------------------------------------------------------ */

    function transferOwnership(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, to);
        owner = to;
    }

    /// @notice Grant escrow-management rights to the orchestrator. Timelock in production.
    function setTaskManager(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        emit TaskManagerChanged(taskManager, to);
        taskManager = to;
    }

    function setPaused(bool v) external onlyOwner {
        _setPaused(v);
    }

    /* ================================================================== */
    /*                        ORCHESTRATOR: ESCROW IN                     */
    /* ================================================================== */

    /// @notice Fund the sub-balance of `taskId` by pulling `amount` from `from`.
    function fundTask(uint256 taskId, uint256 amount, address from) external onlyTaskManager whenNotPaused nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (from == address(0)) revert ZeroAddress();
        _pull(from, amount);
        taskBalance[taskId] += amount;
        subBalancesTotal += amount;
        totalLocked += amount;
        emit TaskFunded(taskId, from, amount, taskBalance[taskId]);
    }

    /// @notice Move `amount` from a task's sub-balance into `account`'s pending balance.
    function creditFromTask(uint256 taskId, address account, uint256 amount) external onlyTaskManager whenNotPaused nonReentrant {
        if (amount == 0) revert ZeroAmount();
        _debitTask(taskId, amount);
        pendingWithdrawal[account] += amount;
        _assertInvariant();
        emit WithdrawalCredited(account, amount, taskId);
    }

    /// @notice Return `amount` of a task's sub-balance to `to` (refund on abort).
    function refundFromTask(uint256 taskId, address to, uint256 amount) external onlyTaskManager whenNotPaused nonReentrant {
        if (amount == 0) return;
        _debitTask(taskId, amount);
        _push(to, amount);
        _assertInvariant();
        emit TaskRefunded(taskId, to, amount);
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

    /// @notice Close a channel of `taskId` and return the unconsumed lock to the sub-balance.
    function closeTaskChannel(uint256 taskId, uint256 channelId) external onlyTaskManager whenNotPaused nonReentrant returns (uint128 amount) {
        Channel storage ch = channels[channelId];
        if (ch.taskId != taskId) revert ChannelNotInTask(channelId, taskId);
        if (ch.streamer != msg.sender) revert NotStreamer(msg.sender);
        if (ch.closed) revert ChannelClosed(channelId);

        ch.closed = true;
        amount = ch.maxCumulative - ch.withdrawn;
        unchecked {
            uint128 freed = ch.maxCumulative;
            taskBalance[taskId] += amount;
            subBalancesTotal += amount;
            taskChannelLocked[taskId] -= freed;
            channelLocksTotal -= freed;
        }
        // `totalLocked` unchanged: channel lock -> sub-balance
        _assertInvariant();
        emit ChannelClosedByStreamer(channelId, amount, taskId);
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
            channelLocksTotal -= freed;
            if (amount == 0) continue;
            taskBalance[taskId] += amount;
            subBalancesTotal += amount;
            recovered += amount;
        }
        _assertInvariant();
    }

    /// @notice Close every open channel of a task and refund the recovered total to `to`.
    /// @dev The natural end-of-task call: any node that did not redeem its slices gets the
    ///      money back, so an unresponsive node cannot strand the buyer's budget.
    /// @dev As in `sweepTaskChannels`, channels that are still inside their reward window are
    ///      left open rather than reclaimed.
    function unwindTask(uint256 taskId, address to) external onlyTaskManager whenNotPaused nonReentrant returns (uint128 recovered) {
        uint256[] memory ids = taskChannels[taskId];
        for (uint256 i = 0; i < ids.length; ++i) {
            Channel storage ch = channels[ids[i]];
            if (ch.closed) continue;
            if (ch.unlockAt > block.timestamp) continue; // still claimable
            ch.closed = true;
            uint128 amount = ch.maxCumulative - ch.withdrawn;
            uint128 freed = ch.maxCumulative;
            if (amount == 0) {
                taskChannelLocked[taskId] -= freed;
                channelLocksTotal -= freed;
                continue;
            }
            taskBalance[taskId] += amount;
            subBalancesTotal += amount;
            taskChannelLocked[taskId] -= freed;
            channelLocksTotal -= freed;
            recovered += amount;
        }
        if (recovered > 0) {
            uint256 bal = taskBalance[taskId];
            if (bal < recovered) revert InsufficientTaskBalance(taskId, bal, recovered);
            unchecked {
                taskBalance[taskId] = bal - recovered;
                subBalancesTotal -= recovered;
            }
            totalLocked -= recovered; // funds leave the vault
            _push(to, recovered);
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

        Channel storage ch = channels[channelId];
        if (ch.node == address(0) || ch.node != msg.sender) revert NotNode(msg.sender, channelId);
            if (ch.closed) revert ChannelClosed(channelId);
            // `consumed` holds the *next* expected slice index, so the first slice (index 0) is
            // redeemable. Comparing with `<=` against a "highest index used" counter would lock
            // out slice 0 forever, because the counter starts at 0.
            if (sliceIndex < ch.consumed) revert SliceNotMonotonic(channelId, sliceIndex, ch.consumed);
            if (amount > ch.maxCumulative) revert ExceedsCap(channelId, amount, ch.maxCumulative);
            if (amount <= ch.withdrawn) {
                // Nothing new to pay. Still consume the index so a later, larger slice remains
                // redeemable and the signature cannot be replayed for a different amount.
                ch.consumed = uint64(sliceIndex) + 1;
                return 0;
            }

            bytes32 structHash =
                keccak256(abi.encode(REDEEM_TYPEHASH, channelId, ch.streamer, ch.node, ch.maxCumulative, ch.unlockAt, deadline));
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
            if (!_authorize(digest, signature, ch.streamer)) revert InvalidSignature();

            ch.consumed = uint64(sliceIndex) + 1;
        paid = amount - ch.withdrawn;
        ch.withdrawn = amount;

        totalLocked -= paid;
        channelLocksTotal -= paid;
        totalWithdrawn += paid;
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
        taskBalance[ch.taskId] += amount;
        subBalancesTotal += amount;
        taskChannelLocked[ch.taskId] -= freed;
        channelLocksTotal -= freed;
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
        channelLocksTotal -= freed;
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
        _push(msg.sender, amount);
        emit WithdrawalClaimed(msg.sender, amount);
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

    /// @notice `totalLocked` must always equal sub-balances plus open channel locks.
    function accountedLocked() public view returns (uint256) {
        return subBalancesTotal + channelLocksTotal;
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

    function _pull(address from, uint256 amount) private {
        // Defensive against non-standard tokens (USDT returns no data on success).
        (bool ok, bytes memory ret) = address(token).call(abi.encodeCall(IERC20.transferFrom, (from, address(this), amount)));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed(address(token), from, amount);
    }

    function _push(address to, uint256 amount) private {
        if (amount == 0) return;
        (bool ok, bytes memory ret) = address(token).call(abi.encodeCall(IERC20.transfer, (to, amount)));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed(address(token), to, amount);
    }

    /// @dev O(1): `channelLocksTotal` is maintained incrementally on every channel movement,
    ///      and `subBalancesTotal` on every sub-balance movement, so
    ///      `totalLocked == subBalancesTotal + channelLocksTotal` is checkable in constant
    ///      time. This is the tripwire that catches an accounting bug before it becomes a
    ///      drainable one; it is cheap enough to sit on the orchestrator hot path.
    function _assertInvariant() private view {
        if (totalLocked != subBalancesTotal + channelLocksTotal) {
            revert InvariantViolated(totalLocked, subBalancesTotal + channelLocksTotal);
        }
    }
}
