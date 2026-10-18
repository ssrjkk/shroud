// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICipherTask} from "../interfaces/ICipherTask.sol";
import {PaymentVault} from "../payments/PaymentVault.sol";
import {Dividend} from "./Dividend.sol";
import {TaskParamsLib} from "./TaskParamsLib.sol";

/// @title SettlementLib
/// @notice The paged distribution of a task's escrow: contributor pro-rata, dust, committee, the
///         buyer refund, and the early reclaim of the node pool for epochs that never run.
///
/// @dev ## Why this is a linked library and not a section of `CipherTask`
///
///      `CipherTask` has to fit inside the 24,576-byte deployment limit, and escrow distribution is
///      its largest self-contained subtree. Moving code out only helps when the callee is
///      `external`: `viaIR` inlines `internal` library functions into the caller, so an internal
///      extraction is byte-neutral. Measured with this repository's own toolchain, a 60-check body
///      costs 2,747 bytes inlined and leaves the caller at 286 bytes when it lives in an `external`
///      library.
///
///      `external` library functions compile to `DELEGATECALL`, so the code here runs *as*
///      `CipherTask`: `address(this)` is the orchestrator, which is what `PaymentVault`'s
///      `onlyTaskManager` check requires, storage writes land in the host's slots through the
///      pointers it passes, and the events below are emitted from the host's address. Nothing here
///      holds funds or authority of its own.
///
/// @dev ## The paging invariant this must preserve
///
///      `userPool` is frozen by the first page (`started` and `userPool` in `State`) and never
///      recomputed, because the `available` clamp depends on a balance that *shrinks* as pages pay
///      contributors. Recomputing per page would make amounts page-dependent and the drift would
///      land on whoever happened to sit in a later page. Per-contributor amounts therefore come from
///      `t.budget`, the frozen pool and the weights recorded at submission, so any caller can execute
///      a page and every caller computes the same numbers.
library SettlementLib {
    /// @notice Maximum number of reporters that can be paid in one batch.
    /// @dev Prevents a Gas DoS attack where a task with thousands of reporters causes the
    ///      `payReporters` loop to exceed the block gas limit and lock the task. DISPUTE_QUORUM
    ///      is 3, so 64 is a generous headroom above any legitimate quorum.
    uint256 internal constant MAX_REPORTERS = 64;

    /// @notice Settlement progress for one task. Every field is keyed by `taskId`.
    /// @dev The host declares exactly one member of this type, so the slot block the library
    ///      reaches through the storage pointer is the block the host actually owns.
    struct State {
        mapping(uint256 => bool) settled; // a page has run
        mapping(uint256 => bool) started; // the first page froze the pool
        mapping(uint256 => uint256) cursor; // first contributor not yet paid
        mapping(uint256 => uint256) distributed; // credited so far, for the dust leg
        mapping(uint256 => address) dustRecipient; // deterministic highest-address sink
        mapping(uint256 => uint128) userPool; // frozen by the first page
    }

    struct Outcome {
        bool finished; // the last page ran, so the host may mark the task settled
        uint128 userPool;
        uint128 committeePool;
        uint128 refunded; // what went back to the buyer
    }

    // Redeclared from `CipherTask` so the library can emit them. A delegatecall'd library logs from
    // the host's address and the topic and encoding are identical, so clients decoding through the
    // orchestrator's ABI see exactly the events they saw before the extraction.
    event Withdrawn(uint256 indexed taskId, address indexed who, uint128 amount);
    event SettleProgress(uint256 indexed taskId, uint256 paidUpTo, uint256 total);
    event EscrowSettled(uint256 indexed taskId, uint128 contributorsPool, uint128 committeePool, uint128 refunded);
    event NodeRewardChannelOpened(
        uint256 indexed taskId,
        uint32 indexed epoch,
        address indexed node,
        uint256 channelId,
        uint128 maxCumulative,
        uint64 unlockAt,
        uint128 firstSlice
    );

    /// @notice Pay contributor pages `[cursor, cursor + PAGE_SIZE)` and, on the last page, the dust,
    ///         committee and buyer legs.
    /// @param vault the escrow vault holding the task sub-balance
    /// @param t the task, by storage pointer
    /// @param contributors the task's contributor list, in submission order
    /// @param contributions the task's contributions, keyed by address
    /// @param totalWeight the task's active total weight in Q16.16: frozen once
    ///        settlement starts (slashes are forbidden after that point), already net
    ///        of any pre-settlement slashes, so honest shares are never diluted by
    ///        forfeited weight.
    /// @param s the host's settlement state
    /// @param treasury the committee leg's recipient; the host's own treasury, passed rather than
    ///        read, because this library has no storage of its own
    /// @param pageSize contributors paid by one page, owned by the host (`CipherTask`'s
    ///        `SETTLE_PAGE_SIZE`) so the bound has exactly one definition
    /// @dev The guards that decide *whether* a page may run (terminal status, epoch lock, epochs
    ///      remaining, cursor match) stay with the host: they are the task's state machine talking,
    ///      and this function is only correct when called from inside them.
    function payPage(
        PaymentVault vault,
        uint256 taskId,
        ICipherTask.Task storage t,
        address[] storage contributors,
        mapping(address => ICipherTask.Contribution) storage contributions,
        mapping(uint256 => uint256) storage totalWeight,
        State storage s,
        address treasury,
        uint256 pageSize
    ) external returns (Outcome memory out) {
        // Return every un-redeemed reward lock to the sub-balance first, so the split below is
        // computed against the vault's real balance rather than an assumption. Idempotent, so
        // repeated pages are safe.
        vault.sweepTaskChannels(taskId);
        uint256 available = vault.taskBalance(taskId);

        uint128 committeePool = (t.budget * t.params.committeeShareBps) / TaskParamsLib.BPS;
        uint128 userPool;
        if (s.started[taskId]) {
            userPool = s.userPool[taskId];
        } else {
            userPool = (t.budget * t.params.userShareBps) / TaskParamsLib.BPS;
            if (userPool > available) userPool = uint128(available);
            s.userPool[taskId] = userPool;
            s.started[taskId] = true;
        }

        uint256 weight = totalWeight[taskId];
        uint256 start = s.cursor[taskId];
        uint256 count = contributors.length;
        uint256 end = start + pageSize;
        if (end < start || end > count) end = count;
        uint256 distributed = s.distributed[taskId];
        address dustRecipient = s.dustRecipient[taskId];

        for (uint256 i = start; i < end; ++i) {
            address a = contributors[i];
            ICipherTask.Contribution memory c = contributions[a];
            if (!c.accepted || c.slashed) continue;
            uint128 amount = Dividend.shareOf(userPool, c.weightQ16, weight);
            if (amount > 0) {
                distributed += amount;
                vault.creditFromTask(taskId, a, amount);
                emit Withdrawn(taskId, a, amount);
            }
            if (a > dustRecipient) dustRecipient = a; // deterministic dust sink
        }

        s.distributed[taskId] = distributed;
        s.dustRecipient[taskId] = dustRecipient;
        s.cursor[taskId] = end;

        // Not the last page: record progress and stop. The legs below are computed against the whole
        // pool being distributed, so they must not run yet.
        if (end < count) {
            emit SettleProgress(taskId, end, count);
            return Outcome(false, userPool, committeePool, 0);
        }

        // Final page: every reward channel must have matured (redeemed, reclaimed, or swept
        // above). Paying the committee/buyer legs against an incomplete balance permanently
        // shorts them — the task is terminal after this call, so no later call can top them
        // up (threat model F-22). Contributor pages are unaffected and may run at any time:
        // their shares come from the frozen pool, which node locks can never eat into.
        // If this reverts, wait out the reward window and call again; settlement is
        // permissionless, so anyone can finish it.
        if (vault.hasImmatureChannels(taskId)) revert ICipherTask.ChannelsImmature(taskId);
        s.settled[taskId] = true;

        uint128 dust = userPool > uint128(distributed) ? uint128(userPool) - uint128(distributed) : 0;
        if (dust > 0 && dustRecipient != address(0)) {
            vault.creditFromTask(taskId, dustRecipient, dust);
            emit Withdrawn(taskId, dustRecipient, dust);
        }

        // Report what was actually paid, not the nominal pool: indexers reading
        // `EscrowSettled` must see the capped leg, not a promise the balance
        // could not keep.
        uint128 committeePaid = 0;
        if (committeePool > 0) {
            uint256 left = vault.taskBalance(taskId);
            committeePaid = committeePool > left ? uint128(left) : committeePool;
            if (committeePaid > 0) {
                vault.creditFromTask(taskId, treasury, committeePaid);
                emit Withdrawn(taskId, treasury, committeePaid);
            }
        }

        // Everything still in the sub-balance (the node pool for unopened or disputed epochs, plus
        // integer-division dust) goes back to the buyer.
        uint256 finalBalance = vault.taskBalance(taskId);
        if (finalBalance > 0) {
            vault.creditFromTask(taskId, t.params.buyer, finalBalance);
            emit Withdrawn(taskId, t.params.buyer, uint128(finalBalance));
        }

        emit EscrowSettled(taskId, userPool, committeePaid, uint128(finalBalance));
        return Outcome(true, userPool, committeePaid, uint128(finalBalance));
    }

    /// @notice Pay the nodes that re-executed and disagreed with the claimed digest.
    ///
    ///      The docstring on `finalizeEpoch` promises reporters are paid out of the disputed
    ///      lock; without this they would spend real gas and re-execution compute for nothing,
    ///      and the only rational strategy would be to accept every claim unchallenged. The
    ///      bounty is `reexecutionBps` of the lock split equally, with the division remainder to
    ///      the first reporter so the whole bounty is always paid out and nothing is stranded in
    ///      the sub-balance. The remainder of the lock is *not* paid here: it stays in the task
    ///      sub-balance and is refunded to the buyer at settlement.
    ///
    /// @dev Lives here rather than in the host for the same reason `payPage` does: the host
    ///      contract must stay inside the 24,576-byte deployment limit, and only `external`
    ///      library calls move bytes out. The bounty channels must not overwrite the epoch's
    ///      headline channel (`_epochChannel` stays the winner's own): reporter channels are
    ///      opened without recording them, exactly as the host's `_openChannel` does for the
    ///      abort-retention path. The guards deciding *whether* a quorum was reached stay with
    ///      the host in `finalizeEpoch`.
    function payReporters(
        PaymentVault vault,
        uint256 taskId,
        uint32 epoch,
        address[] storage reporters,
        uint16 reexecutionBps,
        uint128 lock,
        uint64 unlockAt,
        mapping(uint256 => mapping(uint256 => uint128)) storage authorizedSlice
    ) external {
        uint256 n = reporters.length;
        if (n == 0 || lock == 0) return;
        // Cap to MAX_REPORTERS: a task with thousands of reporters would otherwise cause this
        // loop to exceed the block gas limit and lock the task permanently. DISPUTE_QUORUM is 3,
        // so 64 is generous headroom. Excess reporters beyond the cap receive nothing — this is
        // safe because the bounty is tiny relative to the gas cost of collecting it.
        if (n > MAX_REPORTERS) n = MAX_REPORTERS;
        uint128 bounty = (uint128(lock) * reexecutionBps) / TaskParamsLib.BPS;
        if (bounty == 0) return;
        uint128 each = bounty / uint128(n);
        if (each == 0) return;
        uint128 total = each * uint128(n);
        for (uint256 i = 0; i < n; ++i) {
            openReporterChannel(vault, taskId, epoch, reporters[i], each, unlockAt, authorizedSlice);
        }
        if (total < bounty) {
            openReporterChannel(vault, taskId, epoch, reporters[0], bounty - total, unlockAt, authorizedSlice);
        }
    }

    /// @dev Reporter channels mirror the host's `_openChannel` without the headline write: the
    ///      vault call, the slice authorisation and the event are identical, only the
    ///      `_epochChannel` slot (the winner's) is left alone.
    function openReporterChannel(
        PaymentVault vault,
        uint256 taskId,
        uint32 epoch,
        address node,
        uint128 reward,
        uint64 unlockAt,
        mapping(uint256 => mapping(uint256 => uint128)) storage authorizedSlice
    ) private {
        if (reward == 0) return;
        uint256 channelId = vault.openTaskChannel(taskId, node, reward, unlockAt);
        authorizedSlice[channelId][0] = reward;
        emit NodeRewardChannelOpened(taskId, epoch, node, channelId, reward, unlockAt, reward);
    }

    /// @notice Credit the buyer the escrow belonging to epochs that will never run.
    /// @dev The same reservation rule `payPage`'s last page uses: the contributor and committee
    ///      pools are reserved for settlement, so reclaim can only ever touch the node pool of the
    ///      epochs that remain unrun. Living next to `payPage` is what keeps those two definitions
    ///      of "reserved" from drifting apart.
    /// @dev The guards deciding *whether* a reclaim may run (caller is the buyer, no live epoch
    ///      lock, every epoch accounted for, settlement not begun) stay with the host.
    function reclaim(PaymentVault vault, uint256 taskId, ICipherTask.Task storage t) external returns (uint128 amount) {
        // Un-redeemed reward locks return to the sub-balance before the refund is computed.
        vault.sweepTaskChannels(taskId);

        uint256 available = vault.taskBalance(taskId);
        if (available == 0) return 0;

        uint128 userPool = (t.budget * t.params.userShareBps) / TaskParamsLib.BPS;
        uint128 committeePool = (t.budget * t.params.committeeShareBps) / TaskParamsLib.BPS;
        uint256 reserved = uint256(userPool) + uint256(committeePool);
        if (available <= reserved) return 0;

        amount = uint128(available - reserved);
        // Pull-based, consistent with `payPage` and `abort`.
        vault.creditFromTask(taskId, t.params.buyer, amount);
        emit Withdrawn(taskId, t.params.buyer, amount);
    }
}
