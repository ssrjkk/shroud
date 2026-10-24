// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICipherTask} from "../interfaces/ICipherTask.sol";

/// @title TaskParamsLib
/// @notice Bounds on `TaskParams`, checked once at `createTask`.
/// @dev This is an *external* library on purpose. The checks are pure, but they sit on the path
///      every task takes, and their revert data is the largest single contributor to
///      `CipherTask`'s deployed size. Linking them out keeps `CipherTask` inside the 24 576-byte
///      code size limit that `createTask` has been creeping past, and a pure library has no
///      state to compromise. `CipherTask` re-exports the bounds as public constants, so the ABI
///      an SDK reads is unchanged.
library TaskParamsLib {
    uint32 public constant MAX_EPOCHS = 365;
    uint32 public constant MAX_CONTRIBUTORS = 5_000;
    uint32 public constant MAX_FEATURES = 512;
    uint32 public constant MAX_ROWS_PER_SHARD = 100_000;
    uint32 public constant MAX_CONTRIBUTION_WINDOW = 30 days;
    uint32 public constant MAX_EPOCH_DURATION = 1 days;
    uint32 public constant MAX_DISPUTE_WINDOW = 1 hours;
    uint16 public constant BPS = 10_000;

    /// @dev Upper bound on the dispute bounty: past half the node pool a claimant can be made
    ///      worse off than the reward the epoch pays, which turns reporting into harassment.
    uint16 public constant MAX_REEXECUTION_BPS = 5_000;

    /// @notice Reject a parameter set the protocol cannot settle or prove against.
    /// @dev `updateManager` is deliberately not checked: a zero manager means "the buyer", which
    ///      `createTask` substitutes. A non-zero requirement here would be unreachable.
    function validate(ICipherTask.TaskParams calldata p) external pure {
        if (p.epochs == 0 || p.epochs > MAX_EPOCHS) revert ICipherTask.EpochCountInvalid();
        if (p.minContributors == 0 || p.maxContributors < p.minContributors) {
            revert ICipherTask.ContributorBoundsInvalid();
        }
        if (p.maxContributors > MAX_CONTRIBUTORS) revert ICipherTask.ContributorCapExceeded();
        if (p.minRowsPerShard == 0 || p.minRowsPerShard > MAX_ROWS_PER_SHARD) {
            revert ICipherTask.RowsPerShardInvalid();
        }
        if (p.features == 0 || p.features > MAX_FEATURES) revert ICipherTask.FeatureCountInvalid();
        if (p.labelBits != 8 && p.labelBits != 16) revert ICipherTask.LabelBitsInvalid();
        if (p.contributionWindow < 1 hours || p.contributionWindow > MAX_CONTRIBUTION_WINDOW) {
            revert ICipherTask.ContributionWindowInvalid();
        }
        if (p.epochDuration < 5 minutes || p.epochDuration > MAX_EPOCH_DURATION) {
            revert ICipherTask.EpochDurationInvalid();
        }
        if (p.disputeWindow < 1 minutes || p.disputeWindow > MAX_DISPUTE_WINDOW) {
            revert ICipherTask.DisputeWindowInvalid();
        }
        if (p.reexecutionBps > MAX_REEXECUTION_BPS) revert ICipherTask.ReexecutionBpsInvalid();
        if (p.modelSpecCid == bytes32(0)) revert ICipherTask.ModelSpecMissing();
        if (p.shapeRoot == bytes32(0)) revert ICipherTask.ShapeRootMissing();
    }

    /// @notice On-chain hyperparams per epoch (M5). `scale == 0` = unset (legacy).
    struct EpochHyper {
        uint32 scale;
        uint32 lrQ16;
        uint32 l2Q16;
        uint32 minibatch;
        uint64 seed;
    }

    /// @notice Pin consensus hyperparams for `epoch` (external so the host stays small).
    function pinHyper(
        ICipherTask.Task storage t,
        mapping(uint256 => mapping(uint32 => EpochHyper)) storage h,
        uint256 taskId,
        address caller,
        uint32 epoch,
        uint32 scale,
        uint32 lrQ16,
        uint32 l2Q16,
        uint32 minibatch,
        uint64 seed
    ) external {
        if (caller != t.params.buyer && caller != t.params.updateManager) {
            revert ICipherTask.NotUpdateManagerOrOwner(taskId, caller);
        }
        if (epoch != t.nextEpoch) revert ICipherTask.EpochOutOfOrder(taskId, epoch);
        if (scale == 0 || minibatch == 0 || lrQ16 == 0) {
            revert ICipherTask.InvalidTaskStatus(taskId, t.status, ICipherTask.TaskStatus.EpochOpen);
        }
        h[taskId][epoch] = EpochHyper(scale, lrQ16, l2Q16, minibatch, seed);
    }

    /// @notice The three payout legs must partition the budget exactly.
    /// @dev `external`, not `internal`: the compiler inlines an internal library call into the
    ///      caller, which would leave the bytecode exactly where it was. Measured on this pair, an
    ///      inlined `validate` cost 2 747 bytes inside `CipherTask` against 286 bytes for the
    ///      `DELEGATECALL` site, with the 2 742-byte body sitting in the library instead.
    function requireShares(uint16 user, uint16 node, uint16 committee) external pure {
        if (user == 0) revert ICipherTask.InvalidShares(user, node, committee);
        if (uint256(user) + uint256(node) + uint256(committee) != BPS) {
            revert ICipherTask.InvalidShares(user, node, committee);
        }
    }

    /// @notice Initialise a fresh `Task` slot (external so the host stays small).
    /// @dev The 11-field struct assignment is ~200 bytes inline; a DELEGATECALL site is
    ///      ~30 bytes with the body in the library. `pm` already has updateManager
    ///      substituted by the caller.
    function initTask(
        ICipherTask.Task storage t,
        ICipherTask.TaskParams memory pm,
        uint128 escrowed,
        bytes32 emptyRoot
    ) external {
        t.params = pm;
        t.budget = escrowed;
        t.locked = 0;
        t.createdAt = uint64(block.timestamp);
        t.windowEnd = uint64(block.timestamp) + pm.contributionWindow;
        t.sealAt = 0;
        t.epochDeadline = 0;
        t.contributors = 0;
        t.shards = 0;
        t.nextEpoch = 0;
        t.ctRoot = emptyRoot;
        t.lastWeightsCid = bytes32(0);
        t.lastWeightsDigest = bytes32(0);
        t.status = ICipherTask.TaskStatus.Opening;
        t.isSealed = false;
    }
}
