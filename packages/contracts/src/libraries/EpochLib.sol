// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICipherTask} from "../interfaces/ICipherTask.sol";
import {IProofVerifier} from "../zk/ProofVerifier.sol";
import {PaymentVault} from "../payments/PaymentVault.sol";
import {Dividend} from "./Dividend.sol";
import {TaskParamsLib} from "./TaskParamsLib.sol";
import {BondLib} from "./BondLib.sol";
import {SettlementLib} from "./SettlementLib.sol";
import {IERC20} from "../interfaces/IERC20.sol";

/// @title RewardLib
/// @notice Reward-channel opening for `CipherTask` (external so the host stays small).
/// @dev Runs by DELEGATECALL as the host. The contract is the streamer, so the node redeems
///      without any off-chain signer; the authorised slice blob is what `isValidSignature`
///      (ERC-1271) checks in the vault.
library RewardLib {
    event NodeRewardChannelOpened(
        uint256 indexed taskId,
        uint32 indexed epoch,
        address indexed node,
        uint256 channelId,
        uint128 maxCumulative,
        uint64 unlockAt,
        uint128 firstSlice
    );

    /// @notice Open the winner's headline channel for `epoch` (records `_epochChannel`).
    function payNode(
        PaymentVault vault,
        mapping(uint256 => mapping(uint32 => uint256)) storage epochChannel,
        mapping(uint256 => mapping(uint256 => uint128)) storage authorizedSlice,
        uint64 window,
        uint256 taskId,
        uint32 epoch,
        address node,
        uint128 reward
    ) external {
        uint256 channelId = openChannel(vault, authorizedSlice, window, taskId, epoch, node, reward);
        if (channelId != 0) epochChannel[taskId][epoch] = channelId;
    }

    /// @dev Open a reward channel without recording it as the epoch's headline channel. Used
    ///      for reporter bounties and abort retention, which must not overwrite the winner's
    ///      slot that indexers read.
    function openChannel(
        PaymentVault vault,
        mapping(uint256 => mapping(uint256 => uint128)) storage authorizedSlice,
        uint64 window,
        uint256 taskId,
        uint32 epoch,
        address node,
        uint128 reward
    ) public returns (uint256 channelId) {
        if (reward == 0) return 0;
        uint64 unlockAt = uint64(block.timestamp) + window;
        channelId = vault.openTaskChannel(taskId, node, reward, unlockAt);
        authorizedSlice[channelId][0] = reward;
        emit NodeRewardChannelOpened(taskId, epoch, node, channelId, reward, unlockAt, reward);
    }

    function epochLock(ICipherTask.Task storage t) external view returns (uint128) {
        uint128 pool = (t.budget * t.params.nodeShareBps) / TaskParamsLib.BPS;
        return pool / t.params.epochs;
    }
}

/// @title CommitLib
/// @notice Epoch commit verification + winner recording (external so the host stays small).
/// @dev The proof is a 32-byte *reference*, never the proof itself: a single-segment STARK is
///      far larger than 32 bytes, and a segmented proof is summarised by its Merkle root. The
///      verifier behind `proofVerifier` resolves which it is.
library CommitLib {
    event EpochCommitted(uint256 indexed taskId, uint32 indexed epoch, address indexed node, bytes32 traceDigest);
    event EpochVerified(uint256 indexed taskId, uint32 indexed epoch, address indexed node, bool ok);
    event TaskStatusChanged(uint256 indexed taskId, ICipherTask.TaskStatus from, ICipherTask.TaskStatus to);

    bytes4 private constant _REASON_STARK_REJECTED = 0x73746172; // "star"

    function commit(
        ICipherTask.Task storage t,
        mapping(uint256 => mapping(uint32 => mapping(address => ICipherTask.EpochCommit))) storage commits,
        mapping(uint256 => mapping(uint32 => address)) storage winners,
        mapping(uint256 => mapping(uint32 => bytes32)) storage claimed,
        mapping(uint256 => mapping(address => bool)) storage registered,
        IProofVerifier proofVerifier,
        bytes32 ctRoot,
        bytes32 lastWeightsDigest,
        uint256 taskId,
        uint32 epoch,
        address node,
        bytes32 proof,
        bytes32 encWeightsCid,
        bytes32 weightsDigest,
        bytes32 metricsCid,
        bytes32 traceDigest,
        bool segmented
    ) external {
        if (t.status != ICipherTask.TaskStatus.EpochOpen && t.status != ICipherTask.TaskStatus.EpochCommitting) {
            revert ICipherTask.InvalidTaskStatus(taskId, t.status, ICipherTask.TaskStatus.EpochOpen);
        }
        if (!registered[taskId][node]) revert ICipherTask.NodeNotRegistered(taskId, node);
        if (epoch != t.nextEpoch) revert ICipherTask.EpochOutOfOrder(taskId, epoch);
        if (block.timestamp > t.epochDeadline) revert ICipherTask.CommitWindowExpired(taskId, t.epochDeadline);
        if (encWeightsCid == bytes32(0) || weightsDigest == bytes32(0) || traceDigest == bytes32(0)) {
            revert ICipherTask.WeightPinMismatch(taskId, weightsDigest, encWeightsCid);
        }
        ICipherTask.EpochCommit storage c = commits[taskId][epoch][node];
        if (c.committedAt != 0) revert ICipherTask.DuplicateCommit(taskId, epoch, node);
        if (proof == bytes32(0)) revert ICipherTask.ProofReferenceMissing(taskId, epoch, node);

        bytes32 transcript = keccak256(
            abi.encode(
                "SHROUD/PoC/v1",
                block.chainid,
                address(this),
                taskId,
                epoch,
                ctRoot,
                lastWeightsDigest,
                traceDigest,
                node // H2 fix: bind STARK to the node so a proof cannot be replayed under a different address
            )
        );
        bytes memory publicInput =
            abi.encode(transcript, epoch, t.shards, traceDigest, ctRoot, lastWeightsDigest, block.chainid);

        bool ok = segmented
            ? proofVerifier.verifyProofSegmented(publicInput, abi.encodePacked(proof))
            : proofVerifier.verifyProof(publicInput, abi.encodePacked(proof));
        emit EpochVerified(taskId, epoch, node, ok);
        if (!ok) revert ICipherTask.ProofRejected(taskId, epoch, _REASON_STARK_REJECTED);

        c.proof = proof;
        c.encWeightsCid = encWeightsCid;
        c.weightsDigest = weightsDigest;
        c.metricsCid = metricsCid;
        c.traceDigest = traceDigest;
        c.committedAt = uint64(block.timestamp);
        c.revealNonce = 1;
        c.verified = true;

        // First verified commit takes the winner seat and keeps it: ties resolve by commit
        // order, not by address. H2 fix: the transcript above now binds `node`, so a proof
        // seen in the mempool cannot be replayed from a different address — the replay's
        // public input differs and a real verifier rejects it. Front-running the first commit
        // would require predicting its trace digest, which the reporter cannot know before
        // it is published; disagreements go through disputes.
        address incumbent = winners[taskId][epoch];
        if (incumbent == address(0)) {
            winners[taskId][epoch] = node;
            claimed[taskId][epoch] = traceDigest;
        }

        if (t.status != ICipherTask.TaskStatus.EpochCommitting) {
            emit TaskStatusChanged(taskId, t.status, ICipherTask.TaskStatus.EpochCommitting);
            t.status = ICipherTask.TaskStatus.EpochCommitting;
        }
        emit EpochCommitted(taskId, epoch, node, traceDigest);
    }
}

/// @title ContributeLib
/// @notice Contribution intake for `CipherTask` (external so the host stays small).
library ContributeLib {
    event ContributionSubmitted(
        uint256 indexed taskId, address indexed contributor, uint32 indexed leafIndex, bytes32 ciphertextCid, uint32 rows
    );
    event TaskStatusChanged(uint256 indexed taskId, ICipherTask.TaskStatus from, ICipherTask.TaskStatus to);

    /// @dev All `submitContribution` checks + writes. The host only routes here.
    function submit(
        BondLib.State storage bonds,
        ICipherTask.Task storage t,
        mapping(address => ICipherTask.Contribution) storage contributions,
        mapping(uint256 => address) storage byLeaf,
        mapping(bytes32 => bool) storage shardSeen,
        address[] storage contributorList,
        mapping(uint256 => uint256) storage totalWeight,
        IERC20 token,
        uint256 taskId,
        address contributor,
        bytes32 ciphertextCid,
        bytes32 ctDigest,
        bytes calldata shapeProof,
        bool shapeProofsRequired,
        bytes32 rowCommitment,
        uint32 rows,
        uint32 maxRowsPerShard
    ) external {
        if (t.status != ICipherTask.TaskStatus.Opening && t.status != ICipherTask.TaskStatus.Collecting) {
            revert ICipherTask.InvalidTaskStatus(taskId, t.status, ICipherTask.TaskStatus.Collecting);
        }
        if (block.timestamp > t.windowEnd) revert ICipherTask.ContributionWindowClosed(taskId);
        if (contributions[contributor].accepted) revert ICipherTask.AlreadyContributed(taskId, contributor);
        if (ciphertextCid == bytes32(0) || ctDigest == bytes32(0)) revert ICipherTask.ZeroContribution();
        if (shardSeen[ciphertextCid]) revert ICipherTask.DuplicateShard(taskId, ciphertextCid);
        if (rows < t.params.minRowsPerShard) revert ICipherTask.ShardTooSmall(rows, t.params.minRowsPerShard);
        if (rows > maxRowsPerShard) revert ICipherTask.ShardTooLarge(rows, maxRowsPerShard);
        if (t.contributors >= t.params.maxContributors) revert ICipherTask.CapReached(taskId, t.params.maxContributors);
        bytes32 shapeProofDigest = keccak256(shapeProof);
        if (shapeProofsRequired && shapeProof.length == 0) revert ICipherTask.ShapeProofInvalid(taskId, contributor);
        if (rowCommitment == bytes32(0)) revert ICipherTask.RowCommitmentInvalid(taskId, contributor);

        uint32 leafIndex = t.shards;
        // H2: secure mode ignores self-declared rows for weight (liveness only).
        uint32 effRows = bonds.weightByBond[taskId] ? 1 : rows;
        uint96 w = uint96(Dividend.weight(effRows, Dividend.liveness(t.createdAt, t.windowEnd, uint64(block.timestamp))));
        if (w == 0) revert ICipherTask.ZeroContribution();

        contributions[contributor] = ICipherTask.Contribution({
            ciphertextCid: ciphertextCid,
            ctDigest: ctDigest,
            shapeProof: shapeProofDigest,
            rowCommitment: rowCommitment,
            rows: rows,
            leafIndex: leafIndex,
            submittedAt: uint64(block.timestamp),
            weightQ16: w,
            accepted: true,
            slashed: false
        });

        byLeaf[leafIndex] = contributor;
        shardSeen[ciphertextCid] = true;
        totalWeight[taskId] += w;
        t.ctRoot = keccak256(abi.encodePacked(t.ctRoot, leafIndex, ciphertextCid));
        contributorList.push(contributor);

        unchecked {
            t.shards += 1;
            t.contributors += 1;
        }

        if (t.status == ICipherTask.TaskStatus.Opening) {
            emit TaskStatusChanged(taskId, t.status, ICipherTask.TaskStatus.Collecting);
            t.status = ICipherTask.TaskStatus.Collecting;
        }

        // Bond last: a reverting pull must not leave a recorded contribution behind.
        // H2: rows are self-declared, so the pull scales with claimed rows (perRow).
        BondLib.pull(bonds, token, taskId, contributor, rows);

        emit ContributionSubmitted(taskId, contributor, leafIndex, ciphertextCid, rows);
    }
}

/// @title UnwindLib
/// @notice Abort / emergency-unwind refund path (external so the host stays small).
/// @dev Settlement is a commitment to contributors and cannot be unwound once any page ran;
///      freezing there cannot strand funds because settlement is permissionless and every page
///      is independently callable. A node holding a *verified* commit for the open epoch keeps
///      a slice of that epoch's lock as a redeemable channel; anything else refunds in full.
library UnwindLib {
    event Withdrawn(uint256 indexed taskId, address indexed who, uint128 amount);
    event TaskStatusChanged(uint256 indexed taskId, ICipherTask.TaskStatus from, ICipherTask.TaskStatus to);
    event TaskAborted(uint256 indexed taskId, bytes4 reason);

    uint16 private constant _ABORT_LOCK_BPS = 2_000;

    function unwind(
        PaymentVault vault,
        ICipherTask.Task storage t,
        SettlementLib.State storage settlement,
        mapping(uint256 => mapping(uint32 => address)) storage winners,
        mapping(uint256 => mapping(uint256 => uint128)) storage authorizedSlice,
        uint64 window,
        uint256 taskId,
        bytes4 reason
    ) external {
        if (settlement.settled[taskId]) revert ICipherTask.AlreadySettled(taskId);
        if (settlement.started[taskId]) revert ICipherTask.SettlementBegun(taskId);
        // Every epoch ran: contributors and the committee are owed their pools via
        // `settle`, so `abort` must not refund the whole escrow to the buyer.
        if (t.nextEpoch >= t.params.epochs) revert ICipherTask.SettleReady(taskId);

        address worker = winners[taskId][t.nextEpoch];
        uint128 keep = (t.locked > 0 && worker != address(0)) ? (t.locked * _ABORT_LOCK_BPS) / TaskParamsLib.BPS : 0;

        vault.sweepTaskChannels(taskId);
        uint256 available = vault.taskBalance(taskId);
        t.locked = 0;

        if (keep > 0) {
            RewardLib.openChannel(vault, authorizedSlice, window, taskId, t.nextEpoch, worker, keep);
        }

        uint128 refund = uint128(available > keep ? available - keep : 0);
        if (refund > 0) {
            // Pull-based like every other payout leg: the refund is credited to the buyer, who
            // claims it. Pushing here would revert the whole unwind on a failing buyer hook.
            vault.creditFromTask(taskId, t.params.buyer, refund);
            emit Withdrawn(taskId, t.params.buyer, refund);
        }
        emit TaskStatusChanged(taskId, t.status, ICipherTask.TaskStatus.Aborted);
        t.status = ICipherTask.TaskStatus.Aborted;
        emit TaskAborted(taskId, reason);
    }
}
