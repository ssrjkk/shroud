// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICipherTask} from "../interfaces/ICipherTask.sol";

/// @title DisputeLib
/// @notice Commit-reveal dispute reporting for `CipherTask` (threat model F-04/F-18).
///
/// @dev External library on purpose, like `SettlementLib`/`TaskParamsLib`: `CipherTask` must
///      stay inside the 24,576-byte deployment limit, and only `external` library calls move
///      bytes out (`internal` calls inline back into the caller under `viaIR`). Runs by
///      `DELEGATECALL` as the host, so events log from the host's address and storage writes
///      land in the host's slots through the pointers it passes.
///
///      Why commit-reveal exists at all: a bare `reportDispute` sits in the mempool where any
///      other registered node holding its own verified commit can copy the digest and race it.
///      The copy costs nothing, earns the reporter bounty for work it did not do and lets a
///      Sybil ring manufacture quorum cheaply. Committing
///      `keccak256(abi.encode(digest, salt, reporter))` first makes the digest unknowable until
///      the reveal, and binding the reporter address stops one commitment being replayed by
///      another identity.
library DisputeLib {
    /// @notice Maximum reporters recorded (and paid) per task/epoch.
    /// @dev Reporters must hold a verified commit, so the array is already bounded by
    ///      `MAX_NODES = 200`. A 64-reporter cap keeps `payReporters` and channel sweeps
    ///      far below the block gas limit. `DISPUTE_QUORUM` is 3; 64 is generous headroom.
    uint32 internal constant MAX_REPORTERS_PER_EPOCH = 64;

    /// @notice Expected dispute-committee seats per epoch. The lottery below draws
    ///         each registered node with probability `COMMITTEE_SIZE * weight / total`,
    ///         where `weight` is the node's posted bond and `total` the task's bond
    ///         sum — stake-weighted sortition. With flat bonds this reduces exactly to
    ///         `COMMITTEE_SIZE / nodeCount` (uniform draw), so small tasks behave as
    ///         before (everyone eligible) while large tasks stop counting arbitrary
    ///         Sybil identities toward quorum.
    /// @dev `COMMITTEE_SIZE * weight` cannot overflow in practice (`weight` is a uint128
    ///      bond position, so the product stays far below 2^256) and Solidity 0.8 would
    ///      revert rather than wrap in any case. Kept above `DISPUTE_QUORUM` (3): a
    ///      healthy committee always has several eligible members, and
    ///      `MAX_REPORTERS_PER_EPOCH` (64) still bounds payout.
    uint256 internal constant COMMITTEE_SIZE = 7;

    /// @notice Dispute state for every task/epoch. Owned by the host, passed by pointer.
    struct State {
        mapping(uint256 => mapping(uint32 => mapping(address => bytes32))) commitment;
        mapping(uint256 => mapping(uint32 => mapping(address => bool))) recorded;
        mapping(uint256 => mapping(uint32 => uint256)) count;
        mapping(uint256 => mapping(uint32 => address[])) reporters;
        /// Sortition seed per epoch, fixed by the first counted report. `block.prevrandao`
        /// of that block is unpredictable to anyone registering earlier (registration
        /// closes before the epoch opens), and every later report in the epoch evaluates
        /// against the same seed, so eligibility is stable within the epoch.
        mapping(uint256 => mapping(uint32 => bytes32)) seed;
    }

    // Redeclared from the host so a delegatecall'd library logs from the host's address with
    // identical topics — clients decoding through the orchestrator ABI see no difference.
    event DisputeCommitted(uint256 indexed taskId, uint32 indexed epoch, address indexed reporter, bytes32 commitment);
    event DisputeReported(uint256 indexed taskId, uint32 indexed epoch, address indexed reporter, bytes32 digest);

    /// @notice Open a dispute commitment. Optional, but once open the bare report path closes
    ///         for the reporter until they reveal (otherwise the commitment is theatre).
    function commit(
        State storage s,
        mapping(uint256 => mapping(address => bool)) storage registered,
        ICipherTask.Task storage t,
        uint256 taskId,
        uint32 epoch,
        address reporter,
        bytes32 commitment
    ) external {
        if (!registered[taskId][reporter]) revert ICipherTask.NodeNotRegistered(taskId, reporter);
        if (t.status != ICipherTask.TaskStatus.EpochCommitting) {
            revert ICipherTask.InvalidTaskStatus(taskId, t.status, ICipherTask.TaskStatus.EpochCommitting);
        }
        if (commitment == bytes32(0)) revert ICipherTask.CommitmentMismatch(taskId, epoch, reporter);
        if (s.recorded[taskId][epoch][reporter]) revert ICipherTask.DuplicateCommit(taskId, epoch, reporter);
        if (s.commitment[taskId][epoch][reporter] != bytes32(0)) {
            revert ICipherTask.CommitmentPending(taskId, epoch, reporter);
        }
        s.commitment[taskId][epoch][reporter] = commitment;
        emit DisputeCommitted(taskId, epoch, reporter, commitment);
    }

    /// @notice Reveal a committed digest and record the dispute atomically.
    function reveal(
        State storage s,
        mapping(uint256 => mapping(address => bool)) storage registered,
        ICipherTask.Task storage t,
        mapping(uint256 => mapping(uint32 => mapping(address => ICipherTask.EpochCommit))) storage commits,
        mapping(uint256 => mapping(uint32 => bytes32)) storage claimed,
        uint256 taskId,
        uint32 epoch,
        address reporter,
        bytes32 digest,
        bytes32 salt,
        uint256 committeeTotal,
        uint256 reporterWeight
    ) external {
        bytes32 c = s.commitment[taskId][epoch][reporter];
        if (c == bytes32(0)) revert ICipherTask.CommitmentMismatch(taskId, epoch, reporter);
        if (keccak256(abi.encode(digest, salt, reporter)) != c) {
            // Deliberately NO slash here, though the mismatch is attributable: a revert
            // rolls back every state change in the transaction, so an eager slash would
            // burn nothing — and a typo'd salt is indistinguishable on-chain from malice,
            // so burning on this path would tax honest mistakes. The commitment stays
            // intact, so the reporter simply retries with the right salt; the committee
            // gate above is what makes Sybil disputes expensive, not this path.
            revert ICipherTask.CommitmentMismatch(taskId, epoch, reporter);
        }
        delete s.commitment[taskId][epoch][reporter];
        record(s, registered, t, commits, claimed, taskId, epoch, reporter, digest, committeeTotal, reporterWeight);
    }

    /// @notice Bare report path (backward compatible). Reverts while the reporter has an open
    ///         commitment — commit means commit.
    function report(
        State storage s,
        mapping(uint256 => mapping(address => bool)) storage registered,
        ICipherTask.Task storage t,
        mapping(uint256 => mapping(uint32 => mapping(address => ICipherTask.EpochCommit))) storage commits,
        mapping(uint256 => mapping(uint32 => bytes32)) storage claimed,
        uint256 taskId,
        uint32 epoch,
        address reporter,
        bytes32 digest,
        uint256 committeeTotal,
        uint256 reporterWeight
    ) external {
        if (s.commitment[taskId][epoch][reporter] != bytes32(0)) {
            revert ICipherTask.CommitmentPending(taskId, epoch, reporter);
        }
        record(s, registered, t, commits, claimed, taskId, epoch, reporter, digest, committeeTotal, reporterWeight);
    }

    /// @dev Pure eligibility predicate, separated so the host can expose it as a view
    ///      without mutating state. Unset seed, empty registry total, or zero weight
    ///      means not eligible. `COMMITTEE_SIZE * weight >= total` (small registries,
    ///      whales) is an automatic pass — the lottery covers everyone.
    function isEligibleSeed(bytes32 seed, uint256 totalWeight, uint256 weight, address reporter)
        internal
        pure
        returns (bool)
    {
        if (seed == bytes32(0) || totalWeight == 0 || weight == 0) return false;
        return uint256(keccak256(abi.encode(seed, reporter))) % totalWeight < COMMITTEE_SIZE * weight;
    }

    /// @dev Sortition gate for `record`: fixes the epoch seed on first use, then admits
    ///      only drawn members. Inlined into the host (internal), so no DELEGATECALL.
    function isEligible(
        State storage s,
        uint256 taskId,
        uint32 epoch,
        address reporter,
        uint256 totalWeight,
        uint256 weight
    ) internal returns (bool) {
        bytes32 seed = s.seed[taskId][epoch];
        if (seed == bytes32(0)) {
            seed = keccak256(abi.encode(block.prevrandao, taskId, epoch));
            s.seed[taskId][epoch] = seed;
        }
        return isEligibleSeed(seed, totalWeight, weight, reporter);
    }

    /// @dev The shared counting logic. A report is only counted from an address holding its own
    ///      verified commit for the epoch whose digest it reports — re-execution must produce a
    ///      proof that verifies, which is the work the bounty pays for (F-18) — AND drawn
    ///      into the epoch committee, so a Sybil ring cannot manufacture quorum (F-04).
    function record(
        State storage s,
        mapping(uint256 => mapping(address => bool)) storage registered,
        ICipherTask.Task storage t,
        mapping(uint256 => mapping(uint32 => mapping(address => ICipherTask.EpochCommit))) storage commits,
        mapping(uint256 => mapping(uint32 => bytes32)) storage claimed,
        uint256 taskId,
        uint32 epoch,
        address reporter,
        bytes32 digest,
        uint256 committeeTotal,
        uint256 reporterWeight
    ) private {
        if (!registered[taskId][reporter]) revert ICipherTask.NodeNotRegistered(taskId, reporter);
        if (t.status != ICipherTask.TaskStatus.EpochCommitting) {
            revert ICipherTask.InvalidTaskStatus(taskId, t.status, ICipherTask.TaskStatus.EpochCommitting);
        }
        if (s.recorded[taskId][epoch][reporter]) revert ICipherTask.DuplicateCommit(taskId, epoch, reporter);
        if (digest == claimed[taskId][epoch]) revert ICipherTask.DisputeAgreesWithClaim(taskId, epoch, reporter);
        if (!isEligible(s, taskId, epoch, reporter, committeeTotal, reporterWeight)) {
            revert ICipherTask.NotCommitteeMember(taskId, epoch, reporter);
        }

        ICipherTask.EpochCommit storage mine = commits[taskId][epoch][reporter];
        if (!mine.verified) revert ICipherTask.DisputeWithoutVerifiedCommit(taskId, epoch, reporter);
        if (mine.traceDigest != digest) {
            revert ICipherTask.DisputeDigestMismatch(taskId, epoch, reporter, mine.traceDigest, digest);
        }

        s.recorded[taskId][epoch][reporter] = true;
        s.count[taskId][epoch] += 1;
        // Bound the reporters array at the source: without a cap, a task with hundreds of
        // reporters makes `payReporters` and channel sweeps exceed the block gas limit and
        // locks the task. Quorum is 3; the 65th reporter is not needed for security.
        if (s.reporters[taskId][epoch].length >= MAX_REPORTERS_PER_EPOCH) {
            revert ICipherTask.CapReached(taskId, MAX_REPORTERS_PER_EPOCH);
        }
        s.reporters[taskId][epoch].push(reporter);
        emit DisputeReported(taskId, epoch, reporter, digest);
    }
}
