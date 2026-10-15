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
    /// @notice Dispute state for every task/epoch. Owned by the host, passed by pointer.
    struct State {
        mapping(uint256 => mapping(uint32 => mapping(address => bytes32))) commitment;
        mapping(uint256 => mapping(uint32 => mapping(address => bool))) recorded;
        mapping(uint256 => mapping(uint32 => uint256)) count;
        mapping(uint256 => mapping(uint32 => address[])) reporters;
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
        bytes32 salt
    ) external {
        bytes32 c = s.commitment[taskId][epoch][reporter];
        if (c == bytes32(0)) revert ICipherTask.CommitmentMismatch(taskId, epoch, reporter);
        if (keccak256(abi.encode(digest, salt, reporter)) != c) {
            revert ICipherTask.CommitmentMismatch(taskId, epoch, reporter);
        }
        delete s.commitment[taskId][epoch][reporter];
        record(s, registered, t, commits, claimed, taskId, epoch, reporter, digest);
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
        bytes32 digest
    ) external {
        if (s.commitment[taskId][epoch][reporter] != bytes32(0)) {
            revert ICipherTask.CommitmentPending(taskId, epoch, reporter);
        }
        record(s, registered, t, commits, claimed, taskId, epoch, reporter, digest);
    }

    /// @dev The shared counting logic. A report is only counted from an address holding its own
    ///      verified commit for the epoch whose digest it reports — re-execution must produce a
    ///      proof that verifies, which is the work the bounty pays for (F-18).
    function record(
        State storage s,
        mapping(uint256 => mapping(address => bool)) storage registered,
        ICipherTask.Task storage t,
        mapping(uint256 => mapping(uint32 => mapping(address => ICipherTask.EpochCommit))) storage commits,
        mapping(uint256 => mapping(uint32 => bytes32)) storage claimed,
        uint256 taskId,
        uint32 epoch,
        address reporter,
        bytes32 digest
    ) private {
        if (!registered[taskId][reporter]) revert ICipherTask.NodeNotRegistered(taskId, reporter);
        if (t.status != ICipherTask.TaskStatus.EpochCommitting) {
            revert ICipherTask.InvalidTaskStatus(taskId, t.status, ICipherTask.TaskStatus.EpochCommitting);
        }
        if (s.recorded[taskId][epoch][reporter]) revert ICipherTask.DuplicateCommit(taskId, epoch, reporter);
        if (digest == claimed[taskId][epoch]) revert ICipherTask.DisputeAgreesWithClaim(taskId, epoch, reporter);

        ICipherTask.EpochCommit storage mine = commits[taskId][epoch][reporter];
        if (!mine.verified) revert ICipherTask.DisputeWithoutVerifiedCommit(taskId, epoch, reporter);
        if (mine.traceDigest != digest) {
            revert ICipherTask.DisputeDigestMismatch(taskId, epoch, reporter, mine.traceDigest, digest);
        }

        s.recorded[taskId][epoch][reporter] = true;
        s.count[taskId][epoch] += 1;
        s.reporters[taskId][epoch].push(reporter);
        emit DisputeReported(taskId, epoch, reporter, digest);
    }
}
