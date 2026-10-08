// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "encrypted-types/EncryptedTypes.sol";

/// @title ICipherTask
/// @notice Orchestrator interface for Shroud: escrow-backed, FHE-native training tasks.
/// @dev All FHE types are the fhEVM/Zama ciphertext handles. Never decrypt inside this contract
///      except through DecryptionGate, which is contract-restricted to settled outputs.
interface ICipherTask {
    /* ------------------------------------------------------------------ */
    /*                                  enums                              */
    /* ------------------------------------------------------------------ */

    enum TaskStatus {
        None,
        Opening, // created, waiting for the first contribution
        Collecting, // >= 1 contribution, window open
        Sealed, // ctRoot frozen, no more shards accepted
        EpochOpen, // buyer published encWeights_e, nodes may commit
        EpochCommitting, // at least one valid STARK received, dispute window live
        EpochSettled, // epoch accepted, payout for the epoch released
        Settling, // all epochs done, escrow distributed
        Revealing, // threshold decryption in flight
        Disclosed, // buyer withdrew plaintext weights
        Aborted, // refunded / slashed to zero
        Paused // admin pause
    }

    enum UpdateMode {
        FullBatch, // 1 bootstrapped pass over the dataset per epoch
        MiniBatch, // minibatch_size rows per pass, gradient accumulation
        Batch // full gradient, all rows, single pass
    }

    /* ------------------------------------------------------------------ */
    /*                                 structs                             */
    /* ------------------------------------------------------------------ */

    struct TaskParams {
        address buyer; // who escrowed and receives the weights
        address updateManager; // may call openEpoch(); defaults to buyer
        uint32 epochs; // E, 1..=MAX_EPOCHS
        uint32 minContributors; // seal threshold
        uint32 maxContributors;
        uint32 minRowsPerShard;
        uint32 features; // d, 1..=MAX_FEATURES
        uint32 labelBits; // 8 or 16
        uint32 contributionWindow; // seconds, Collecting -> Sealed
        uint32 epochDuration; // seconds a node has to commit
        uint32 disputeWindow; // seconds the fraud window stays open
        uint32 pricePerRow; // buyer's stated price, informational + oracle floor
        uint16 userShareBps; // of budget -> contributors
        uint16 nodeShareBps; // of budget -> compute nodes
        uint16 committeeShareBps; // of budget -> decryption committee
        uint16 reexecutionBps; // of node pool -> dispute bounty
        bytes32 modelSpecCid; // IPFS/arweave CID of the model + data schema
        bytes32 shapeRoot; // buyer-signed Merkle root of acceptable row shapes
        UpdateMode updateMode;
    }

    struct Task {
        TaskParams params;
        uint128 budget; // total escrow, USDC 6dp
        uint128 locked; // currently committed to the open epoch
        uint64 createdAt;
        uint64 windowEnd; // contribution window deadline (fixed at creation)
        uint64 sealAt;
        uint64 epochDeadline; // deadline for the currently open epoch (0 when none)
        uint32 contributors; // distinct accepted contributors
        uint32 shards; // accepted shard count == ctRoot leaf count
        uint32 nextEpoch; // next epoch index to open
        bytes32 ctRoot; // incremental SHA-256 over shard CIDs (in leaf order)
        bytes32 lastWeightsCid; // encWeights_e for the open epoch
        bytes32 lastWeightsDigest; // bound into the next STARK's public input
        TaskStatus status;
        bool isSealed;
    }

    struct Contribution {
        bytes32 ciphertextCid; // DA object
        bytes32 ctDigest; // keccak(ciphertext bytes) — pinned
        bytes32 shapeProof; // keccak(Groth16 shape proof bytes); the proof itself lives in the DA
        uint32 rows;
        uint32 leafIndex;
        uint64 submittedAt;
        uint96 weightQ16; // Dividend.weight(rows, liveness), frozen at submission
        bool accepted;
        /// @dev Always false. There is no slashing mechanism in this codebase: no bond is ever
        ///      taken (`contributionBond` does not exist) and nothing writes this field. It is
        ///      kept because `settle` reads it and because adding slashing later should not change
        ///      the payout path — but do not read it as "fraud has been punished". Threat model
        ///      F-01 records the missing bond as unimplemented work rather than a mitigation.
        bool slashed;
    }

    struct EpochCommit {
        bytes32 proof; // STARK (or merkleRootOfProofs when segmented)
        bytes32 encWeightsCid; // ciphertext weights for epoch e+1
        bytes32 weightsDigest; // sha256 of the plaintext weight vector
        bytes32 metricsCid; // encrypted metrics (loss, acc) — never revealed
        bytes32 traceDigest; // digest of the STARK trace, for re-execution comparison
        uint64 committedAt;
        uint64 revealNonce; // bumped per competing commit; binds re-execution reports
        bool verified;
    }

    /* ------------------------------------------------------------------ */
    /*                                 events                              */
    /* ------------------------------------------------------------------ */

    event TaskCreated(uint256 indexed taskId, address indexed buyer, uint128 budget, uint32 epochs);
    event TaskStatusChanged(uint256 indexed taskId, TaskStatus from, TaskStatus to);
    event ContributionSubmitted(
        uint256 indexed taskId,
        address indexed contributor,
        uint32 indexed leafIndex,
        bytes32 ciphertextCid,
        uint32 rows
    );
    event TaskSealed(uint256 indexed taskId, bytes32 ctRoot, uint32 shards, uint32 contributors);
    event EpochOpened(uint256 indexed taskId, uint32 indexed epoch, bytes32 encWeightsCid, bytes32 weightsDigest);
    event EpochCommitted(uint256 indexed taskId, uint32 indexed epoch, address indexed node, bytes32 traceDigest);
    event EpochVerified(uint256 indexed taskId, uint32 indexed epoch, address indexed node, bool ok);
    event DisputeReported(uint256 indexed taskId, uint32 indexed epoch, address indexed reporter, bytes32 digest);
    event EpochSettled(uint256 indexed taskId, uint32 indexed epoch, address indexed node, uint128 amount);
    event TaskSettled(uint256 indexed taskId, uint128 userPool, uint128 nodePool, uint128 treasury);
    event RevealRequested(uint256 indexed taskId, bytes32 weightsCid, bytes32 blsAggregateSig);
    event PartialDecryptionSubmitted(uint256 indexed taskId, address indexed member, bytes32 partialDecryption);
    event RevealCompleted(uint256 indexed taskId, address indexed buyer);
    event Withdrawn(uint256 indexed taskId, address indexed who, uint128 amount);
    event TaskAborted(uint256 indexed taskId, bytes4 reason);
    event FheStateCheckpoint(uint256 indexed taskId, bytes32 encStateInput);

    /* ------------------------------------------------------------------ */
    /*                                 errors                              */
    /* ------------------------------------------------------------------ */

    error NotTaskUpdateManager(uint256 taskId, address caller);
    error InvalidTaskStatus(uint256 taskId, TaskStatus current, TaskStatus expected);
    error InvalidParams(string reason);
    error BudgetTooSmall(uint256 minimum, uint128 provided);
    error ContributionWindowClosed(uint256 taskId);
    error AlreadyContributed(uint256 taskId, address contributor);
    error ShardTooSmall(uint32 rows, uint32 minimum);
    error ShardTooLarge(uint32 rows, uint32 maximum);
    error CapReached(uint256 taskId, uint32 cap);
    error ShapeProofInvalid(uint256 taskId, address contributor);
    error CiphertextPinMismatch(uint256 taskId, bytes32 expected, bytes32 provided);
    error RowCommitmentInvalid(uint256 taskId, address contributor);
    error ProofTooLarge(uint256 proofLength, uint256 max);

    /// @dev The 32-byte proof reference a node committed was zero, i.e. absent.
    error ProofReferenceMissing(uint256 taskId, uint32 epoch, address node);
    error ProofRejected(uint256 taskId, uint32 epoch, bytes4 reason);
    error DuplicateCommit(uint256 taskId, uint32 epoch, address node);
    error DisputeAlreadyClosed(uint256 taskId, uint32 epoch);
    error DisputeBelowQuorum(uint256 taskId, uint32 epoch, uint256 have, uint256 need);
    error EscrowMismatch(uint256 taskId, uint128 expected);
    error WeightPinMismatch(uint256 taskId, bytes32 expected, bytes32 provided);
    error RevealNotAllowed(uint256 taskId, TaskStatus status);
    error AlreadyDisclosed(uint256 taskId);
    error NothingToWithdraw(address account);
    error NotCommitteeMember(address caller);
    error OutputNotRegistered(uint256 taskId, bytes32 weightsCid);

    /* ------------------------------------------------------------------ */
    /*                                 actions                             */
    /* ------------------------------------------------------------------ */

        /// @param budget the exact amount (base units) escrowed for the task; the buyer must have
        ///        approved at least this much to the vault. Nothing more is pulled.
        /// @param p     the task parameters
        function createTask(uint128 budget, TaskParams calldata p) external returns (uint256 taskId);
    function submitContribution(
        uint256 taskId,
        bytes32 ciphertextCid,
        bytes32 ctDigest,
        bytes calldata shapeProof,
        bytes32 rowCommitment,
        uint32 rows
    ) external;
    function sealTask(uint256 taskId) external;
    function registerNode(uint256 taskId, bytes32 blsPubKey) external;
    function openEpoch(
        uint256 taskId,
        bytes32 encWeightsCid,
        bytes32 weightsDigest,
        externalEuint64 encStateExternal,
        bytes calldata encStateProof
    ) external;
    function commitEpoch(
        uint256 taskId,
        uint32 epoch,
        bytes32 proof,
        bytes32 encWeightsCid,
        bytes32 weightsDigest,
        bytes32 metricsCid,
        bytes32 traceDigest
    ) external;
    function reportDispute(uint256 taskId, uint32 epoch, bytes32 reexecutedDigest) external;
    function finalizeEpoch(uint256 taskId, uint32 epoch) external;
    function settle(uint256 taskId) external;
    function settleFrom(uint256 taskId, uint256 cursor) external;
    function settleCursor(uint256 taskId) external view returns (uint256);
    function isFullySettled(uint256 taskId) external view returns (bool);
    function requestReveal(uint256 taskId, bytes calldata blsAggregateSig) external;
    function submitPartialDecryption(uint256 taskId, bytes32 partialDecryption) external;
    function withdraw(uint256 taskId) external returns (uint128 amount);
    function reclaimUnspentEpochs(uint256 taskId) external returns (uint128 amount);
    function abort(uint256 taskId, bytes4 reason) external;
    function emergencyUnwind(uint256 taskId) external;
    function grantStateAccess(uint256 taskId, address account) external;

    /* ------------------------------------------------------------------ */
    /*                                 views                               */
    /* ------------------------------------------------------------------ */

    function tasks(uint256 taskId) external view returns (Task memory);
    function contributions(uint256 taskId, address contributor) external view returns (Contribution memory);
    function contributionOf(uint256 taskId, uint256 leafIndex) external view returns (address);
    function commits(uint256 taskId, uint32 epoch, address node) external view returns (EpochCommit memory);
    function acceptedWeights(uint256 taskId) external view returns (bytes32 encWeightsCid, bytes32 weightsDigest);
    function pendingPayout(address account) external view returns (uint128 amount);
    function divisorFor(uint256 taskId) external view returns (uint128);
    function escrowToken() external view returns (address);
    function disputeQuorum(uint256 taskId) external view returns (uint256 need, uint256 have);
}
