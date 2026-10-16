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
        Aborted // refunded / unwound
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
        bytes32 ctRoot; // keccak256 accumulation chain over the shard CIDs, in leaf order
        bytes32 lastWeightsCid; // encWeights_e for the open epoch
        bytes32 lastWeightsDigest; // bound into the next STARK's public input
        TaskStatus status;
        bool isSealed;
    }

    struct Contribution {
        bytes32 ciphertextCid; // DA object
        bytes32 ctDigest; // keccak(ciphertext bytes) — pinned
        bytes32 shapeProof; // keccak(Groth16 shape proof bytes); the proof itself lives in the DA
        /// @dev Commitment to the contributor's row Merkle root. Required at submission and read
        ///      back by a re-execution, which decrypts the shard, rebuilds the row root and
        ///      compares. Without it the `shapeProof` digest would pin the existence of a proof
        ///      without pinning what it proves, so a submission could pair any proof with any
        ///      ciphertext.
        bytes32 rowCommitment;
        uint32 rows;
        uint32 leafIndex;
        uint64 submittedAt;
        uint96 weightQ16; // Dividend.weight(rows, liveness), frozen at submission
        bool accepted;
        /// @dev True once `slashContributionBond` burns the contributor's bond to the
        ///      treasury; `settle` then skips this contribution's reward share. The slash
        ///      is attested, not proven — there is no on-chain proof the shard was bad
        ///      (threat model F-01: the bond is opt-in, default zero).
        bool slashed;
    }

    struct EpochCommit {
        bytes32 proof; // STARK (or merkleRootOfProofs when segmented)
        bytes32 encWeightsCid; // ciphertext weights for epoch e+1
        bytes32 weightsDigest; // keccak256 of the little-endian lane words (see Weights::digest)
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
    /// @dev Emitted by `DisputeLib` (DELEGATECALL, same topic): a reporter committed to a
    ///      dispute digest without revealing it yet.
    event DisputeCommitted(uint256 indexed taskId, uint32 indexed epoch, address indexed reporter, bytes32 commitment);
    event ContributionBondRequirementSet(uint256 indexed taskId, uint128 amount);
    event ContributionBondReleased(uint256 indexed taskId, address indexed contributor, uint128 amount);
    event ContributionBondSlashed(uint256 indexed taskId, address indexed contributor, uint128 amount);
    event EpochSettled(uint256 indexed taskId, uint32 indexed epoch, address indexed node, uint128 amount);
    /// @notice The dispute quorum was reached for `epoch`: its claimant is not paid and the epoch
    ///         is skipped. Emitted instead of `TaskAborted`, because the task keeps running.
    event EpochRejected(uint256 indexed taskId, uint32 indexed epoch, uint256 reporters);
    /// @notice A rejected epoch's winner contradicted by quorum forfeits its registration bond
    ///         into the task sub-balance (buyer refund at settlement). Reporters keep theirs:
    ///         the chain cannot tell a lying winner from a lying quorum, but the winner is the
    ///         address three independently verified proofs disagree with.
    /// @dev Declared here (and emitted by `PaymentVault`, which owns custody) so indexers
    ///      decoding through the orchestrator ABI see the identical topic.
    event NodeBondSlashed(uint256 indexed taskId, uint32 indexed epoch, address indexed node, uint128 amount);
    /// @notice A registration bond released to its owner; releasable only once the task can no
    ///         longer slash it (terminal or fully settled).
    /// @dev Declared here, emitted by `PaymentVault`; same topic-identity reasoning as above.
    event NodeBondWithdrawn(uint256 indexed taskId, address indexed node, uint128 amount);
    event TaskSettled(uint256 indexed taskId, uint128 userPool, uint128 nodePool, uint128 treasury);
    /// @param blsAggregateSigDigest `keccak256` of the aggregate signature that authorised the
    ///        reveal. The 96-byte signature itself does not fit a `bytes32` topic-free field, and
    ///        an empty placeholder would make the event worthless to an auditor: a digest is
    ///        what lets a committee member prove which signature the chain accepted.
    event RevealRequested(uint256 indexed taskId, bytes32 weightsCid, bytes32 blsAggregateSigDigest);
    event RevealCompleted(uint256 indexed taskId, address indexed buyer);
    event Withdrawn(uint256 indexed taskId, address indexed who, uint128 amount);
    event TaskAborted(uint256 indexed taskId, bytes4 reason);
    event FheStateCheckpoint(uint256 indexed taskId, bytes32 encStateInput);

    /* ------------------------------------------------------------------ */
    /*                                 errors                              */
    /* ------------------------------------------------------------------ */

    /// @dev Every condition this contract rejects has its own error. A shared
    ///      `InvalidParams(string)` was both ambiguous for an SDK (two different "window"
    ///      reverts mean opposite things) and expensive: each call site had to ABI-encode a
    ///      dynamic string into memory, and those sites were the single largest line item in
    ///      `CipherTask`'s deployed size. The field name is in the selector instead, so the
    ///      arguments are only carried where they are already on the stack.
    error InvalidTaskStatus(uint256 taskId, TaskStatus current, TaskStatus expected);
    error BuyerMustBeCaller(address expected, address actual);
    error ZeroContribution();

    /* ---------------------------- createTask: parameters ---------------------------- */

    error EpochCountInvalid();
    error ContributorBoundsInvalid();
    error ContributorCapExceeded();
    error RowsPerShardInvalid();
    error FeatureCountInvalid();
    error LabelBitsInvalid();
    error ContributionWindowInvalid();
    error EpochDurationInvalid();
    error DisputeWindowInvalid();
    error ReexecutionBpsInvalid();
    error ModelSpecMissing();
    error ShapeRootMissing();
    error InvalidShares(uint16 user, uint16 node, uint16 committee);

    /* ---------------------------- contributions ---------------------------- */

    error BudgetTooSmall(uint256 minimum, uint128 provided);
    error ContributionWindowClosed(uint256 taskId);
    error AlreadyContributed(uint256 taskId, address contributor);
    error DuplicateShard(uint256 taskId, bytes32 ciphertextCid);
    error ShardTooSmall(uint32 rows, uint32 minimum);
    error ShardTooLarge(uint32 rows, uint32 maximum);
    error CapReached(uint256 taskId, uint32 cap);
    error BelowMinContributors(uint256 taskId, uint32 minimum, uint32 have);
    error ShapeProofInvalid(uint256 taskId, address contributor);
    error RowCommitmentInvalid(uint256 taskId, address contributor);
    error NoContributions(uint256 taskId);

    /* ---------------------------- epochs ---------------------------- */

    error UnknownTask(uint256 taskId);
    error AlreadyTerminal(uint256 taskId, TaskStatus status);
    error EpochStillLive(uint256 taskId, uint64 deadline);
    error NotUpdateManagerOrOwner(uint256 taskId, address caller);
    error NodeNotRegistered(uint256 taskId, address node);
    error ProofReferenceMissing(uint256 taskId, uint32 epoch, address node);
    error ProofRejected(uint256 taskId, uint32 epoch, bytes4 reason);
    error DuplicateCommit(uint256 taskId, uint32 epoch, address node);
    error EpochLocked(uint256 taskId);
    error AllEpochsRun(uint256 taskId, uint32 epoch);
    error EpochOutOfOrder(uint256 taskId, uint32 provided);
    error CommitWindowExpired(uint256 taskId, uint64 deadline);
    error DisputeBelowQuorum(uint256 taskId, uint32 epoch, uint256 have, uint256 need);
    error DisputeAgreesWithClaim(uint256 taskId, uint32 epoch, address reporter);
    error DisputeWithoutVerifiedCommit(uint256 taskId, uint32 epoch, address reporter);
    error DisputeDigestMismatch(uint256 taskId, uint32 epoch, address reporter, bytes32 committed, bytes32 reported);

    /* ---------------------------- nodes: bond ---------------------------- */
    /// @dev Declared here so the orchestrator ABI resolves them, but raised by `PaymentVault`,
    ///      which owns bond custody (see its `nodeBond` ledger). A revert propagates through
    ///      `registerNode`, so matching against this ABI sees the exact same bytes as an inline
    ///      raise would produce.
    error BondInsufficient(uint256 taskId, address node, uint128 required);
    error BlsKeyAlreadyUsed(uint256 taskId, bytes32 blsPubKey);
    error ZeroBlsKey(uint256 taskId, address node);
    error BondNotReleasable(uint256 taskId, address node);

    /* ---------------------------- settlement ---------------------------- */

    error EscrowMismatch(uint256 taskId, uint128 expected);
    error BudgetExhausted(uint256 taskId, uint128 available, uint128 required);
    error WeightPinMismatch(uint256 taskId, bytes32 expected, bytes32 provided);
    error RevealNotAllowed(uint256 taskId, TaskStatus status);
    error EpochsRemain(uint256 taskId);
    error AlreadySettled(uint256 taskId);
    error SettlementBegun(uint256 taskId);
    error SettleReady(uint256 taskId);
    error NoEpochOpened(uint256 taskId);
    error SettleCursorMismatch(uint256 taskId, uint256 provided);
    /// @dev The final settlement page ran while a reward channel of the task could still be
    ///      redeemed. Paying the committee/buyer legs against that incomplete balance would
    ///      permanently short them (F-22): wait for the window, then settle again.
    error ChannelsImmature(uint256 taskId);
    error NotTaskParty(uint256 taskId, address account);
    error ZeroAddress();
    /// @dev A dispute commitment is already open for this reporter: it must be revealed with
    ///      its salt (`reportDisputeWithSalt`), not bypassed with a bare `reportDispute`.
    error CommitmentPending(uint256 taskId, uint32 epoch, address reporter);
    /// @dev The reporter never committed, or the salt does not open the commitment.
    error CommitmentMismatch(uint256 taskId, uint32 epoch, address reporter);
    /// @dev Contribution-bond requirement outside the allowed range (see CipherTask).
    error BondRequirementInvalid(uint256 taskId, uint128 amount);
    error NoBondToRelease(uint256 taskId, address contributor);
    error InvalidPopSignature(uint256 taskId, address node);
    error TransferFailed(address token, address to, uint256 amount);

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
    /// @notice Register with proof-of-possession of the node's signing key over its BLS key.
    /// @dev `sig` must be a 65-byte ECDSA signature by `msg.sender` (EIP-191 personal message)
    ///      over `keccak256(abi.encode(taskId, blsPubKey, msg.sender, block.chainid,
    ///      address(this)))`. BLS keys are otherwise self-declared: uniqueness only stops lazy
    ///      reuse, and anyone can register any key. Binding the BLS key to the node's EOA at
    ///      registration at least proves one live signer per identity and makes key-theft
    ///      repudiation impossible — the registration transaction itself is the attestation.
    function registerNodeWithPop(uint256 taskId, bytes32 blsPubKey, bytes calldata sig) external;
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
    /// @notice Submit a segmented STARK (Merkle root over segment proofs) for epoch `epoch`.
    /// @dev Same bindings and winner logic as `commitEpoch`, but verified through
    ///      `IProofVerifier.verifyProofSegmented`. Without this entry point the segmented
    ///      verifier path was unreachable: the docs claimed segmented verification existed
    ///      while `commitEpoch` could only ever call `verifyProof` (F-33). `proof` must be
    ///      exactly 32 bytes (the segment Merkle root); anything else reverts in the verifier.
    function commitEpochSegmented(
        uint256 taskId,
        uint32 epoch,
        bytes32 segmentedRoot,
        bytes32 encWeightsCid,
        bytes32 weightsDigest,
        bytes32 metricsCid,
        bytes32 traceDigest
    ) external;
    function reportDispute(uint256 taskId, uint32 epoch, bytes32 reexecutedDigest) external;
    /// @notice Commit to a dispute digest before revealing it (front-run resistance).
    /// @dev `commitment = keccak256(abi.encode(digest, salt, msg.sender))`. A bare
    ///      `reportDispute` in the mempool can be copied by any other registered node that
    ///      also holds a verified commit; the copy pays the copier the reporter bounty for
    ///      work it did not do and, worse, lets a Sybil ring manufacture quorum cheaply.
    ///      Committing first makes the digest unknowable until `reportDisputeWithSalt`.
    function commitDispute(uint256 taskId, uint32 epoch, bytes32 commitment) external;
    /// @notice Reveal a committed dispute digest.
    function reportDisputeWithSalt(uint256 taskId, uint32 epoch, bytes32 reexecutedDigest, bytes32 salt) external;
    function finalizeEpoch(uint256 taskId, uint32 epoch) external;
    function settle(uint256 taskId) external;
    function settleFrom(uint256 taskId, uint256 cursor) external;
    function settleCursor(uint256 taskId) external view returns (uint256);
    function isFullySettled(uint256 taskId) external view returns (bool);
    /// @notice Set (or clear with 0) the per-contributor bond required to submit a shard.
    /// @dev Anti-spam, not punishment: without any bond a fraudulent shard costs nothing to
    ///      submit and is detected only if someone re-executes (F-01). Callable by the buyer
    ///      or update manager while the contribution window is still open. Capped so a
    ///      malicious buyer cannot set a prohibitive bond to censor contributions.
    function setContributionBondRequirement(uint256 taskId, uint128 amount) external;
    /// @notice Release a contributor's bond to them. Callable by anyone once the task can no
    ///         longer slash it (terminal or fully settled); the money can only go to the
    ///         contributor, so the caller has no discretion.
    function releaseContributionBond(uint256 taskId, address contributor) external;
    /// @notice Slash a contributor's bond to the treasury (never to the buyer: the buyer must
    ///         gain nothing from slashing, or slashing becomes a revenue stream). Callable by
    ///         the buyer, update manager or owner. The contribution is also marked slashed, so
    ///         `settle` skips its reward share.
    /// @dev Closed once the task is settled or terminal: post-hoc burns of honest
    ///      contributors' unreleased bonds would be grief indistinguishable from a real slash.
    function slashContributionBond(uint256 taskId, address contributor) external;
    function requestReveal(uint256 taskId, bytes calldata blsAggregateSig) external;
    function submitPartialDecryption(uint256 taskId, bytes32 partialDecryption) external;
    function withdraw(uint256 taskId) external;
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
    function contributorsOf(uint256 taskId) external view returns (address[] memory);
    function commits(uint256 taskId, uint32 epoch, address node) external view returns (EpochCommit memory);
    function acceptedWeights(uint256 taskId) external view returns (bytes32 encWeightsCid, bytes32 weightsDigest);
    function pendingPayout(address account) external view returns (uint128 amount);
    function divisorFor(uint256 taskId) external view returns (uint128);
    function escrowToken() external view returns (address);
    function disputeQuorum(uint256 taskId) external view returns (uint256 need, uint256 have);
    function statusOf(uint256 taskId) external view returns (TaskStatus);
    function nodeRegistered(uint256 taskId, address node) external view returns (bool);
    function epochWinner(uint256 taskId, uint32 epoch) external view returns (address);
    function epochChannel(uint256 taskId, uint32 epoch) external view returns (uint256);
    function ctRootOf(uint256 taskId) external view returns (bytes32);
    function nodePoolOf(uint256 taskId) external view returns (uint128);
    function rewardChannelWindow() external view returns (uint64);
    function proofTranscript(uint256 taskId, uint32 epoch, bytes32 traceDigest) external view returns (bytes32);
    function settleUserPool(uint256 taskId) external view returns (uint128);

    /// @dev A channel's slice is authorised by this contract, so a node redeems with an
    ///      ERC-1271 signature that is really an ABI-packed `(channelId, sliceIndex, amount,
    ///      padding)` — see `PaymentVault.redeem`. The digest the vault checks is
    ///      `PaymentVault.redeemDigest`, which is the single definition clients use; this contract
    ///      does not republish it.
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4);
}
