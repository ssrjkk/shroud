//! Solidity bindings for the Shroud contracts.
//!
//! Hand-maintained rather than generated so the reviewer can see exactly which ABI the node
//! depends on. Every declaration below was checked against `packages/contracts/src` and against
//! the compiler's own ABI in `packages/contracts/artifacts`, not against a prose description:
//! a binding that names a function the contract does not have is invisible until it reverts.
//!
//! Two rules are worth stating because breaking them is silent:
//!
//! * **Only bind what a node may actually call.** `withdraw`, `reclaimUnspentEpochs`,
//!   `closeChannel` and `abort` are deliberately absent — the first three are buyer, manager or
//!   streamer-only, so binding them would advertise work the node can never do.
//! * **Mirror the struct field names verbatim.** `Task.isSealed` is `isSealed`, not `sealed`, so
//!   a reordering or rename in Solidity shows up as a field that is never read rather than a
//!   plausible-looking wrong value.
#![allow(clippy::too_many_arguments)]

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface ICipherTaskView {
        // struct ICipherTask.TaskParams is a tuple; flattened into a struct here for clarity.
        struct TaskParams {
            address buyer;
            address updateManager;
            uint32 epochs;
            uint32 minContributors;
            uint32 maxContributors;
            uint32 minRowsPerShard;
            uint32 features;
            uint32 labelBits;
            uint32 contributionWindow;
            uint32 epochDuration;
            uint32 disputeWindow;
            uint32 pricePerRow;
            uint16 userShareBps;
            uint16 nodeShareBps;
            uint16 committeeShareBps;
            uint16 reexecutionBps;
            bytes32 modelSpecCid;
            bytes32 shapeRoot;
            uint8 updateMode;
        }

        /// Mirrors `ICipherTask.Task`.
        ///
        /// `status` is declared `uint8` rather than the Solidity `TaskStatus` enum: the encoding
        /// is identical and the node compares it against `state::TaskStatus::from_u8`, so taking
        /// it as a raw integer keeps the enum's numbering in exactly one place in this crate.
        struct Task {
            TaskParams params;
            uint128 budget;
            uint128 locked;
            uint64 createdAt;
            uint64 windowEnd;
            uint64 sealAt;
            uint64 epochDeadline;
            uint32 contributors;
            uint32 shards;
            uint32 nextEpoch;
            bytes32 ctRoot;
            bytes32 lastWeightsCid;
            bytes32 lastWeightsDigest;
            uint8 status;
            bool isSealed;
        }

        /// Mirrors `ICipherTask.EpochCommit`. This is what makes a dispute decidable locally:
        /// `reportDispute` requires *the reporter's own commit* to be `verified`, so a node has
        /// to read this struct before it decides to file.
        struct EpochCommit {
            bytes32 proof;
            bytes32 encWeightsCid;
            bytes32 weightsDigest;
            bytes32 metricsCid;
            bytes32 traceDigest;
            uint64 committedAt;
            uint64 revealNonce;
            bool verified;
        }

        function tasks(uint256 taskId) external view returns (Task memory);
        function commits(uint256 taskId, uint32 epoch, address node) external view returns (EpochCommit memory);
        function statusOf(uint256 taskId) external view returns (uint8);
        function taskCount() external view returns (uint256);
        function settleCursor(uint256 taskId) external view returns (uint256);
        function isFullySettled(uint256 taskId) external view returns (bool);
        function acceptedWeights(uint256 taskId) external view returns (bytes32 encWeightsCid, bytes32 weightsDigest);
        function ctRootOf(uint256 taskId) external view returns (bytes32);
        function divisorFor(uint256 taskId) external view returns (uint128);
        function nodePoolOf(uint256 taskId) external view returns (uint128);
        function rewardChannelWindow() external view returns (uint64);
        function proofTranscript(uint256 taskId, uint32 epoch, bytes32 traceDigest) external view returns (bytes32);
        function epochChannel(uint256 taskId, uint32 epoch) external view returns (uint256);
        function epochWinner(uint256 taskId, uint32 epoch) external view returns (address);
        function nodeRegistered(uint256 taskId, address node) external view returns (bool);
        function contributionOf(uint256 taskId, uint256 leafIndex) external view returns (address);
        function contributorsOf(uint256 taskId) external view returns (address[] memory);
        function escrowToken() external view returns (address);
        function pendingPayout(address account) external view returns (uint128);
        function disputeQuorum(uint256 taskId) external view returns (uint256 need, uint256 have);
    }

    #[sol(rpc)]
    interface ICipherTaskWrite {
        function registerNode(uint256 taskId, bytes32 blsPubKey) external;
        function commitEpoch(
            uint256 taskId,
            uint32 epoch,
            bytes32 proof,
            bytes32 encWeightsCid,
            bytes32 weightsDigest,
            bytes32 metricsCid,
            bytes32 traceDigest
        ) external;
        /// @dev `reexecutedDigest` must equal *our own* committed `traceDigest`, and must differ
        ///      from the epoch's claimed digest. It is not a free-form accusation.
        function reportDispute(uint256 taskId, uint32 epoch, bytes32 reexecutedDigest) external;
        function finalizeEpoch(uint256 taskId, uint32 epoch) external;
        function settle(uint256 taskId) external;
        function settleFrom(uint256 taskId, uint256 cursor) external;
    }

    #[sol(rpc)]
    interface IPaymentVault {
        struct Channel {
            address node;
            address streamer;
            uint128 maxCumulative;
            uint128 withdrawn;
            uint256 taskId;
            uint64 consumed;
            uint64 unlockAt;
            bool closed;
        }

        function channelInfo(uint256 channelId) external view returns (Channel memory);
        function channelIds(uint256 taskId) external view returns (uint256[] memory);
        function pendingWithdrawal(address account) external view returns (uint256);
        function redeemDigest(
            uint256 channelId,
            address streamer,
            address node,
            uint128 maxCumulative,
            uint64 unlockAt,
            uint256 deadline
        ) external view returns (bytes32);

        function redeem(
            uint256 channelId,
            uint256 sliceIndex,
            uint128 amount,
            uint256 deadline,
            bytes calldata signature
        ) external returns (uint128 paid);

        function reclaim(uint256 channelId) external returns (uint128 amount);
        function claim() external returns (uint256 amount);
    }

    #[sol(rpc)]
    interface INetworkParams {
        /// `Params public current` is a plain struct state variable, so solc's auto-getter
        /// returns its *flattened* members, not a tuple — hence eleven outputs here rather than
        /// `returns (Params memory)`. The same shape is pinned in the SDK's ABI.
        function current() external view returns (
            uint64 chainId,
            uint64 keyVersion,
            bytes32 fhePublicKeyHash,
            bytes32 committeeAggregateKey,
            uint16 committeeThreshold,
            uint16 committeeSize,
            uint32 maxProofBytes,
            uint32 maxCiphertextBytes,
            uint32 maxFeatures,
            uint64 activatedAt,
            bool active
        );
        function isCurrentKey(bytes32 sPubHash) external view returns (bool);
        function rotationPending() external view returns (bool);
    }
}

/// Event topics.
///
/// Computed with `keccak256` at first use from the exact Solidity signature strings rather than
/// pasted as hex. A hardcoded topic is a silent-failure risk: a typo in one byte means the
/// watcher simply never matches that event, the node idles, and nothing errors. Deriving them
/// makes that class of bug impossible.
///
/// The hex the compiler produced is still checked — in `topics_match_the_compiled_abi` below,
/// which pins every derived topic against the value in `artifacts/`. That catches the failure
/// mode deriving alone does not: a *signature string* that is wrong in a way keccak happily
/// hashes (a missing `indexed`, a wrong element type), which would otherwise just mean the
/// watcher subscribes to a topic nobody emits.
pub mod events {
    use alloy::primitives::{keccak256, B256};
    use once_cell::sync::Lazy;

    // --- CipherTask -------------------------------------------------------------------
    pub const TASK_SEALED: &str = "TaskSealed(uint256,bytes32,uint32,uint32)";
    pub const EPOCH_OPENED: &str = "EpochOpened(uint256,uint32,bytes32,bytes32)";
    pub const EPOCH_COMMITTED: &str = "EpochCommitted(uint256,uint32,address,bytes32)";
    pub const EPOCH_VERIFIED: &str = "EpochVerified(uint256,uint32,address,bool)";
    pub const EPOCH_SETTLED: &str = "EpochSettled(uint256,uint32,address,uint128)";
    pub const EPOCH_REJECTED: &str = "EpochRejected(uint256,uint32,uint256)";
    pub const DISPUTE_REPORTED: &str = "DisputeReported(uint256,uint32,address,bytes32)";
    pub const CONTRIBUTION_SUBMITTED: &str =
        "ContributionSubmitted(uint256,address,uint32,bytes32,uint32)";
    pub const TASK_ABORTED: &str = "TaskAborted(uint256,bytes4)";
    pub const TASK_SETTLED: &str = "TaskSettled(uint256,uint128,uint128,uint128)";
    pub const NODE_REWARD_CHANNEL_OPENED: &str =
        "NodeRewardChannelOpened(uint256,uint32,address,uint256,uint128,uint64,uint128)";

    // --- PaymentVault -----------------------------------------------------------------
    pub const CHANNEL_OPENED: &str =
        "ChannelOpened(uint256,uint256,address,address,uint128,uint64)";
    pub const SLICE_REDEEMED: &str = "SliceRedeemed(uint256,address,uint128,uint128,uint256)";
    pub const CHANNEL_RECLAIMED: &str = "ChannelReclaimed(uint256,address,uint128)";

    /// Everything the node folds, in the order [`decode_task_event`] and
    /// [`decode_vault_event`] consult. Split by emitter address because the watcher subscribes
    /// to both contracts with one filter: a topic that belongs to the vault must not be fed to
    /// the task decoder, where a data word would be read as an address.
    pub const TASK_EVENTS: &[&str] = &[
        CONTRIBUTION_SUBMITTED,
        DISPUTE_REPORTED,
        EPOCH_COMMITTED,
        EPOCH_OPENED,
        EPOCH_REJECTED,
        EPOCH_SETTLED,
        EPOCH_VERIFIED,
        NODE_REWARD_CHANNEL_OPENED,
        TASK_ABORTED,
        TASK_SEALED,
        TASK_SETTLED,
    ];

    pub const VAULT_EVENTS: &[&str] = &[CHANNEL_OPENED, SLICE_REDEEMED, CHANNEL_RECLAIMED];

    /// The signatures the node subscribes to. Kept in one place so the filter and the decoders
    /// cannot drift apart.
    pub static WATCH: Lazy<Vec<B256>> = Lazy::new(|| {
        TASK_EVENTS
            .iter()
            .chain(VAULT_EVENTS)
            .map(|sig| topic(sig))
            .collect()
    });

    pub fn topic(sig: &str) -> B256 {
        keccak256(sig.as_bytes())
    }

    macro_rules! topic_static {
        ($name:ident, $sig:expr) => {
            #[doc = concat!("`topic(", stringify!($sig), ")`, computed once.")]
            pub static $name: Lazy<B256> = Lazy::new(|| topic($sig));
        };
    }

    topic_static!(TASK_SEALED_TOPIC, TASK_SEALED);
    topic_static!(EPOCH_OPENED_TOPIC, EPOCH_OPENED);
    topic_static!(EPOCH_COMMITTED_TOPIC, EPOCH_COMMITTED);
    topic_static!(EPOCH_VERIFIED_TOPIC, EPOCH_VERIFIED);
    topic_static!(EPOCH_SETTLED_TOPIC, EPOCH_SETTLED);
    topic_static!(EPOCH_REJECTED_TOPIC, EPOCH_REJECTED);
    topic_static!(DISPUTE_REPORTED_TOPIC, DISPUTE_REPORTED);
    topic_static!(CONTRIBUTION_SUBMITTED_TOPIC, CONTRIBUTION_SUBMITTED);
    topic_static!(TASK_ABORTED_TOPIC, TASK_ABORTED);
    topic_static!(TASK_SETTLED_TOPIC, TASK_SETTLED);
    topic_static!(NODE_REWARD_CHANNEL_OPENED_TOPIC, NODE_REWARD_CHANNEL_OPENED);
    topic_static!(CHANNEL_OPENED_TOPIC, CHANNEL_OPENED);
    topic_static!(SLICE_REDEEMED_TOPIC, SLICE_REDEEMED);
    topic_static!(CHANNEL_RECLAIMED_TOPIC, CHANNEL_RECLAIMED);

    #[cfg(test)]
    mod tests {
        use super::*;

        /// `(signature, topic0)` exactly as the compiler emitted them into
        /// `packages/contracts/artifacts/src/.../{CipherTask,PaymentVault}.json`. Regenerate
        /// with `npx hardhat compile` and read the `abi` array; do not edit from the Solidity
        /// source, which is the thing being checked.
        ///
        /// One pair per line and `rustfmt::skip` for the same reason as the captured logs in
        /// `chain::watcher`: a 64-byte hex word cannot be wrapped, and shredding each pair over
        /// four lines makes the table unreadable against the compiler output it is copied from.
        #[rustfmt::skip]
        const COMPILED: &[(&str, &str)] = &[
            (CONTRIBUTION_SUBMITTED, "0xc37fa11865d20db8c2f9f36ef55d1f99c41a0ee1f98fd66fcad5c3e82cae8ef3"),
            (DISPUTE_REPORTED, "0x56c6da7aeff81fba1958ad3eddabcec10d01fa5edbe133afd962121e89b9acf9"),
            (EPOCH_COMMITTED, "0xbe1c0401080fba30020b1609c22d6c3de654f750279eb2c12daac731b9c5f668"),
            (EPOCH_OPENED, "0x7e3cb4c8395e586b6b675ae99ac10bb09551b19d95aeae90a896aead64caab2b"),
            (EPOCH_REJECTED, "0x8ef810f8e72a2aced85333b1f2a81efc7ee1e964b7b6e12eac2e49eb288900cc"),
            (EPOCH_SETTLED, "0x9c7e9f71dff59cfde2bb5e38de2a9baecc65bbaaa779209751a12c1c28355610"),
            (EPOCH_VERIFIED, "0xde1a096b42a741da9abd8e171b97e821d67b222feddb8d4e6efdfd642df44091"),
            (NODE_REWARD_CHANNEL_OPENED, "0x2226c20f431901d82fc48febfeab68c3b8b46423aae620f73d8b0b3c2b407053"),
            (TASK_ABORTED, "0xe445d9d031ef936fdcc51bb3f78ad934dc35d6a085ab35864de6329a6e9f65c8"),
            (TASK_SEALED, "0x99bf7cc8880bbbcd95ba1c122c314cb230e1607837b7aed2ea1957185b28c41b"),
            (TASK_SETTLED, "0x64b9379e52477e67cef49489615cca11e9f6343f94879ddc0c0f50ba19a4be65"),
            (CHANNEL_OPENED, "0x70d39e0205cc39a51528f1c53832da8ccc0820ec76bec1d321bfa6c864c829cf"),
            (SLICE_REDEEMED, "0x107845e530b551b1ff303785868633c9e6e01096d45d483f669269e4b5995a69"),
            (CHANNEL_RECLAIMED, "0x97c9fd82973dc049001bdce58b00498bb0ed44ee59212ca45dbe5f1e8201ba84"),
        ];

        #[test]
        fn topics_match_the_compiled_abi() {
            for (sig, hex) in COMPILED {
                let expected = hex.parse::<B256>().expect("topic is valid hex");
                assert_eq!(
                    topic(sig),
                    expected,
                    "signature {sig:?} does not hash to the compiler's topic0"
                );
            }
            // The list must stay complete, or a future event would be pinned against nothing.
            assert_eq!(COMPILED.len(), TASK_EVENTS.len() + VAULT_EVENTS.len());
        }

        #[test]
        fn watch_covers_both_event_lists_exactly_once() {
            let mut all = WATCH.clone();
            assert_eq!(all.len(), TASK_EVENTS.len() + VAULT_EVENTS.len());
            all.sort();
            all.dedup();
            assert_eq!(
                all.len(),
                WATCH.len(),
                "two signatures collide on keccak256"
            );
        }

        #[test]
        fn statics_agree_with_their_signature_strings() {
            assert_eq!(*TASK_SEALED_TOPIC, topic(TASK_SEALED));
            assert_eq!(
                *NODE_REWARD_CHANNEL_OPENED_TOPIC,
                topic(NODE_REWARD_CHANNEL_OPENED)
            );
            assert_eq!(*CHANNEL_RECLAIMED_TOPIC, topic(CHANNEL_RECLAIMED));
        }
    }
}
