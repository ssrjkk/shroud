//! Solidity bindings for the Shroud contracts.
//!
//! Hand-maintained rather than generated so the reviewer can see exactly which ABI the node
//! depends on. `just codegen-bindings` regenerates them from `packages/contracts/artifacts`
//! and the diff is reviewed like any other code.
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
            bool sealed;
        }

        function tasks(uint256 taskId) external view returns (Task memory);
        function statusOf(uint256 taskId) external view returns (uint8);
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
        function isSettled(uint256 taskId) external view returns (bool);
        function pendingPayout(address account) external view returns (uint128);
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
        function reportDispute(uint256 taskId, uint32 epoch, bytes32 reexecutedDigest) external;
        function disputeQuorum(uint256 taskId) external view returns (uint256 need, uint256 have);
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
    }

    #[sol(rpc)]
    interface INetworkParams {
        struct Params {
            uint64 chainId;
            uint64 keyVersion;
            bytes32 fhePublicKeyHash;
            bytes32 committeeAggregateKey;
            uint16 committeeThreshold;
            uint16 committeeSize;
            uint32 maxProofBytes;
            uint32 maxCiphertextBytes;
            uint32 maxFeatures;
            uint64 activatedAt;
            bool active;
        }

        function current() external view returns (Params memory);
        function isCurrentKey(bytes32 sPubHash) external view returns (bool);
        function rotationPending() external view returns (bool);
    }
}

/// Event topics.
///
/// Computed with `keccak256` at load time from the exact Solidity signature strings rather
/// than pasted as hex. A hardcoded topic is a silent-failure risk: a typo in one byte means the
/// watcher simply never matches that event, the node idles, and nothing errors. Deriving them
/// makes that class of bug impossible, and it keeps the signatures next to the topics.
pub mod events {
    use alloy::primitives::{keccak256, B256};
    use once_cell::sync::Lazy;

    /// The signatures the node subscribes to. Kept in one place so the filter and the decoders
    /// cannot drift apart.
    pub const SIGNATURES: &[&str] = &[
        "TaskSealed(uint256,bytes32,uint32,uint32)",
        "EpochOpened(uint256,uint32,bytes32,bytes32)",
        "EpochCommitted(uint256,uint32,address,bytes32)",
        "EpochSettled(uint256,uint32,address,uint128)",
        "DisputeReported(uint256,uint32,address,bytes32)",
        "TaskAborted(uint256,bytes4)",
        "ChannelOpened(uint256,uint256,address,address,uint128,uint64)",
        "SliceRedeemed(uint256,address,uint128,uint128,uint256)",
    ];

    fn topic(sig: &str) -> B256 {
        keccak256(sig.as_bytes())
    }

    pub fn task_sealed() -> B256 {
        topic(SIGNATURES[0])
    }
    pub fn epoch_opened() -> B256 {
        topic(SIGNATURES[1])
    }
    pub fn epoch_committed() -> B256 {
        topic(SIGNATURES[2])
    }
    pub fn epoch_settled() -> B256 {
        topic(SIGNATURES[3])
    }
    pub fn dispute_reported() -> B256 {
        topic(SIGNATURES[4])
    }
    pub fn task_aborted() -> B256 {
        topic(SIGNATURES[5])
    }
    pub fn channel_opened() -> B256 {
        topic(SIGNATURES[6])
    }
    pub fn slice_redeemed() -> B256 {
        topic(SIGNATURES[7])
    }

    /// The full set the watcher filters on.
    pub static WATCH: Lazy<Vec<B256>> =
        Lazy::new(|| SIGNATURES.iter().copied().map(topic).collect());

    /// The subset that means "there is work for me to do".
    pub static ACTIONABLE: Lazy<Vec<B256>> =
        Lazy::new(|| vec![task_sealed(), epoch_opened(), dispute_reported()]);

    /// The subset that means "someone else did the work; verify, settle or collect".
    pub static OBSERVABLE: Lazy<Vec<B256>> = Lazy::new(|| {
        vec![
            epoch_committed(),
            epoch_settled(),
            task_aborted(),
            channel_opened(),
            slice_redeemed(),
        ]
    });

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn topics_are_distinct() {
            let mut all = SIGNATURES.iter().copied().map(topic).collect::<Vec<_>>();
            let before = all.len();
            all.sort();
            all.dedup();
            assert_eq!(all.len(), before, "two signatures collide on keccak256");
        }

        #[test]
        fn watch_covers_every_signature() {
            assert_eq!(WATCH.len(), SIGNATURES.len());
            assert_eq!(WATCH.len(), ACTIONABLE.len() + OBSERVABLE.len());
        }
    }
}
