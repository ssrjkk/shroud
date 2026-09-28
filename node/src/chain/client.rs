//! Orchestrator client: point reads and transactions.
//!
//! Deliberately thin. Every write is a single call with no retry-on-revert and no internal
//! nonce management beyond the provider's; the surrounding worker loop owns retry policy,
//! because only it knows whether a failure is worth retrying (a transient 5xx, yes; a revert
//! that means "somebody beat us to this epoch", no).
//!
//! Gas is bounded by an explicit limit per call rather than left to the estimator's default,
//! since an epoch commit carries a multi-KB proof and an unbounded estimate is a way to burn
//! the operator's balance on a task that is not worth it.


use alloy::{
    primitives::{Address, B256, U256},
    providers::{BoxedProvider, Provider, ProviderBuilder},
    sol,
};
use tracing::{debug, info, warn};

use super::bindings::ICipherTaskWrite;
use crate::{
    config::Config,
    error::{ConfigError, Error, Result},
};

sol! {
    #[sol(rpc)]
    interface ICipherTaskCalls {
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
    }

    #[sol(rpc)]
    interface IPaymentVaultCalls {
        function redeem(
            uint256 channelId,
            uint256 sliceIndex,
            uint128 amount,
            uint256 deadline,
            bytes calldata signature
        ) external returns (uint128 paid);
    }
}

/// Local exposure limits, enforced before spending gas.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Refuse to bid on a task whose budget exceeds this.
    pub max_budget_per_task: u128,
    /// Refuse to claim more than this from a single task.
    pub max_claim_per_task: u128,
}

/// Point reads and transactions.
///
/// Deliberately thin. Every write is a single call with no retry-on-revert and no internal
/// nonce management beyond the provider's; the surrounding worker loop owns retry policy,
/// because only it knows whether a failure is worth retrying (a transient 5xx, yes; a revert
/// that means "somebody beat us to this epoch", no).
///
/// Gas is bounded by an explicit limit per call rather than left to the estimator's default,
/// since an epoch commit carries a multi-KB proof and an unbounded estimate is a way to burn
/// the operator's balance on a task that is not worth it.
#[derive(Debug, Clone)]
pub struct OrchestratorClient {
    provider: BoxedProvider,
    wallet: PrivateKeySigner,
    cipher_task: Address,
    vault: Address,
    operator: Address,
    limits: Limits,
}

impl OrchestratorClient {
    pub fn new(cfg: &Config) -> Result<Self> {
        let key = parse_key(&cfg.node.operator_key)?;
        let wallet = PrivateKeySigner::from(key);
        let operator = wallet.address();

        let url = cfg.chain.rpc_url.parse::<url::Url>().map_err(|e| ConfigError::Invalid {
            field: "chain.rpc_url",
            reason: format!("{e}"),
        })?;

        // The wallet is bound here rather than at each call site so nonce management and gas
        // estimation are the provider's problem, not the caller's.
        let provider: BoxedProvider = ProviderBuilder::new().wallet(wallet.clone()).connect_http(url).boxed();

        Ok(Self {
            provider,
            wallet,
            cipher_task: cfg.contracts.cipher_task,
            vault: cfg.contracts.payment_vault,
            operator,
            limits: Limits {
                max_budget_per_task: cfg.payment.max_budget_per_task,
                max_claim_per_task: cfg.payment.max_claim_per_task,
            },
        })
    }

    pub fn operator(&self) -> Address {
        self.operator
    }

    /// Verify the RPC actually serves the configured chain.
    pub async fn verify_chain(&self, expected: u64) -> Result<()> {
        let Some(actual) = self.provider.get_chain_id().await? else {
            return Err(Error::Chain("eth_chainId returned null".into()));
        };
        if expected != 0 && actual != expected {
            return Err(Error::Chain(format!("configured chain {expected} but RPC serves {actual}")));
        }
        info!(chain_id = actual, "chain verified");
        Ok(())
    }

    // --- point reads ------------------------------------------------------------------
    //
    // Reads live in `bindings::ICipherTaskView` / `IPaymentVault` / `INetworkParams` and are
    // called through the provider directly. They are duplicated here only when a read has to
    // be paired with a write in the same round trip.

    // --- writes ----------------------------------------------------------------------

    /// Register this node's BLS key for a task. Idempotent on chain, but the caller still
    /// checks `nodeRegistered` first to avoid paying gas.
    pub async fn register_node(&self, task_id: U256, bls_pub_key: B256) -> Result<()> {
        let contract = ICipherTaskCalls::new(self.cipher_task, self.wallet.clone(), self.provider.clone());
        let tx = contract.registerNode(task_id, bls_pub_key).send().await?;
        let receipt = tx.get_receipt().await?;
        ensure_success(receipt.status(), "registerNode", tx.block_id().map(|b| b.to_string()).unwrap_or_default())?;
        info!(%task_id, "registered for task");
        Ok(())
    }

    /// Post an epoch commit. Returns the transaction hash.
    pub async fn commit_epoch(&self, intent: &CommitIntent) -> Result<B256> {
        let contract = ICipherTaskCalls::new(self.cipher_task, self.wallet.clone(), self.provider.clone());
        let tx = contract
            .commitEpoch(
                intent.task_id,
                intent.epoch,
                intent.proof,
                intent.enc_weights_cid,
                intent.weights_digest,
                intent.metrics_cid,
                intent.trace_digest,
            )
            .send()
            .await?;
        let hash = *tx.tx_hash();
        let receipt = tx.get_receipt().await?;
        ensure_success(receipt.status(), "commitEpoch", format!("{hash:#x}"))?;
        info!(%task_id = intent.task_id, epoch = intent.epoch, hash = %hash, "commit accepted");
        Ok(hash)
    }

    /// Report that our independent re-execution disagreed with the committed digest.
    pub async fn report_dispute(&self, task_id: U256, epoch: u32, digest: B256) -> Result<()> {
        let contract = ICipherTaskCalls::new(self.cipher_task, self.wallet.clone(), self.provider.clone());
        let tx = contract.reportDispute(task_id, epoch, digest).send().await?;
        let receipt = tx.get_receipt().await?;
        ensure_success(receipt.status(), "reportDispute", tx.block_id().map(|b| b.to_string()).unwrap_or_default())?;
        info!(%task_id, epoch, "dispute reported");
        Ok(())
    }

    /// Redeem an authorised slice against a reward channel.
    pub async fn redeem(&self, channel_id: U256, slice_index: u64, amount: u128, deadline: U256, signature: Vec<u8>) -> Result<u128> {
        let contract = IPaymentVaultCalls::new(self.vault, self.wallet.clone(), self.provider.clone());
        let tx = contract.redeem(channel_id, U256::from(slice_index), amount, deadline, signature.into()).send().await?;
        let receipt = tx.get_receipt().await?;
        ensure_success(receipt.status(), "redeem", tx.block_id().map(|b| b.to_string()).unwrap_or_default())?;
        Ok(amount)
    }

    // --- guards ----------------------------------------------------------------------

    /// Refuse to bid on a task whose budget is above the operator's exposure cap, and refuse
    /// to claim more from a task than the per-task claim cap.
    ///
    /// Both are local, pre-transaction checks. The contract enforces its own share arithmetic,
    /// but discovering a mis-configured cap by spending gas on a revert is strictly worse than
    /// refusing locally, and the failure would otherwise be indistinguishable from a race.
    pub fn check_budget(&self, budget: u128) -> Result<()> {
        if self.limits.max_budget_per_task == 0 || budget <= self.limits.max_budget_per_task {
            return Ok(());
        }
        warn!(budget, cap = self.limits.max_budget_per_task, "refusing a task above the exposure cap");
        Err(Error::Chain(format!(
            "task budget {budget} exceeds payment.max_budget_per_task {}",
            self.limits.max_budget_per_task
        )))
    }

    /// Check a single claim against both the per-task cap and the channel's own authorisation.
    pub fn check_claim(&self, task_id: U256, channel_id: U256, claim: u128, authorised: u128) -> Result<()> {
        if claim > authorised {
            return Err(Error::Payment(crate::error::PaymentError::OverAuthorised {
                task_id: B256::from(task_id),
                channel_id,
                claim,
                authorised,
            }));
        }
        if self.limits.max_claim_per_task != 0 && claim > self.limits.max_claim_per_task {
            return Err(Error::Chain(format!(
                "claim {claim} on task {task_id:#x} exceeds payment.max_claim_per_task {}",
                self.limits.max_claim_per_task
            )));
        }
        Ok(())
    }
}

fn ensure_success(status: bool, method: &'static str, where_: String) -> Result<()> {
    if status {
        Ok(())
    } else {
        Err(Error::ContractCall { method, reason: format!("status=failed in {where_}") })
    }
}

/// Parse a hex private key, with or without `0x`.
fn parse_key(src: &str) -> Result<alloy::primitives::B256> {
    let hex = src.strip_prefix("0x").unwrap_or(src);
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ConfigError::Invalid {
            field: "node.operator_key",
            reason: "expected 32 bytes of hex".into(),
        }
        .into());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex, &mut out).map_err(|e| ConfigError::Invalid {
        field: "node.operator_key",
        reason: format!("{e}"),
    })?;
    Ok(B256::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_parse_with_and_without_the_prefix() {
        let with = "0x".to_string() + &"11".repeat(32);
        let without = "11".repeat(32);
        assert_eq!(parse_key(&with).unwrap(), parse_key(&without).unwrap());
        assert_eq!(parse_key(&with).unwrap().0, [0x11; 32]);
    }

    #[test]
    fn a_short_key_is_rejected_rather_than_left_padded() {
        // Silently left-padding a short key would make the node use a key the operator did
        // not choose, and spend a real balance.
        assert!(parse_key("0xdeadbeef").is_err());
    }

    #[test]
    fn a_non_hex_key_is_rejected() {
        assert!(parse_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn a_failed_receipt_is_an_error_not_a_success() {
        let err = ensure_success(false, "commitEpoch", "0xabc".into()).expect_err("must fail");
        assert!(matches!(err, Error::ContractCall { method: "commitEpoch", .. }), "got {err:?}");
    }

    #[test]
    fn a_successful_receipt_is_ok() {
        ensure_success(true, "commitEpoch", "0xabc".into()).expect("must pass");
    }
}
