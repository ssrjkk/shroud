//! Orchestrator client: point reads and transactions.
//!
//! Deliberately thin. Every write is a single call with no retry-on-revert and no internal
//! nonce management beyond the provider's; the surrounding worker loop owns retry policy,
//! because only it knows whether a failure is worth retrying (a transient 5xx, yes; a revert
//! that means "somebody beat us to this epoch", no).
//!
//! Two rules this module exists to enforce:
//!
//! * **Nothing is reported as paid that the chain did not pay.** A Solidity return value is not
//!   in the receipt we wait for, so `redeem` re-reads the channel and reports the delta of
//!   `withdrawn` — which is what the contract moved, not what we asked it to move. The same
//!   reasoning gives `reclaim` and `claim` their amounts from the chain's own state.
//! * **A write that we can already see will revert is not sent.** Each money path reads the
//!   state the contract is about to check (channel owner, slice monotonicity, remaining
//!   authorisation, `pendingWithdrawal`) and refuses locally, because a reverted transaction
//!   still costs the operator real gas.
//!
//! The ABI lives entirely in [`super::bindings`]; this module instantiates it. Two copies of one
//! ABI is how a binding and a call site drift apart without either failing to compile.

use alloy::{
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use tracing::{info, warn};

use crate::{
    chain::{
        bindings::{ICipherTaskView, ICipherTaskWrite, INetworkParams, IPaymentVault, IERC20},
        parse_rpc_url,
        slice::{BLOB_BYTES, SLICE_DEADLINE},
    },
    config::Config,
    error::{ConfigError, Error, PaymentError, Result},
};

/// Parameters for a single `commitEpoch` call.
#[derive(Debug, Clone)]
pub struct CommitIntent {
    pub task_id: U256,
    pub epoch: u32,
    pub proof: B256,
    pub enc_weights_cid: B256,
    pub weights_digest: B256,
    pub metrics_cid: B256,
    pub trace_digest: B256,
}

/// Local exposure limits, enforced before spending gas.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Refuse to bid on a task whose budget exceeds this.
    pub max_budget_per_task: u128,
    /// Refuse to claim more than this from a single task.
    pub max_claim_per_task: u128,
}

/// A `PaymentVault.Channel` as the chain holds it right now.
///
/// Copied out of the generated struct so the rest of the crate reads snake_case and so a
/// comparison against the folded state is explicit rather than a field-by-field surprise.
///
/// `Default` is the shape the vault returns for a channel id it has never seen: every field zero,
/// including `node`, so "unreadable" and "not ours" are distinguishable from "ours".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelOnChain {
    pub node: Address,
    pub streamer: Address,
    pub task_id: U256,
    pub max_cumulative: u128,
    pub withdrawn: u128,
    /// Next slice index the contract will accept.
    pub consumed: u64,
    pub unlock_at: u64,
    pub closed: bool,
}

impl ChannelOnChain {
    /// What the channel still authorises: `maxCumulative - withdrawn`.
    pub fn remaining(&self) -> u128 {
        self.max_cumulative.saturating_sub(self.withdrawn)
    }

    /// `true` when slice `index` is still redeemable under the contract's monotonicity rule
    /// (`if (sliceIndex < ch.consumed) revert SliceNotMonotonic`).
    pub fn accepts_slice(&self, index: u64) -> bool {
        index >= self.consumed
    }
}

/// An `ICipherTask.Task` reduced to what a write decision needs.
///
/// Only the fields that gate a transaction are copied: `status`, `locked`, `nextEpoch` and
/// `params.epochs` decide `settle`; `epochDeadline + params.disputeWindow` decides
/// `finalizeEpoch`; `budget` decides whether the task is inside the operator's exposure cap.
/// Anything else the node derives from logs instead.
///
/// `Default` is the all-zero task the orchestrator returns for an id it has never seen, which the
/// worker's gates read as "nothing is open here".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TaskOnChain {
    pub status: u8,
    pub budget: u128,
    pub locked: u128,
    /// Deadline for the currently open epoch, `0` when none is open.
    pub epoch_deadline: u64,
    pub dispute_window: u32,
    pub epoch_duration: u32,
    /// `params.epochs`: the total the buyer asked for.
    pub epochs: u32,
    pub next_epoch: u32,
    pub ct_root: B256,
    pub last_weights_cid: B256,
    pub last_weights_digest: B256,
    pub contributors: u32,
    pub shards: u32,
    pub is_sealed: bool,
    /// `params.features`: lanes per row. The execution engine decodes shards against this;
    /// a mismatch is a shape error, never a reinterpretation.
    pub features: u32,
}

impl TaskOnChain {
    /// The chain time at which the epoch the contract is running becomes finalizable.
    ///
    /// `finalizeEpoch` requires `block.timestamp >= epochDeadline + disputeWindow` unless the
    /// dispute quorum has already been reached, so this is the earliest block that can succeed.
    pub fn finalize_ready_at(&self) -> u64 {
        self.epoch_deadline
            .saturating_add(self.dispute_window as u64)
    }
}

/// A `Contribution` as the chain holds it, reduced to what re-execution needs:
///
/// the CID locates the bytes in the DA layer and the digest proves they are the bytes the
/// contributor committed. `accepted` is carried so the worker never executes on a shard
/// the contract rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContributionOnChain {
    pub contributor: Address,
    pub ciphertext_cid: B256,
    pub ct_digest: B256,
    pub accepted: bool,
}

/// An `EpochCommit` as the chain holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOnChain {
    pub trace_digest: B256,
    pub committed_at: u64,
    pub verified: bool,
}

/// Point reads and transactions for the orchestrator, the vault, and the network params.
#[derive(Debug, Clone)]
pub struct OrchestratorClient {
    provider: DynProvider,
    cipher_task: Address,
    vault: Address,
    network_params: Address,
    operator: Address,
    limits: Limits,
    redeem_gas: u64,
}

/// Send a transaction, wait for its receipt, and fail loudly on a reverted status.
///
/// Every write in this crate is this one sequence, so it is a macro rather than a generic
/// helper: the `CallBuilder` type is parameterised by the generated call type, and naming it in
/// a trait bound would tie this module to codegen internals for no benefit.
macro_rules! submit_tx {
    ($call:expr, $gas:expr, $method:literal) => {{
        let builder = $call;
        let builder = match $gas {
            Some(limit) => builder.gas(limit),
            None => builder,
        };
        let pending = builder.send().await.map_err(Error::alloy)?;
        let hash = *pending.tx_hash();
        let receipt = pending.get_receipt().await.map_err(Error::alloy)?;
        ensure_success(receipt.status(), $method, format!("{hash:#x}"))?;
        hash
    }};
}

impl OrchestratorClient {
    pub fn new(cfg: &Config) -> Result<Self> {
        let key = parse_key(&cfg.node.operator_key)?;
        let wallet = PrivateKeySigner::from_bytes(&key).map_err(|e| ConfigError::Invalid {
            field: "node.operator_key",
            reason: format!("{e}"),
        })?;
        let operator = wallet.address();

        let provider: DynProvider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(parse_rpc_url(&cfg.chain.rpc_url)?)
            .erased();

        Ok(Self {
            provider,
            cipher_task: cfg.contracts.cipher_task,
            vault: cfg.contracts.payment_vault,
            network_params: cfg.contracts.network_params,
            operator,
            limits: Limits {
                max_budget_per_task: u128::from(cfg.payment.max_budget_per_task),
                max_claim_per_task: u128::from(cfg.payment.max_claim_per_task),
            },
            redeem_gas: cfg.payment.redeem_gas_limit,
        })
    }

    pub fn operator(&self) -> Address {
        self.operator
    }

    pub fn cipher_task(&self) -> Address {
        self.cipher_task
    }

    pub fn vault(&self) -> Address {
        self.vault
    }

    /// Verify the RPC actually serves the configured chain.
    pub async fn verify_chain(&self, expected: u64) -> Result<()> {
        let actual = self.provider.get_chain_id().await.map_err(Error::alloy)?;
        if expected != 0 && actual != expected {
            return Err(Error::Chain(format!(
                "configured chain {expected} but RPC serves {actual}"
            )));
        }
        info!(chain_id = actual, "chain verified");
        Ok(())
    }

    // --- point reads ------------------------------------------------------------------

    /// `(number, timestamp)` of the latest block.
    ///
    /// `timestamp` is the chain clock, and every deadline the node compares against —
    /// `channel.unlockAt`, the `redeem` deadline — is a `block.timestamp`, not wall-clock time.
    /// An operator with a skewed machine clock would otherwise reclaim early and pay gas for a
    /// `TooEarly` revert, or wait for a window that already closed.
    pub async fn latest_block(&self) -> Result<(u64, u64)> {
        let block = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
            .map_err(Error::alloy)?
            .ok_or_else(|| Error::Chain("latest block not available".into()))?;
        Ok((block.header.number, block.header.timestamp))
    }

    /// Whether the chain has this node registered on the task.
    ///
    /// This is the authority for `state::TaskState::registered`: a reorg replay cannot know
    /// whether our `registerNode` survived, but the contract does.
    pub async fn is_registered(&self, task_id: U256) -> Result<bool> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        c.nodeRegistered(task_id, self.operator)
            .call()
            .await
            .map_err(Error::alloy)
    }

    /// Our commit for an epoch, or `None` if we never committed.
    ///
    /// An unset `EpochCommit` is all zeroes, and a real commit always carries
    /// `committedAt = block.timestamp > 0`, so a zero timestamp is the absence test: `commitEpoch`
    /// writes `committedAt = block.timestamp` and rejects an epoch whose digest is empty.
    pub async fn commit_of(
        &self,
        task_id: U256,
        epoch: u32,
        node: Address,
    ) -> Result<Option<CommitOnChain>> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        let commit = c
            .commits(task_id, epoch, node)
            .call()
            .await
            .map_err(Error::alloy)?;
        if commit.committedAt == 0 {
            return Ok(None);
        }
        Ok(Some(CommitOnChain {
            trace_digest: commit.traceDigest,
            committed_at: commit.committedAt,
            verified: commit.verified,
        }))
    }

    /// The task's current status byte, for the pre-write check in the worker loop.
    pub async fn status_of(&self, task_id: U256) -> Result<u8> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        c.statusOf(task_id).call().await.map_err(Error::alloy)
    }

    /// The channel the contract opened for `epoch` of `task_id`. `U256::ZERO` means none.
    pub async fn epoch_channel(&self, task_id: U256, epoch: u32) -> Result<U256> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        c.epochChannel(task_id, epoch)
            .call()
            .await
            .map_err(Error::alloy)
    }

    /// The node the contract will pay for `epoch`, once it has a winner.
    pub async fn epoch_winner(&self, task_id: U256, epoch: u32) -> Result<Address> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        c.epochWinner(task_id, epoch)
            .call()
            .await
            .map_err(Error::alloy)
    }

    /// The task as the contract holds it, for the pre-write gates in the worker.
    ///
    /// `finalizeEpoch` and `settleFrom` both revert on a status or a cursor the node can read
    /// first, and both take a `taskId` the fold only knows approximately — so the worker reads
    /// this rather than discovering the mismatch through a failed transaction.
    pub async fn task(&self, task_id: U256) -> Result<TaskOnChain> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        let t = c.tasks(task_id).call().await.map_err(Error::alloy)?;
        Ok(TaskOnChain {
            status: t.status,
            budget: t.budget,
            locked: t.locked,
            epoch_deadline: t.epochDeadline,
            dispute_window: t.params.disputeWindow,
            epoch_duration: t.params.epochDuration,
            epochs: t.params.epochs,
            next_epoch: t.nextEpoch,
            ct_root: t.ctRoot,
            last_weights_cid: t.lastWeightsCid,
            last_weights_digest: t.lastWeightsDigest,
            contributors: t.contributors,
            shards: t.shards,
            is_sealed: t.isSealed,
            features: t.params.features,
        })
    }

    /// The contributor address recorded for `leafIndex` of `task_id`.
    ///
    /// Leaves are positional (`0..shards`), so the worker walks them in order and resolves
    /// each one to the address whose `contributions` entry pins its bytes.
    pub async fn contribution_of(&self, task_id: U256, leaf_index: u32) -> Result<Address> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        c.contributionOf(task_id, U256::from(leaf_index))
            .call()
            .await
            .map_err(Error::alloy)
    }

    /// The contribution `contributor` made to `task_id`: CID, digest and acceptance.
    ///
    /// The worker verifies `keccak256(bytes) == ct_digest` after fetching from the DA
    /// layer, so a store that serves wrong bytes is caught before the engine runs.
    pub async fn contribution(
        &self,
        task_id: U256,
        contributor: Address,
    ) -> Result<ContributionOnChain> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        let s = c
            .contributions(task_id, contributor)
            .call()
            .await
            .map_err(Error::alloy)?;
        Ok(ContributionOnChain {
            contributor,
            ciphertext_cid: s.ciphertextCid,
            ct_digest: s.ctDigest,
            accepted: s.accepted,
        })
    }

    /// Index of the first contributor `settleFrom` has not yet paid.
    ///
    /// A page may only continue an unfinished settlement (`cursor != _settlement.cursor` reverts
    /// `SettleCursorMismatch`), so settling means resuming at exactly this number rather than at
    /// a remembered one.
    pub async fn settle_cursor(&self, task_id: U256) -> Result<U256> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        c.settleCursor(task_id).call().await.map_err(Error::alloy)
    }

    /// The `ctRoot` the contract sealed for this task.
    pub async fn ct_root(&self, task_id: U256) -> Result<B256> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        c.ctRootOf(task_id).call().await.map_err(Error::alloy)
    }

    /// `(need, have)` of the dispute quorum for the epoch the contract is currently running.
    ///
    /// `disputeQuorum` reports `_disputeCount[taskId][t.nextEpoch]`, so `have` counts the epoch
    /// `finalizeEpoch` would close — the same epoch, not the one the fold last saw open. The
    /// quorum is the only path that ends an epoch's dispute window early, so a node that cannot
    /// read it would either finalize too late or pay gas for a `DisputeBelowQuorum` revert.
    pub async fn dispute_quorum(&self, task_id: U256) -> Result<(U256, U256)> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        let q = c
            .disputeQuorum(task_id)
            .call()
            .await
            .map_err(Error::alloy)?;
        Ok((q.need, q.have))
    }

    /// Contributors paid per settlement call (`CipherTask.SETTLE_PAGE_SIZE`).
    ///
    /// Read rather than hardcoded so a future paging change moves the node with it. The
    /// worker uses it to recognise the final page — the only page gated on reward-channel
    /// maturity (F-22) — without guessing from a constant that lives in another repo layer.
    pub async fn settle_page_size(&self) -> Result<U256> {
        let c = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        c.SETTLE_PAGE_SIZE().call().await.map_err(Error::alloy)
    }

    /// Channel ids the vault opened for `task_id`, in opening order.
    pub async fn channel_ids(&self, task_id: U256) -> Result<Vec<U256>> {
        let v = IPaymentVault::new(self.vault, self.provider.clone());
        v.channelIds(task_id).call().await.map_err(Error::alloy)
    }

    /// Whether `task_id` still has an open reward channel whose window has not matured.
    ///
    /// Consulted before the final settlement page only: earlier pages pay contributors from
    /// the frozen pool, which node locks can never eat into, so they must not wait.
    pub async fn has_immature_channels(&self, task_id: U256) -> Result<bool> {
        let v = IPaymentVault::new(self.vault, self.provider.clone());
        v.hasImmatureChannels(task_id)
            .call()
            .await
            .map_err(Error::alloy)
    }

    /// Earliest chain time at which no channel of `task_id` is immature anymore.
    ///
    /// `None` means nothing is outstanding and the final page may run now. This is what the
    /// worker waits for instead of burning gas on a `ChannelsImmature` revert every poll for
    /// the whole reward window.
    pub async fn immature_until(&self, task_id: U256, now: u64) -> Result<Option<u64>> {
        let mut until: Option<u64> = None;
        for id in self.channel_ids(task_id).await? {
            let ch = self.channel(id).await?;
            if !ch.closed && ch.unlock_at > now {
                until = Some(until.map_or(ch.unlock_at, |u: u64| u.min(ch.unlock_at)));
            }
        }
        Ok(until)
    }

    /// Full channel state as the vault holds it.
    pub async fn channel(&self, channel_id: U256) -> Result<ChannelOnChain> {
        let v = IPaymentVault::new(self.vault, self.provider.clone());
        let ch = v
            .channelInfo(channel_id)
            .call()
            .await
            .map_err(Error::alloy)?;
        Ok(ChannelOnChain {
            node: ch.node,
            streamer: ch.streamer,
            task_id: ch.taskId,
            max_cumulative: ch.maxCumulative,
            withdrawn: ch.withdrawn,
            consumed: ch.consumed,
            unlock_at: ch.unlockAt,
            closed: ch.closed,
        })
    }

    /// Tokens credited to an account and not yet claimed.
    pub async fn pending_withdrawal(&self, account: Address) -> Result<U256> {
        let v = IPaymentVault::new(self.vault, self.provider.clone());
        v.pendingWithdrawal(account)
            .call()
            .await
            .map_err(Error::alloy)
    }

    /// The FHE public key hash the network is currently using.
    pub async fn current_key_hash(&self) -> Result<B256> {
        let p = INetworkParams::new(self.network_params, self.provider.clone());
        let ret = p.current().call().await.map_err(Error::alloy)?;
        Ok(ret.fhePublicKeyHash)
    }

    /// Refuse to run an epoch against a key the network does not recognise.
    ///
    /// This is what `node.enforce_key_pin` means. A node whose local params are stale produces
    /// ciphertexts under a superseded key: the epoch still executes, the digest still looks
    /// plausible, and the mismatch only surfaces when the committee cannot decrypt the result —
    /// after the node has been paid and the task has been sealed. So the check gates start-up,
    /// and it is a hard error rather than a warning.
    pub async fn verify_key_pin(&self, cfg: &Config) -> Result<()> {
        if !cfg.node.enforce_key_pin {
            // Loud, not silent: without the pin nothing would notice a substituted `s_pub`
            // (threat model F-08) — the node would train under the attacker's key and look
            // healthy doing it. Operators who accept that must do so knowingly.
            warn!("node.enforce_key_pin is off; the on-chain FHE key is NOT checked — a substituted s_pub would go undetected");
            return Ok(());
        }
        let local = cfg.fhe.public_key_hash.ok_or(ConfigError::Missing {
            field: "fhe.public_key_hash",
            reason: Some("node.enforce_key_pin is on, so the node needs the local keccak(s_pub) to compare against the on-chain pin"),
        })?;
        if self.network_params.is_zero() {
            return Err(ConfigError::Missing {
                field: "contracts.network_params",
                reason: Some("node.enforce_key_pin is on, so the node needs the NetworkParams contract to read the on-chain pin from"),
            }
            .into());
        }
        let on_chain = self.current_key_hash().await?;
        if on_chain != local {
            return Err(Error::KeyPinMismatch { on_chain, local });
        }
        info!(key_hash = %on_chain, "local FHE params match the chain");
        Ok(())
    }

    // --- writes ----------------------------------------------------------------------

    /// Register this node's BLS key for a task. Idempotent on chain, but the caller still
    /// checks `nodeRegistered` first to avoid paying gas.
    ///
    /// Registration pulls the bond from the operator into the vault, so the vault must be
    /// approved first — the same two-step pattern as the buyer's escrow. The approval is for
    /// `MaxUint256`, also like the buyer's: one approval covers every future task, and the
    /// vault can only pull `REGISTRATION_BOND` per registration.
    pub async fn register_node(&self, task_id: U256, bls_pub_key: B256) -> Result<B256> {
        self.ensure_bond_allowance().await?;
        let contract = ICipherTaskWrite::new(self.cipher_task, self.provider.clone());
        let hash = submit_tx!(
            contract.registerNode(task_id, bls_pub_key),
            None,
            "registerNode"
        );
        info!(%task_id, %hash, "registered for task");
        Ok(hash)
    }

    /// The bond `registerNode` pulls, read from the vault so the node never hardcodes money.
    pub async fn registration_bond(&self) -> Result<u128> {
        let vault = IPaymentVault::new(self.vault, self.provider.clone());
        vault.REGISTRATION_BOND().call().await.map_err(Error::alloy)
    }

    /// This operator's bond on a task, or zero when never posted, released or slashed.
    pub async fn node_bond(&self, task_id: U256, node: Address) -> Result<u128> {
        let vault = IPaymentVault::new(self.vault, self.provider.clone());
        vault
            .nodeBond(task_id, node)
            .call()
            .await
            .map_err(Error::alloy)
    }

    /// Release our bond once the task can no longer slash it. The contract decides
    /// releasability; the worker checks the bond is still there first (see `release_gate`), so
    /// this sends only when the call is expected to succeed.
    pub async fn release_bond(&self, task_id: U256) -> Result<B256> {
        let vault = IPaymentVault::new(self.vault, self.provider.clone());
        let hash = submit_tx!(
            vault.releaseBond(task_id, self.operator),
            None,
            "releaseBond"
        );
        info!(%task_id, %hash, "registration bond released");
        Ok(hash)
    }

    /// Approve the vault to pull registration bonds, unless it already may.
    ///
    /// Checked rather than blindly sent: an approval is a transaction like any other, and one
    /// per operator lifetime is enough.
    async fn ensure_bond_allowance(&self) -> Result<()> {
        let bond = self.registration_bond().await?;
        let task = ICipherTaskView::new(self.cipher_task, self.provider.clone());
        let token = task.escrowToken().call().await.map_err(Error::alloy)?;
        let erc20 = IERC20::new(token, self.provider.clone());
        let allowance: U256 = erc20
            .allowance(self.operator, self.vault)
            .call()
            .await
            .map_err(Error::alloy)?;
        if allowance >= U256::from(bond) {
            return Ok(());
        }
        let hash = submit_tx!(erc20.approve(self.vault, U256::MAX), None, "approve");
        info!(token = %token, bond, %hash, "vault approved for registration bonds");
        Ok(())
    }

    /// Post an epoch commit. Returns the transaction hash.
    pub async fn commit_epoch(&self, intent: &CommitIntent) -> Result<B256> {
        let contract = ICipherTaskWrite::new(self.cipher_task, self.provider.clone());
        let hash = submit_tx!(
            contract.commitEpoch(
                intent.task_id,
                intent.epoch,
                intent.proof,
                intent.enc_weights_cid,
                intent.weights_digest,
                intent.metrics_cid,
                intent.trace_digest,
            ),
            None,
            "commitEpoch"
        );
        info!(task_id = %intent.task_id, epoch = intent.epoch, %hash, "commit accepted");
        Ok(hash)
    }

    /// Report that our independent re-execution disagreed with the committed digest.
    pub async fn report_dispute(&self, task_id: U256, epoch: u32, digest: B256) -> Result<B256> {
        let contract = ICipherTaskWrite::new(self.cipher_task, self.provider.clone());
        let hash = submit_tx!(
            contract.reportDispute(task_id, epoch, digest),
            None,
            "reportDispute"
        );
        info!(%task_id, epoch, %hash, "dispute reported");
        Ok(hash)
    }

    /// Commit to a dispute digest without revealing it (commit-reveal front half).
    ///
    /// `commitment` must be `transcript::dispute_commitment(digest, salt, operator)`. The
    /// digest stays hidden until the reveal, so a mempool observer cannot copy the report
    /// into its own dispute for free.
    pub async fn commit_dispute(
        &self,
        task_id: U256,
        epoch: u32,
        commitment: B256,
    ) -> Result<B256> {
        let contract = ICipherTaskWrite::new(self.cipher_task, self.provider.clone());
        let hash = submit_tx!(
            contract.commitDispute(task_id, epoch, commitment),
            None,
            "commitDispute"
        );
        info!(%task_id, epoch, %hash, "dispute committed");
        Ok(hash)
    }

    /// Reveal a committed dispute digest (commit-reveal back half).
    pub async fn report_dispute_with_salt(
        &self,
        task_id: U256,
        epoch: u32,
        digest: B256,
        salt: B256,
    ) -> Result<B256> {
        let contract = ICipherTaskWrite::new(self.cipher_task, self.provider.clone());
        let hash = submit_tx!(
            contract.reportDisputeWithSalt(task_id, epoch, digest, salt),
            None,
            "reportDisputeWithSalt"
        );
        info!(%task_id, epoch, %hash, "dispute revealed");
        Ok(hash)
    }

    /// Close an epoch's dispute window: pays the winner and opens its reward channel.
    ///
    /// Callable by anyone, so this is a race rather than a right; the worker sends it because
    /// nobody else has an incentive to, not because only it may.
    pub async fn finalize_epoch(&self, task_id: U256, epoch: u32) -> Result<B256> {
        let contract = ICipherTaskWrite::new(self.cipher_task, self.provider.clone());
        let hash = submit_tx!(
            contract.finalizeEpoch(task_id, epoch),
            None,
            "finalizeEpoch"
        );
        info!(%task_id, epoch, %hash, "epoch finalized");
        Ok(hash)
    }

    /// Distribute a finished task's escrow.
    pub async fn settle(&self, task_id: U256) -> Result<B256> {
        let contract = ICipherTaskWrite::new(self.cipher_task, self.provider.clone());
        let hash = submit_tx!(contract.settle(task_id), None, "settle");
        info!(%task_id, %hash, "settle step accepted");
        Ok(hash)
    }

    /// Resume settling from a cursor, for a task whose full loop would exceed the block gas
    /// limit. `settle` and `settleFrom` are the same loop; the cursor only bounds it.
    pub async fn settle_from(&self, task_id: U256, cursor: U256) -> Result<B256> {
        let contract = ICipherTaskWrite::new(self.cipher_task, self.provider.clone());
        let hash = submit_tx!(contract.settleFrom(task_id, cursor), None, "settleFrom");
        info!(%task_id, %cursor, %hash, "settle step accepted");
        Ok(hash)
    }

    /// Redeem an authorised slice against a reward channel.
    ///
    /// Returns `(tx hash, what the chain actually paid)`. The paid figure is the delta of the
    /// channel's `withdrawn` across the transaction, because `redeem` legitimately pays zero when
    /// the requested cumulative is at or below what the channel already holds: reporting the
    /// *requested* amount as earned would make a replay look like income.
    pub async fn redeem(
        &self,
        channel_id: U256,
        slice_index: u64,
        amount: u128,
        blob: &[u8; BLOB_BYTES],
    ) -> Result<(B256, u128)> {
        let before = self.channel(channel_id).await?;
        self.check_channel_winnable(channel_id, &before, slice_index, amount)?;

        let contract = IPaymentVault::new(self.vault, self.provider.clone());
        let hash = submit_tx!(
            contract.redeem(
                channel_id,
                U256::from(slice_index),
                amount,
                SLICE_DEADLINE,
                alloy::primitives::Bytes::copy_from_slice(blob),
            ),
            Some(self.redeem_gas),
            "redeem"
        );

        let after = self.channel(channel_id).await?;
        let paid = paid_delta(before.withdrawn, after.withdrawn);
        if paid == 0 {
            warn!(
                channel = %channel_id,
                slice_index,
                requested = amount,
                "redeem consumed the slice but paid nothing"
            );
        }
        info!(channel = %channel_id, slice_index, paid, %hash, "slice redeemed");
        Ok((hash, paid))
    }

    /// Reclaim a fully drawn channel once `unlockAt` has passed.
    ///
    /// The node's own `redeem` path leaves the channel open with the lock still recorded, and
    /// `reclaim` is what returns the residue and marks it closed. It only pays what the contract
    /// says is left, which is why the amount is read rather than assumed.
    pub async fn reclaim(&self, channel_id: U256) -> Result<(B256, u128)> {
        let before = self.channel(channel_id).await?;
        let (_, now) = self.latest_block().await?;
        self.check_reclaimable(channel_id, &before, now)?;
        let expected = before.remaining();

        let contract = IPaymentVault::new(self.vault, self.provider.clone());
        let hash = submit_tx!(
            contract.reclaim(channel_id),
            Some(self.redeem_gas),
            "reclaim"
        );
        info!(channel = %channel_id, reclaimed = expected, %hash, "channel reclaimed");
        Ok((hash, expected))
    }

    /// Pull `pendingWithdrawal` for the operator into its wallet.
    ///
    /// Both `redeem` and `reclaim` *credit* rather than transfer, so until this lands the node
    /// has earned tokens it does not hold.
    pub async fn claim(&self) -> Result<(B256, U256)> {
        let expected = self.pending_withdrawal(self.operator).await?;
        if expected.is_zero() {
            return Err(Error::Payment(PaymentError::Reverted {
                reason: format!("nothing to claim for {}", self.operator),
            }));
        }
        let contract = IPaymentVault::new(self.vault, self.provider.clone());
        let hash = submit_tx!(contract.claim(), Some(self.redeem_gas), "claim");
        info!(amount = %expected, %hash, "withdrawal claimed");
        Ok((hash, expected))
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
        warn!(
            budget,
            cap = self.limits.max_budget_per_task,
            "refusing a task above the exposure cap"
        );
        Err(Error::Chain(format!(
            "task budget {budget} exceeds payment.max_budget_per_task {}",
            self.limits.max_budget_per_task
        )))
    }

    /// Check a single claim against both the per-task cap and the channel's own authorisation.
    pub fn check_claim(
        &self,
        task_id: U256,
        channel_id: U256,
        claim: u128,
        authorised: u128,
    ) -> Result<()> {
        if claim > authorised {
            return Err(Error::Payment(PaymentError::OverAuthorised {
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

    /// Everything `redeem` requires of the channel, checked before the transaction is sent.
    fn check_channel_winnable(
        &self,
        channel_id: U256,
        ch: &ChannelOnChain,
        slice_index: u64,
        amount: u128,
    ) -> Result<()> {
        if ch.node != self.operator {
            return Err(Error::Payment(PaymentError::NotOurs {
                channel_id,
                node: ch.node,
                ours: self.operator,
            }));
        }
        if ch.closed {
            return Err(Error::Payment(PaymentError::Reverted {
                reason: format!("channel {channel_id} is closed"),
            }));
        }
        // A channel we have already drawn in full has nothing left to redeem; the contract would
        // accept the call and pay zero, which is a waste of gas rather than an error.
        if ch.remaining() == 0 {
            return Err(Error::Payment(PaymentError::OverAuthorised {
                task_id: B256::from(ch.task_id),
                channel_id,
                claim: amount,
                authorised: ch.withdrawn,
            }));
        }
        if !ch.accepts_slice(slice_index) {
            return Err(Error::Payment(PaymentError::SliceReplayed {
                index: slice_index,
                consumed: ch.consumed,
            }));
        }
        self.check_claim(ch.task_id, channel_id, amount, ch.max_cumulative)
    }

    /// Everything `reclaim` requires of the channel, checked against chain state and chain time.
    fn check_reclaimable(&self, channel_id: U256, ch: &ChannelOnChain, now: u64) -> Result<()> {
        if ch.node != self.operator {
            return Err(Error::Payment(PaymentError::NotOurs {
                channel_id,
                node: ch.node,
                ours: self.operator,
            }));
        }
        if ch.closed {
            return Err(Error::Payment(PaymentError::Reverted {
                reason: format!("channel {channel_id} is already closed"),
            }));
        }
        if now < ch.unlock_at {
            return Err(Error::Payment(PaymentError::Reverted {
                reason: format!(
                    "channel {channel_id} unlocks at {}, chain time is {now}",
                    ch.unlock_at
                ),
            }));
        }
        Ok(())
    }
}

/// The delta the chain moved, never negative.
///
/// `withdrawn` only ever grows (`redeem` sets it to the requested cumulative and reverts if the
/// request is below it), so a backwards read means the two reads straddled a reorg rather than a
/// payment. Returning zero in that case keeps the accounting conservative: the node under-reports
/// what it earned instead of inventing income.
pub fn paid_delta(before: u128, after: u128) -> u128 {
    after.saturating_sub(before)
}

fn ensure_success(status: bool, method: &'static str, where_: String) -> Result<()> {
    if status {
        Ok(())
    } else {
        Err(Error::ContractCall {
            method,
            reason: format!("status=failed in {where_}"),
        })
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
    use alloy::primitives::address;

    /// The key `hardhat #0`, and the address it derives to. Both appear in the captured logs the
    /// watcher tests use, so the operator identity in these tests is a real one rather than a
    /// fabricated constant.
    const KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn client() -> OrchestratorClient {
        let mut cfg = Config::default();
        cfg.node.operator_key = KEY.into();
        cfg.contracts.cipher_task = address!("0x00000000000000000000000000000000000000aa");
        cfg.contracts.payment_vault = address!("0x00000000000000000000000000000000000000bb");
        cfg.contracts.network_params = address!("0x00000000000000000000000000000000000000cc");
        OrchestratorClient::new(&cfg).expect("a well-formed config builds a client")
    }

    fn channel(node: Address) -> ChannelOnChain {
        ChannelOnChain {
            node,
            streamer: address!("0x00000000000000000000000000000000000000aa"),
            task_id: U256::from(7),
            max_cumulative: 75_000_000,
            withdrawn: 0,
            consumed: 0,
            unlock_at: 1_800,
            closed: false,
        }
    }

    #[test]
    fn keys_parse_with_and_without_the_prefix() {
        let with = "0x".to_string() + &"11".repeat(32);
        let without = "11".repeat(32);
        assert_eq!(parse_key(&with).unwrap(), parse_key(&without).unwrap());
        assert_eq!(parse_key(&with).unwrap().0, [0x11; 32]);
    }

    #[test]
    fn a_short_key_is_rejected_rather_than_left_padded() {
        assert!(parse_key("0xdeadbeef").is_err());
    }

    #[test]
    fn a_non_hex_key_is_rejected() {
        assert!(parse_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn a_failed_receipt_is_an_error_not_a_success() {
        let err = ensure_success(false, "commitEpoch", "0xabc".into()).expect_err("must fail");
        assert!(
            matches!(
                err,
                Error::ContractCall {
                    method: "commitEpoch",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn a_successful_receipt_is_ok() {
        ensure_success(true, "commitEpoch", "0xabc".into()).expect("must pass");
    }

    #[test]
    fn the_operator_address_is_derived_from_the_key() {
        let c = client();
        assert_eq!(
            c.operator(),
            // hardhat #0
            address!("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        );
    }

    #[test]
    fn paid_never_reports_income_the_chain_did_not_move() {
        assert_eq!(paid_delta(0, 75_000_000), 75_000_000);
        assert_eq!(paid_delta(75_000_000, 75_000_000), 0);
        // A backwards read is a reorg, not a payment: reporting the difference as a negative or
        // as the requested amount would both be wrong.
        assert_eq!(paid_delta(100, 40), 0);
    }

    #[test]
    fn a_channel_accepts_its_first_slice_and_no_replay_of_it() {
        let ch = channel(client().operator());
        assert!(ch.accepts_slice(0));
        assert_eq!(ch.remaining(), 75_000_000);
        let drawn = ChannelOnChain {
            consumed: 1,
            withdrawn: 75_000_000,
            ..ch
        };
        assert!(!drawn.accepts_slice(0), "slice 0 is spent");
        assert_eq!(drawn.remaining(), 0);
    }

    #[test]
    fn redeeming_someone_elses_channel_is_refused_before_gas_is_spent() {
        let c = client();
        let foreign = channel(address!("0x70997970c51812dc3a010c7d01b50e0d17dc79c8"));
        let err = c
            .check_channel_winnable(U256::from(1), &foreign, 0, 75_000_000)
            .expect_err("must refuse");
        assert!(
            matches!(err, Error::Payment(PaymentError::NotOurs { .. })),
            "got {err:?}"
        );
    }

    #[test]
    fn redeeming_more_than_the_channel_authorises_is_refused() {
        let c = client();
        let ours = channel(c.operator());
        let err = c
            .check_channel_winnable(U256::from(1), &ours, 0, 75_000_001)
            .expect_err("over-claim must be refused");
        assert!(
            matches!(
                err,
                Error::Payment(PaymentError::OverAuthorised {
                    claim: 75_000_001,
                    authorised: 75_000_000,
                    ..
                })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn a_spent_channel_is_not_redeemed_again() {
        let c = client();
        let spent = ChannelOnChain {
            withdrawn: 75_000_000,
            consumed: 1,
            ..channel(c.operator())
        };
        let err = c
            .check_channel_winnable(U256::from(1), &spent, 0, 75_000_000)
            .expect_err("nothing left to draw");
        assert!(
            matches!(
                err,
                Error::Payment(PaymentError::OverAuthorised {
                    authorised: 75_000_000,
                    ..
                })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn a_closed_channel_is_neither_redeemable_nor_reclaimable() {
        let c = client();
        let closed = ChannelOnChain {
            closed: true,
            ..channel(c.operator())
        };
        assert!(
            matches!(
                c.check_channel_winnable(U256::from(1), &closed, 0, 10),
                Err(Error::Payment(PaymentError::Reverted { .. }))
            ),
            "a closed channel must be refused"
        );
        assert!(
            matches!(
                c.check_reclaimable(U256::from(1), &closed, 2_000),
                Err(Error::Payment(PaymentError::Reverted { .. }))
            ),
            "a closed channel must be refused"
        );
    }

    #[test]
    fn reclaim_before_the_chain_clock_reaches_unlock_at_is_refused() {
        let c = client();
        let ch = channel(c.operator());
        let err = c
            .check_reclaimable(U256::from(1), &ch, 1_799)
            .expect_err("TooEarly must be caught locally");
        assert!(
            matches!(err, Error::Payment(PaymentError::Reverted { .. })),
            "got {err:?}"
        );
        // One second later the same channel is reclaimable, and the node pays gas for it.
        c.check_reclaimable(U256::from(1), &ch, 1_800)
            .expect("unlockAt is inclusive");
    }

    #[test]
    fn the_exposure_caps_are_enforced_locally() {
        let mut cfg = Config::default();
        cfg.node.operator_key = KEY.into();
        cfg.contracts.cipher_task = address!("0x00000000000000000000000000000000000000aa");
        cfg.contracts.payment_vault = address!("0x00000000000000000000000000000000000000bb");
        cfg.payment.max_budget_per_task = 1_000;
        cfg.payment.max_claim_per_task = 500;
        let c = OrchestratorClient::new(&cfg).expect("builds");
        assert!(c.check_budget(1_000).is_ok());
        assert!(c.check_budget(1_001).is_err());
        let id = U256::from(3);
        assert!(c.check_claim(id, id, 500, 10_000).is_ok());
        assert!(
            matches!(c.check_claim(id, id, 501, 10_000), Err(Error::Chain(_))),
            "the per-task claim cap must bite before the channel's own cap"
        );
        assert!(
            matches!(
                c.check_claim(id, id, 10_001, 10_000),
                Err(Error::Payment(PaymentError::OverAuthorised { .. }))
            ),
            "over-claiming the channel is a payment error"
        );
    }

    #[test]
    fn a_zero_cap_means_no_cap_rather_than_no_work() {
        // `0` is "unlimited" by design; treating it as a literal cap would make every task
        // refuse to bid, which is the kind of failure that only shows up in production.
        let mut cfg = Config::default();
        cfg.node.operator_key = KEY.into();
        cfg.contracts.cipher_task = address!("0x00000000000000000000000000000000000000aa");
        cfg.contracts.payment_vault = address!("0x00000000000000000000000000000000000000bb");
        cfg.payment.max_budget_per_task = 0;
        cfg.payment.max_claim_per_task = 0;
        let c = OrchestratorClient::new(&cfg).expect("builds");
        c.check_budget(u128::MAX).expect("0 means unlimited");
        c.check_claim(U256::from(1), U256::from(2), u128::MAX, u128::MAX)
            .expect("0 means unlimited");
    }
}
