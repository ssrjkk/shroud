//! The work loop: turning the fold's nudges into transactions.
//!
//! [`state`](crate::state) emits [`Work`] from logs. This module decides whether a nudge is worth
//! a transaction *right now* and, if it is, spends the gas. The decision is always taken against a
//! fresh point read of the contract rather than against the fold, because the fold is a cache: a
//! peer can finalize an epoch, redeem a channel or settle a task in the interval between the log we
//! reacted to and the transaction we send. Reading first costs one RPC call; guessing costs the gas
//! of a revert.
//!
//! # Gates
//!
//! Every write is preceded by a pure function over data the node already had to read
//! ([`commit_gate`], [`finalize_gate`], [`settle_gate`], [`redeem_gate`], [`reclaim_gate`],
//! [`claim_gate`], [`dispute_gate`]). Each mirrors one `require` sequence from `CipherTask.sol` or
//! `PaymentVault.sol` and answers with a [`Gate`]:
//!
//! * [`Gate::Ready`] — send it.
//! * [`Gate::Wait`] — the call would revert on a deadline the node can name, so requeue at that
//!   deadline instead of polling it.
//! * [`Gate::Skip`] — waiting does not help: the work is already done by somebody, belongs to
//!   another address, or the window closed. Drop the nudge; the next log produces a new one.
//!
//! A decline is logged per nudge at `debug`, and the operator-facing warning is emitted once at
//! start-up. A reorg replay re-fires every event in its window, and a log line per replayed event
//! would be indistinguishable from a node that is working.
//!
//! # What this loop does
//!
//! Every arm moves money or status on chain: registration, epoch execution and
//! re-execution, dispute filing, finalization, settlement, redemption, reclamation,
//! claiming and bond release. Epoch execution runs through the [`fhe`](crate::fhe)
//! engine (`reference-cpu` by default, `tfhe-rs` behind the `prover` feature) on a
//! blocking thread, publishes the weight and metrics artefacts to the
//! content-addressed store, and commits the resulting digests with `commitEpoch`.
//! Re-execution recomputes the same digest and, on a mismatch with the claim, re-arms
//! the commit race so this node's own commit becomes the dispute material the fold
//! files `reportDispute` from.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy::primitives::{Address, B256, U256};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::{
    chain::client::{ChannelOnChain, CommitIntent, CommitOnChain, OrchestratorClient, TaskOnChain},
    chain::slice::{self, Slice},
    config::{parse_bls_pub_key, Config},
    da,
    error::{ConfigError, Error, FheError, Result},
    fhe::{self, EpochInputs, ShardInput},
    state::{NodeState, TaskStatus, Work},
};

/// How many times a nudge may fail before the worker stops retrying it.
///
/// A failing step is usually either a transport problem, which is worth retrying, or a
/// configuration problem, which will fail identically forever. Bounding the retries keeps the
/// second class from spending gas on every poll while still riding out the first.
const MAX_ATTEMPTS: u32 = 5;

/// The verdict of a gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// The contract would accept the call now.
    Ready,
    /// The call would revert on a deadline; retry after this long instead of polling it.
    Wait(Duration),
    /// The call would revert for a reason that waiting cannot fix.
    Skip(&'static str),
}

/// What the worker does with a nudge once the gate has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A transaction went out, or the node consciously did nothing further.
    Done,
    /// The gate vetoed the nudge for a reason that will not change.
    Skipped(&'static str),
    /// Requeue at the deadline rather than dropping the work.
    Retry(Duration),
}

/// A nudge waiting for a deadline the contract set, or for the backoff after a failure.
struct Deferred {
    due: Instant,
    attempts: u32,
    work: Work,
}

/// Consumes [`Work`] and writes to chain.
pub struct Worker {
    cfg: Config,
    client: Arc<OrchestratorClient>,
    state: Arc<NodeState>,
    /// Channels whose first `Redeem` nudge has been debounced; see `payment.redeem_delay`.
    debounced: Mutex<Vec<U256>>,
}

impl Worker {
    pub fn new(cfg: Config, client: Arc<OrchestratorClient>, state: Arc<NodeState>) -> Self {
        Self {
            debounced: Mutex::new(Vec::new()),
            cfg,
            client,
            state,
        }
    }

    /// Run until `shutdown` fires.
    ///
    /// Three sources feed the queue: the wake-up channel (a nudge the fold just produced), the
    /// drain of the fold's own queue (everything produced while this loop was busy, and everything
    /// produced before it started), and a tick of `chain.poll_interval`, which re-runs the
    /// deadline-driven arms and the registration repair.
    pub async fn run(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        if self.cfg.node.bls_pub_key.is_none() {
            warn!(
                "node.bls_pub_key is not set: this node can register for no task, so it can \
                 neither commit nor dispute on any of them"
            );
        }
        info!(
            poll = ?self.cfg.chain.poll_interval,
            auto_redeem = self.cfg.payment.auto_redeem,
            dispute_only = self.cfg.stark.digest_only,
            operator = %self.client.operator(),
            "worker started"
        );

        let mut rx = self.state.subscribe();
        let mut queue: VecDeque<(Work, u32)> = VecDeque::new();
        let mut deferred: Vec<Deferred> = Vec::new();
        let mut tick = tokio::time::interval(self.cfg.chain.poll_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = tick.tick() => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        info!("worker: shutdown requested");
                        return Ok(());
                    }
                }
                nudge = rx.recv() => match nudge {
                    Ok(w) => push_work(&mut queue, &deferred, w, 0),
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        // Missing a wake-up is not missing work: the fold's queue is drained on
                        // every pass below and is the authoritative list.
                        debug!(skipped, "worker: wake-ups lagged; draining the fold's queue");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("worker: state dropped; stopping");
                        return Ok(());
                    }
                }
            }

            let wall_now = Instant::now();
            deferred.retain(|d| {
                if d.due > wall_now {
                    return true;
                }
                push_work(&mut queue, &[], d.work.clone(), d.attempts);
                false
            });
            for w in self.state.take_work() {
                push_work(&mut queue, &deferred, w, 0);
            }
            for w in self.registrations_to_repair() {
                push_work(&mut queue, &deferred, w, 0);
            }
            for w in self.bonds_to_release() {
                push_work(&mut queue, &deferred, w, 0);
            }

            if queue.is_empty() {
                continue;
            }

            // One clock read per pass. Every deadline compared below is a `block.timestamp`, so a
            // skewed machine clock cannot move a window; see `OrchestratorClient::latest_block`.
            let chain_now = match self.client.latest_block().await {
                Ok((_, timestamp)) => timestamp,
                Err(e) => {
                    error!(error = %e, "worker: chain clock unavailable; trying again next tick");
                    continue;
                }
            };

            while let Some((work, attempts)) = queue.pop_front() {
                if let Some(delay) = self.first_redeem_sight(&work) {
                    deferred.push(Deferred {
                        due: Instant::now() + delay,
                        attempts,
                        work,
                    });
                    continue;
                }
                match self.handle(&work, chain_now).await {
                    Ok(Outcome::Done) => {}
                    Ok(Outcome::Skipped(why)) => {
                        debug!(work = ?work, why, "worker: nudge dropped")
                    }
                    Ok(Outcome::Retry(d)) => deferred.push(Deferred {
                        due: Instant::now() + d,
                        attempts,
                        work,
                    }),
                    Err(e) => {
                        let attempts = attempts + 1;
                        if attempts >= MAX_ATTEMPTS {
                            error!(work = ?work, attempts, error = %e, "worker: giving up");
                        } else {
                            error!(work = ?work, attempts, error = %e, "worker: step failed");
                            deferred.push(Deferred {
                                due: Instant::now() + self.backoff(attempts),
                                attempts,
                                work,
                            });
                        }
                    }
                }
            }
        }
    }

    /// `payment.redeem_delay` as a one-shot debounce, or `None` when this channel has waited.
    ///
    /// The reward channel is opened by the same transaction that settles the epoch, so the first
    /// nudge for a channel is pushed back once rather than answered with a read that may not have
    /// caught up with the settlement yet. The delay is a guard against our own RPC staleness, not
    /// a contract rule: `redeem` has no time gate of its own.
    fn first_redeem_sight(&self, work: &Work) -> Option<Duration> {
        let Work::Redeem { channel_id } = work else {
            return None;
        };
        let mut seen = self.lock_debounced();
        if seen.contains(channel_id) {
            return None;
        }
        seen.push(*channel_id);
        Some(self.cfg.payment.redeem_delay)
    }

    fn lock_debounced(&self) -> std::sync::MutexGuard<'_, Vec<U256>> {
        // A poisoned lock means a panic happened while a channel id was being recorded. Keeping
        // the ids we have is strictly better than unwinding the work loop over a log line.
        self.debounced.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Exponential backoff on the poll interval, so a persistently failing step slows down rather
    /// than spending gas on every tick.
    fn backoff(&self, attempts: u32) -> Duration {
        self.cfg
            .chain
            .poll_interval
            .saturating_mul(1u32 << attempts.min(4))
    }

    /// Dispatch one nudge.
    async fn handle(&self, work: &Work, chain_now: u64) -> Result<Outcome> {
        match work {
            Work::Register { task_id } => self.on_register(*task_id).await,
            Work::Execute { task_id, epoch } => self.on_execute(*task_id, *epoch, chain_now).await,
            Work::Reexecute {
                task_id,
                epoch,
                claimed_digest,
            } => self.on_reexecute(*task_id, *epoch, *claimed_digest).await,
            Work::FileDispute {
                task_id,
                epoch,
                our_digest,
            } => self.on_dispute(*task_id, *epoch, *our_digest).await,
            Work::Finalize { task_id, epoch } => {
                self.on_finalize(*task_id, *epoch, chain_now).await
            }
            Work::Settle { task_id } => self.on_settle(*task_id).await,
            Work::Redeem { channel_id } => self.on_redeem(*channel_id).await,
            Work::Reclaim { channel_id } => self.on_reclaim(*channel_id, chain_now).await,
            Work::Claim => self.on_claim().await,
            Work::ReleaseBond { task_id } => self.on_release_bond(*task_id).await,
        }
    }

    // --- the arms ---------------------------------------------------------------------

    /// `registerNode`, but only for a task this node may still work on.
    ///
    /// Registration is the node's bid: it is what makes `commitEpoch` and `reportDispute` callable
    /// at all, it is once per task, and it pays gas. So the chain is read first, the budget is
    /// checked against the operator's exposure cap second, and only then is the transaction sent.
    async fn on_register(&self, task_id: U256) -> Result<Outcome> {
        if self.client.is_registered(task_id).await? {
            // The fold cannot know about our own registrations across a restart or a replay.
            self.state.mark_registered(task_id, true);
            self.rearm_executes(task_id);
            return Ok(Outcome::Done);
        }

        let task = self.client.task(task_id).await?;
        if let Err(e) = self.client.check_budget(task.budget) {
            // Retrying cannot help: the budget is frozen when the task is created.
            debug!(task = %task_id, error = %e, "worker: task is outside the exposure cap");
            return Ok(Outcome::Done);
        }

        let Some(src) = &self.cfg.node.bls_pub_key else {
            debug!(task = %task_id, "worker: no BLS public key configured, so no registration");
            return Ok(Outcome::Done);
        };
        let bls_pub_key = parse_bls_pub_key(src).ok_or_else(|| {
            // `Config::validate` rejects a malformed key at load, so getting here means the file
            // changed under a running node.
            Error::Config(ConfigError::Invalid {
                field: "node.bls_pub_key",
                reason: "expected 32 bytes of hex".into(),
            })
        })?;
        if bls_pub_key.is_zero() {
            // The chain rejects zero keys (`ZeroBlsKey`): registering one would burn gas on a
            // certain revert, and a zero key is never a real identity — it is an unset config.
            debug!(task = %task_id, "worker: BLS public key is zero, so no registration");
            return Ok(Outcome::Done);
        }

        self.client.register_node(task_id, bls_pub_key).await?;
        self.state.mark_registered(task_id, true);
        self.rearm_executes(task_id);
        Ok(Outcome::Done)
    }

    /// Re-nudge the epochs that only became executable because we are now registered.
    ///
    /// `registerNode` emits no log, so the fold has no event to derive them from: a node that joins
    /// a task while an epoch is already open would otherwise read `EpochOpened` in its own past and
    /// never commit to it. This is the only place a nudge enters the fold's queue from outside the
    /// fold, and it stays a nudge — `on_execute` still reads the contract before it spends gas.
    fn rearm_executes(&self, task_id: U256) {
        // Through `pending_epochs`, not `TaskState::epochs_to_execute`: that path also checks
        // registration, terminal/settled status, the `opened` flag and the taint gate, and
        // this is a repair pass re-nudging work the fold already saw.
        let me = self.client.operator();
        for (task, epoch) in self.state.pending_epochs(me) {
            if task == task_id {
                self.state.nudge(Work::Execute {
                    task_id: task,
                    epoch,
                });
            }
        }
    }

    /// The epoch is ours to execute: gather the sealed inputs, run the engine off the
    /// async runtime, publish the artefacts and commit the digests.
    ///
    /// Gas is spent only after two gates (before the engine runs and after it finishes,
    /// against a fresh chain read) and a duplicate-commit check: the engine may take a
    /// minute, and a peer may have committed — or the window may have closed — while it ran.
    async fn on_execute(&self, task_id: U256, epoch: u32, chain_now: u64) -> Result<Outcome> {
        let task = self.client.task(task_id).await?;
        if !self.client.is_registered(task_id).await? {
            // `registerNode` is in flight or has not been sent. The repair pass re-nudges it, so
            // this arm only has to wait.
            return Ok(Outcome::Retry(self.cfg.chain.poll_interval));
        }
        let min_window = self.cfg.node.min_epoch_window;
        let gate = commit_gate(&task, epoch, chain_now, min_window);
        if gate != Gate::Ready {
            return Ok(outcome_of(gate));
        }
        if self.cfg.stark.digest_only {
            info!(
                task = %task_id,
                epoch,
                "dispute-only configuration: taking no part in the commit race"
            );
            return Ok(Outcome::Done);
        }
        // A commit of ours may have landed while the fold was behind (restart, replay):
        // `commitEpoch` reverts `DuplicateCommit` on a second one, so check first.
        let me = self.client.operator();
        if self.client.commit_of(task_id, epoch, me).await?.is_some() {
            debug!(task = %task_id, epoch, "already committed; the fold will catch up");
            return Ok(Outcome::Done);
        }
        // A fold that flagged itself as inconsistent must not drive execution: the
        // Execute nudge would send the node off to compute an epoch against state it has
        // already declared wrong. Wait for the re-anchored replay instead.
        if self.state.is_tainted() {
            debug!(task = %task_id, epoch, "fold is tainted; waiting for a re-anchored replay");
            return Ok(Outcome::Retry(self.cfg.chain.poll_interval));
        }
        let engine = fhe::select_engine(&self.cfg.fhe);
        let engine_name = engine.name();
        let inputs = match self.execute_inputs(task_id, epoch, &task).await {
            Ok(inputs) => inputs,
            Err(e) if is_retryable(&e) => {
                if !matches!(e, Error::Io(_)) {
                    error!(task = %task_id, epoch, error = %e, "worker: inputs unavailable; retrying");
                }
                return Ok(Outcome::Retry(self.cfg.chain.poll_interval));
            }
            Err(e) => {
                error!(task = %task_id, epoch, error = %e, "worker: epoch has no executable inputs; no commit will be sent");
                return Ok(Outcome::Done);
            }
        };
        let output = match tokio::task::spawn_blocking(move || engine.execute_epoch(&inputs)).await
        {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                error!(task = %task_id, epoch, engine = engine_name, error = %e, "worker: epoch execution failed; no commit will be sent");
                return Ok(Outcome::Done);
            }
            Err(e) => return Err(Error::Other(e.into())),
        };
        let max = self.cfg.shard.max_ciphertext_bytes;
        let dir = &self.cfg.shard.cache_dir;
        let endpoint = &self.cfg.shard.da_endpoint;
        let enc_weights_cid = da::store(dir, endpoint, &output.weights_bytes, max).await?;
        let metrics_cid = da::store(dir, endpoint, &output.metrics_bytes, max).await?;
        // The engine may have taken a minute: re-read the chain before spending gas.
        let (_, fresh_now) = self.client.latest_block().await?;
        let task = self.client.task(task_id).await?;
        if commit_gate(&task, epoch, fresh_now, min_window) != Gate::Ready {
            debug!(task = %task_id, epoch, "window closed while the engine ran; artefacts stay in the store");
            return Ok(Outcome::Done);
        }
        let intent = CommitIntent {
            task_id,
            epoch,
            proof: fhe::proof_reference(output.trace_digest),
            enc_weights_cid,
            weights_digest: output.weights_digest,
            metrics_cid,
            trace_digest: output.trace_digest,
        };
        self.client.commit_epoch(&intent).await?;
        info!(
            task = %task_id,
            epoch,
            engine = engine_name,
            trace = %output.trace_digest,
            rows = output.rows,
            "epoch committed"
        );
        Ok(Outcome::Done)
    }

    /// Re-derive a peer's trace digest to check a claim.
    ///
    /// Advisory work: it produces no transaction of its own. On a mismatch with the claim
    /// it re-arms the commit race — this node's own commit, once it lands, is the verified
    /// material the fold files `reportDispute` from. An agreement is silence.
    async fn on_reexecute(
        &self,
        task_id: U256,
        epoch: u32,
        claimed_digest: B256,
    ) -> Result<Outcome> {
        let me = self.client.operator();
        // Our own commit is the dispute material; the fold files from it without us.
        if let Some(t) = self.state.task(task_id) {
            if t.our_commit(epoch, me).is_some() {
                debug!(task = %task_id, epoch, "already committed; the fold disputes from our commit");
                return Ok(Outcome::Done);
            }
        }
        let task = self.client.task(task_id).await?;
        // Only a committing epoch is disputable: settled or rejected history needs no opinion.
        if chain_status(&task) != TaskStatus::EpochCommitting {
            return Ok(Outcome::Done);
        }
        if self.state.is_tainted() {
            debug!(task = %task_id, epoch, "fold is tainted; waiting for a re-anchored replay");
            return Ok(Outcome::Retry(self.cfg.chain.poll_interval));
        }
        let inputs = match self.execute_inputs(task_id, epoch, &task).await {
            Ok(inputs) => inputs,
            Err(e) if is_retryable(&e) => {
                debug!(task = %task_id, epoch, error = %e, "inputs unavailable; retrying");
                return Ok(Outcome::Retry(self.cfg.chain.poll_interval));
            }
            Err(e) => {
                error!(task = %task_id, epoch, error = %e, "worker: cannot form an opinion about this claim");
                return Ok(Outcome::Done);
            }
        };
        let engine = fhe::select_engine(&self.cfg.fhe);
        let ours = match tokio::task::spawn_blocking(move || engine.digest_epoch(&inputs)).await {
            Ok(Ok(digest)) => digest,
            Ok(Err(e)) => {
                error!(task = %task_id, epoch, error = %e, "worker: cannot form an opinion about this claim");
                return Ok(Outcome::Done);
            }
            Err(e) => return Err(Error::Other(e.into())),
        };
        if ours == claimed_digest {
            debug!(task = %task_id, epoch, "claim reproduces locally; no dispute");
        } else {
            info!(
                task = %task_id,
                epoch,
                claimed = %claimed_digest,
                ours = %ours,
                "claim differs from local re-execution; re-arming the commit race"
            );
            self.state.nudge(Work::Execute { task_id, epoch });
        }
        Ok(Outcome::Done)
    }

    /// Gather everything the engine needs for `epoch` of `task_id`.
    ///
    /// The dataset comes from the *chain*: leaf contributors and digests are contract views,
    /// and the fold only supplies the order it saw. Every payload is verified
    /// (`keccak256(bytes)` against the pin) before the engine runs, so a DA layer that
    /// serves wrong bytes is caught here, not in a dispute.
    ///
    /// A DA layer that has not synced yet surfaces as [`Error::Io`], a fold that is
    /// still backfilling as [`Error::Chain`], and a failing remote backend as
    /// [`Error::Other`]: all three may resolve on their own. Anything else
    /// is a permanent refusal that costs no gas.
    async fn execute_inputs(
        &self,
        task_id: U256,
        epoch: u32,
        task: &TaskOnChain,
    ) -> Result<EpochInputs> {
        if task.features == 0 {
            return Err(Error::Fhe(FheError::ShapeMismatch {
                got_rows: 0,
                got_cols: 0,
                want_rows: 0,
                want_cols: 1,
            }));
        }
        let fold = self.state.task(task_id).ok_or_else(|| {
            Error::Chain(format!("task {task_id:#x} is not in the derived fold yet"))
        })?;
        // The fold must imply exactly the sealed root: executing on a partial history
        // would commit a digest no complete node reproduces.
        let derived = fold.derived_ct_root().ok_or_else(|| {
            Error::Chain(format!(
                "task {task_id:#x}: fold holds a partial contribution history"
            ))
        })?;
        if derived != task.ct_root {
            return Err(Error::Chain(format!(
                "task {task_id:#x}: derived ctRoot {derived:#x} disagrees with the sealed {:#x}",
                task.ct_root
            )));
        }
        let max = self.cfg.shard.max_ciphertext_bytes;
        let dir = self.cfg.shard.cache_dir.clone();
        let endpoint = self.cfg.shard.da_endpoint.clone();
        let mut shards = Vec::with_capacity(fold.leaves.len());
        let mut indexes: Vec<u32> = fold.leaves.keys().copied().collect();
        indexes.sort_unstable();
        for index in indexes {
            let leaf = fold.leaves.get(&index).expect("keyed");
            let contributor = self.client.contribution_of(task_id, index).await?;
            let c = self.client.contribution(task_id, contributor).await?;
            if !c.accepted {
                return Err(Error::ShardStore(crate::error::ShardError::Malformed {
                    offset: index as usize,
                    reason: format!(
                        "contribution of {contributor} at leaf {index} is not accepted"
                    ),
                }));
            }
            if c.ciphertext_cid != leaf.cid {
                return Err(Error::Chain(format!(
                    "task {task_id:#x}: leaf {index} is {:#x} on chain but {:#x} in the fold",
                    c.ciphertext_cid, leaf.cid
                )));
            }
            let bytes = da::fetch(&dir, &endpoint, &c.ciphertext_cid, max).await?;
            da::verify_bytes(&c.ct_digest, &bytes)?;
            shards.push(ShardInput {
                leaf_index: index,
                cid: c.ciphertext_cid,
                ct_digest: c.ct_digest,
                bytes,
            });
        }
        if task.last_weights_cid.is_zero() {
            return Err(Error::Fhe(FheError::Backend(
                "openEpoch pinned no seed weights; the engine cannot start from nothing".into(),
            )));
        }
        let prev_weights_bytes = da::fetch(&dir, &endpoint, &task.last_weights_cid, max).await?;
        let reference = matches!(self.cfg.fhe.backend, crate::config::FheBackend::Reference);
        let prev_weights = if reference {
            Some(self.decode_prev_weights(&prev_weights_bytes, task)?)
        } else {
            None
        };
        Ok(EpochInputs {
            task_id,
            epoch,
            chain_id: self.cfg.chain.chain_id,
            cipher_task: self.client.cipher_task(),
            ct_root: task.ct_root,
            prev_weights_digest: task.last_weights_digest,
            features: task.features,
            scale: self.cfg.fhe.scale,
            lr_q16: self.cfg.fhe.lr_q16,
            l2_q16: self.cfg.fhe.l2_q16,
            minibatch: self.cfg.fhe.minibatch,
            seed: self.cfg.fhe.seed,
            prev_weights,
            prev_weights_bytes,
            shards,
        })
    }

    /// Decode the seed weights `openEpoch` pinned.
    ///
    /// Buyer tooling publishes `shroud/weights/v1` files; anything else (the test suite
    /// pins arbitrary words, early buyers may pin their own convention) falls back to
    /// genesis zeros with a warning that names the foreign pin. The trace always binds
    /// the *chain's* digest, so every node running this code agrees either way — and a
    /// node that understands the buyer's convention will disagree through the dispute
    /// protocol, which is exactly what it is for.
    fn decode_prev_weights(&self, bytes: &[u8], task: &TaskOnChain) -> Result<fhe::Weights> {
        match fhe::Weights::decode(bytes, task.features) {
            Ok(w) => {
                if w.digest() != task.last_weights_digest {
                    warn!(
                        digest = %task.last_weights_digest,
                        "seed weights decode but their digest differs from the chain pin; \
                         executing from the file and binding the chain pin in the trace"
                    );
                }
                Ok(w)
            }
            Err(_) => {
                warn!(
                    cid = %task.last_weights_cid,
                    digest = %task.last_weights_digest,
                    "seed weights are not a shroud/weights/v1 file; executing from genesis \
                     zeros and binding the chain pin in the trace"
                );
                fhe::Weights::zeros(task.features)
            }
        }
    }

    /// `reportDispute` for a claim we can prove wrong.
    ///
    /// The chain's `_claimedDigest` has no view, but `epochWinner` is written in the same branch
    /// that writes it, so `winner == us` is the authoritative reading of "the claim is already
    /// ours" — which is exactly the case `reportDispute` reverts as `DisputeAgreesWithClaim`.
    async fn on_dispute(&self, task_id: U256, epoch: u32, our_digest: B256) -> Result<Outcome> {
        let me = self.client.operator();
        let task = self.client.task(task_id).await?;
        let ours = self.client.commit_of(task_id, epoch, me).await?;
        let winner = self.client.epoch_winner(task_id, epoch).await?;
        let gate = dispute_gate(&task, ours.as_ref(), winner == me, our_digest);
        if gate != Gate::Ready {
            return Ok(outcome_of(gate));
        }
        self.client
            .report_dispute(task_id, epoch, our_digest)
            .await?;
        Ok(Outcome::Done)
    }

    /// `finalizeEpoch`: close the dispute window, pay the winner, open the reward channel.
    ///
    /// Callable by anyone, so this is a race rather than a right. The node sends it because nobody
    /// else has an incentive to, and it is the transaction that turns an earned epoch into a
    /// redeemable channel.
    async fn on_finalize(&self, task_id: U256, epoch: u32, chain_now: u64) -> Result<Outcome> {
        let task = self.client.task(task_id).await?;
        let mut quorum_met = false;
        if chain_now < task.finalize_ready_at() {
            // Only a dispute quorum ends the window early, and only the contract knows the count,
            // so the extra read happens on the one branch where it can change the answer.
            let (need, have) = self.client.dispute_quorum(task_id).await?;
            quorum_met = !need.is_zero() && have >= need;
        }
        let gate = finalize_gate(&task, epoch, chain_now, quorum_met);
        if gate != Gate::Ready {
            return Ok(outcome_of(gate));
        }
        self.client.finalize_epoch(task_id, epoch).await?;
        Ok(Outcome::Done)
    }

    /// `settle` / `settleFrom`: distribute the escrow, one page at a time.
    ///
    /// A page that does not reach the end of the contributor list leaves the task exactly as it
    /// found it (`EpochSettled`, unlocked) with only the cursor moved, and the contract emits no
    /// log for it. So a successful page re-arms the nudge; the final page moves the status to
    /// `Settling`, the gate then vetoes, and the loop stops.
    async fn on_settle(&self, task_id: U256) -> Result<Outcome> {
        let task = self.client.task(task_id).await?;
        let gate = settle_gate(&task);
        if gate != Gate::Ready {
            return Ok(outcome_of(gate));
        }
        // `settle` is `_settleFrom(taskId, 0)` and a page may only continue from the exact cursor,
        // so the two calls are chosen by reading it rather than by remembering it.
        let cursor = self.client.settle_cursor(task_id).await?;
        if cursor.is_zero() {
            self.client.settle(task_id).await?;
        } else {
            self.client.settle_from(task_id, cursor).await?;
        }
        Ok(Outcome::Retry(self.cfg.chain.poll_interval))
    }

    /// `redeem` the one authorised slice of a channel we earned.
    ///
    /// The amount is the channel's own `maxCumulative`, read from the chain: `CipherTask`
    /// authorises exactly slice 0 at exactly that figure, and `redeem` advances `consumed` even
    /// when it pays zero — so a node that asked for less would consume the slice and send the
    /// difference to nobody.
    async fn on_redeem(&self, channel_id: U256) -> Result<Outcome> {
        if !self.cfg.payment.auto_redeem {
            return Ok(Outcome::Skipped("payment.auto_redeem is off"));
        }
        let me = self.client.operator();
        let retry = self.cfg.chain.poll_interval;
        let ch = self.client.channel(channel_id).await?;
        let gate = redeem_gate(&ch, me, retry);
        if gate != Gate::Ready {
            return Ok(outcome_of(gate));
        }
        let amount = ch.max_cumulative;
        let blob = slice::encode(&Slice::epoch_reward(channel_id, amount));
        self.client
            .redeem(channel_id, slice::SLICE_INDEX, amount, &blob)
            .await?;
        Ok(Outcome::Done)
    }

    /// `reclaim` a channel we own once it unlocks.
    ///
    /// The node's own `redeem` path leaves a fully drawn channel open with its lock still
    /// recorded, so this is what closes it and pays whatever the contract says is left.
    async fn on_reclaim(&self, channel_id: U256, chain_now: u64) -> Result<Outcome> {
        let me = self.client.operator();
        let retry = self.cfg.chain.poll_interval;
        let ch = self.client.channel(channel_id).await?;
        let gate = reclaim_gate(&ch, me, chain_now, retry);
        if gate != Gate::Ready {
            return Ok(outcome_of(gate));
        }
        self.client.reclaim(channel_id).await?;
        Ok(Outcome::Done)
    }

    /// `claim`: turn `pendingWithdrawal` into tokens the operator actually holds.
    ///
    /// Both `redeem` and `reclaim` credit rather than transfer, so a node that never calls this has
    /// earned money it does not have.
    async fn on_claim(&self) -> Result<Outcome> {
        let me = self.client.operator();
        let pending = self.client.pending_withdrawal(me).await?;
        let gate = claim_gate(pending);
        if gate != Gate::Ready {
            return Ok(outcome_of(gate));
        }
        self.client.claim().await?;
        Ok(Outcome::Done)
    }

    /// Release our registration bond once the task can no longer slash it.
    ///
    /// Like `claim`, this is exit money, not protocol progress: a node that never calls it
    /// leaves its own bond locked. The gate reads the vault first, so an already-released or
    /// slashed bond is a skipped nudge rather than a `BondNotReleasable` revert.
    async fn on_release_bond(&self, task_id: U256) -> Result<Outcome> {
        let me = self.client.operator();
        let bond = self.client.node_bond(task_id, me).await?;
        let gate = release_gate(bond);
        if gate != Gate::Ready {
            return Ok(outcome_of(gate));
        }
        self.client.release_bond(task_id).await?;
        Ok(Outcome::Done)
    }

    // --- repair -----------------------------------------------------------------------

    /// Registration nudges the fold could not have produced.
    ///
    /// The fold asks on `TaskSealed` and `EpochOpened`, so two real cases would otherwise never
    /// register: a watcher that started mid-history and never saw the seal, and a `registerNode`
    /// that failed for a transient reason after the seal had already been folded. Both leave a
    /// node that can see the epochs it is missing and cannot act on any of them.
    fn registrations_to_repair(&self) -> Vec<Work> {
        let mut out = Vec::new();
        for task_id in self.state.task_ids() {
            let Some(task) = self.state.task(task_id) else {
                continue;
            };
            if task.registered || task.settled || task.status.is_terminal() {
                continue;
            }
            // A sealed task with no epoch yet is the seal nudge's job; this pass is for epochs we
            // are demonstrably missing.
            if task.epochs.is_empty() {
                continue;
            }
            out.push(Work::Register { task_id });
        }
        out
    }

    /// Bond-release nudges the fold could not have produced.
    ///
    /// Same two blind spots as registration: a watcher that started mid-history never saw the
    /// terminal event, and a `releaseBond` that failed transiently after the event was folded.
    /// Either leaves a bond locked that the chain would already release, so this pass re-nudges
    /// every registered task the fold already considers finished. The arm re-reads the vault
    /// before sending, so tasks whose bonds are already gone cost one point read, never a revert.
    fn bonds_to_release(&self) -> Vec<Work> {
        let mut out = Vec::new();
        for task_id in self.state.task_ids() {
            let Some(task) = self.state.task(task_id) else {
                continue;
            };
            if !task.registered {
                continue;
            }
            if task.settled || task.status.is_terminal() {
                out.push(Work::ReleaseBond { task_id });
            }
        }
        out
    }
}

/// Queue `w` unless the same nudge is already queued or already waiting.
///
/// Duplicate nudges are normal — a reorg replay re-fires every event in its window — and a
/// duplicate *transaction* is at best a wasted `DuplicateCommit` revert and at worst a
/// `NothingToClaim` one. Deduplicating here is what makes it safe to drain the fold's queue more
/// than once per pass.
fn push_work(queue: &mut VecDeque<(Work, u32)>, deferred: &[Deferred], work: Work, attempts: u32) {
    let duplicate =
        queue.iter().any(|(queued, _)| *queued == work) || deferred.iter().any(|d| d.work == work);
    if !duplicate {
        queue.push_back((work, attempts));
    }
}

/// A gate's veto as an outcome. `Ready` maps to `Done` so callers can use it as an early return.
fn outcome_of(gate: Gate) -> Outcome {
    match gate {
        Gate::Ready => Outcome::Done,
        Gate::Wait(d) => Outcome::Retry(d),
        Gate::Skip(why) => Outcome::Skipped(why),
    }
}

/// Failures that may resolve on their own: a DA layer that has not synced yet, a fold
/// that is still backfilling, or a remote backend that is temporarily unreachable. The
/// caller requeues those without spending gas; the epoch window bounds the wait, because
/// the gate turns `Ready` into `Skip` once it closes. Data and configuration errors
/// (`Fhe`, `Shard`) are permanent and must be loud instead.
fn is_retryable(e: &Error) -> bool {
    matches!(e, Error::Io(_) | Error::Chain(_) | Error::Other(_))
}

/// The task's status byte as the node's own enum, with an unknown value collapsing to `None`.
///
/// A status this crate does not name is treated as `TaskStatus::None`, which every gate below
/// refuses to act on: the safe answer to an enum reordering in Solidity is to do nothing.
fn chain_status(task: &TaskOnChain) -> TaskStatus {
    TaskStatus::from_u8(task.status).unwrap_or(TaskStatus::None)
}

/// `commitEpoch`: status, order, window, and the operator's own minimum window.
///
/// Mirrors the four `require`s that precede the proof verification, all of which the node can read
/// first. Registration is the one condition the `Task` struct does not expose, so the caller checks
/// it against `nodeRegistered`.
pub fn commit_gate(task: &TaskOnChain, epoch: u32, now: u64, min_window: Duration) -> Gate {
    // Both statuses accept a commit: the first one moves the task from `EpochOpen` to
    // `EpochCommitting`, and a node that commits afterwards is still inside the window.
    let status = chain_status(task);
    if status != TaskStatus::EpochOpen && status != TaskStatus::EpochCommitting {
        return Gate::Skip("the task is not accepting commits");
    }
    if epoch != task.next_epoch {
        return Gate::Skip("the epoch is not the one the contract is running");
    }
    if now > task.epoch_deadline {
        return Gate::Skip("the commit window expired");
    }
    if Duration::from_secs(task.epoch_deadline.saturating_sub(now)) < min_window {
        return Gate::Skip("less than node.min_epoch_window is left");
    }
    Gate::Ready
}

/// `finalizeEpoch`: only callable once the dispute window closes or the quorum has reported.
pub fn finalize_gate(task: &TaskOnChain, epoch: u32, now: u64, quorum_met: bool) -> Gate {
    if chain_status(task) != TaskStatus::EpochCommitting {
        return Gate::Skip("the epoch is not in its dispute window");
    }
    if epoch != task.next_epoch {
        return Gate::Skip("the epoch is not the one the contract is running");
    }
    if quorum_met {
        return Gate::Ready;
    }
    let ready_at = task.finalize_ready_at();
    if now >= ready_at {
        Gate::Ready
    } else {
        Gate::Wait(Duration::from_secs(ready_at - now))
    }
}

/// `settle` / `settleFrom`: every epoch settled, nothing locked, and not already distributed.
pub fn settle_gate(task: &TaskOnChain) -> Gate {
    if chain_status(task) != TaskStatus::EpochSettled {
        return Gate::Skip("the task is not waiting to be settled");
    }
    // `locked` is cleared by `finalizeEpoch`, so a non-zero lock means an epoch is mid-flight and
    // the contract would revert `EpochLocked`.
    if task.locked != 0 {
        return Gate::Skip("the last epoch still holds its lock");
    }
    // The common case, not a fault: `finalizeEpoch` leaves the task `EpochSettled` after *each*
    // epoch, and only the last one may be distributed.
    if task.next_epoch < task.epochs {
        return Gate::Skip("the buyer asked for epochs that have not run yet");
    }
    Gate::Ready
}

/// `redeem`: ours, open, and with its one authorised slice still unconsumed.
///
/// `retry` is the wait used when the vault has no record of the channel at all. That is not the
/// same as "not ours": `channelInfo` on an unknown id returns an all-zero struct, and a channel
/// whose opening transaction has not reached this node's RPC yet must be retried rather than
/// dropped — dropping it would lose the reward permanently.
pub fn redeem_gate(ch: &ChannelOnChain, me: Address, retry: Duration) -> Gate {
    if ch.node == Address::ZERO {
        return Gate::Wait(retry);
    }
    if ch.node != me {
        return Gate::Skip("the channel pays a different node");
    }
    if ch.closed {
        return Gate::Skip("the channel is closed");
    }
    if !ch.accepts_slice(slice::SLICE_INDEX) {
        return Gate::Skip("the authorised slice has been consumed");
    }
    if ch.remaining() == 0 {
        return Gate::Skip("the channel authorises nothing left");
    }
    Gate::Ready
}

/// `reclaim`: ours, still open, and past `unlockAt`.
pub fn reclaim_gate(ch: &ChannelOnChain, me: Address, now: u64, retry: Duration) -> Gate {
    if ch.node == Address::ZERO {
        return Gate::Wait(retry);
    }
    if ch.node != me {
        return Gate::Skip("the channel pays a different node");
    }
    if ch.closed {
        return Gate::Skip("the channel is already reclaimed or closed");
    }
    if now < ch.unlock_at {
        return Gate::Wait(Duration::from_secs(ch.unlock_at - now));
    }
    Gate::Ready
}

/// `claim`: the pull-based out step, which reverts `NothingToClaim` on a zero credit.
pub fn claim_gate(pending: U256) -> Gate {
    if pending.is_zero() {
        return Gate::Skip("nothing is credited to the operator");
    }
    Gate::Ready
}

/// `releaseBond`: the only thing that can stop it is there being no bond.
pub fn release_gate(bond: u128) -> Gate {
    if bond == 0 {
        return Gate::Skip("no registration bond on this task");
    }
    Gate::Ready
}

/// `reportDispute`: standing, digest, and a claim that is not already ours.
///
/// `claim_is_ours` comes from `epochWinner`, which the contract writes in the same branch as
/// `_claimedDigest`: if the winner slot holds our address then the chain's claim *is* our digest,
/// and `reportDispute` would revert `DisputeAgreesWithClaim`.
pub fn dispute_gate(
    task: &TaskOnChain,
    our_commit: Option<&CommitOnChain>,
    claim_is_ours: bool,
    our_digest: B256,
) -> Gate {
    if chain_status(task) != TaskStatus::EpochCommitting {
        return Gate::Skip("the epoch is no longer disputable");
    }
    let Some(commit) = our_commit else {
        return Gate::Skip("we never committed to this epoch");
    };
    if !commit.verified {
        return Gate::Skip("our commit did not verify, so we have no standing to report");
    }
    if commit.trace_digest != our_digest {
        return Gate::Skip("the digest to report is not the one we committed");
    }
    if claim_is_ours {
        return Gate::Skip("the chain already holds our digest as the claim");
    }
    Gate::Ready
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::watcher::ChainEvent;

    const ME: Address = Address::repeat_byte(0x99);
    const OTHER: Address = Address::repeat_byte(0x11);
    const RETRY: Duration = Duration::from_secs(4);

    /// A task whose epoch 3 is running: deadline 1_000, dispute window 300, four epochs asked for.
    fn task(status: TaskStatus, epoch: u32) -> TaskOnChain {
        TaskOnChain {
            status: status as u8,
            budget: 1_000_000_000,
            locked: 0,
            epoch_deadline: 1_000,
            dispute_window: 300,
            epoch_duration: 600,
            epochs: 4,
            next_epoch: epoch,
            ct_root: B256::repeat_byte(0xaa),
            last_weights_cid: B256::repeat_byte(0x0e),
            last_weights_digest: B256::repeat_byte(0x0f),
            contributors: 2,
            shards: 2,
            is_sealed: true,
            features: 3,
        }
    }

    /// A channel of `node`, 50 CMUSD authorised, nothing drawn, unlocking at 2_000.
    fn channel(node: Address) -> ChannelOnChain {
        ChannelOnChain {
            node,
            streamer: Address::repeat_byte(0x77),
            task_id: U256::from(1),
            max_cumulative: 50_000_000,
            withdrawn: 0,
            consumed: 0,
            unlock_at: 2_000,
            closed: false,
        }
    }

    fn commit(digest: u8, verified: bool) -> CommitOnChain {
        CommitOnChain {
            trace_digest: B256::repeat_byte(digest),
            committed_at: 900,
            verified,
        }
    }

    /// A worker with a real client. `OrchestratorClient::new` builds a provider but does not dial
    /// it, so these tests need neither a chain nor a network.
    fn worker_with(state: Arc<NodeState>) -> Worker {
        let mut cfg = Config::default();
        cfg.node.operator_key =
            "0x1111111111111111111111111111111111111111111111111111111111111111".into();
        cfg.contracts.cipher_task = Address::repeat_byte(0x01);
        cfg.contracts.payment_vault = Address::repeat_byte(0x02);
        let client = Arc::new(OrchestratorClient::new(&cfg).expect("a client from a valid config"));
        Worker {
            debounced: Mutex::new(Vec::new()),
            cfg,
            client,
            state,
        }
    }

    fn worker() -> Worker {
        let state = Arc::new(NodeState::new());
        let w = worker_with(state);
        // The fold attributes commits and channels to this address; if it disagrees with the
        // client's key-derived operator the worker would redeem nobody's channels. Tests that
        // need a fixed address set it explicitly — the default here is agreement.
        w.state.set_operator(w.client.operator());
        w
    }

    #[test]
    fn an_epoch_we_could_still_commit_in_is_ready() {
        let t = task(TaskStatus::EpochOpen, 3);
        assert_eq!(
            commit_gate(&t, 3, 700, Duration::from_secs(300)),
            Gate::Ready
        );
    }

    #[test]
    fn committing_after_the_deadline_is_refused_rather_than_reverted() {
        let t = task(TaskStatus::EpochCommitting, 3);
        assert!(matches!(
            commit_gate(&t, 3, 1_001, Duration::from_secs(0)),
            Gate::Skip("the commit window expired")
        ));
    }

    #[test]
    fn an_epoch_that_is_too_short_to_finish_is_skipped() {
        let t = task(TaskStatus::EpochOpen, 3);
        // 120 seconds left against an operator minimum of 300.
        assert!(matches!(
            commit_gate(&t, 3, 880, Duration::from_secs(300)),
            Gate::Skip("less than node.min_epoch_window is left")
        ));
    }

    #[test]
    fn committing_the_wrong_epoch_is_refused() {
        let t = task(TaskStatus::EpochOpen, 3);
        assert!(matches!(
            commit_gate(&t, 2, 700, Duration::from_secs(0)),
            Gate::Skip("the epoch is not the one the contract is running")
        ));
    }

    #[test]
    fn a_task_that_is_not_committing_cannot_be_committed_to() {
        let t = task(TaskStatus::EpochSettled, 3);
        assert!(matches!(
            commit_gate(&t, 3, 700, Duration::from_secs(0)),
            Gate::Skip("the task is not accepting commits")
        ));
    }

    #[test]
    fn finalize_waits_for_the_window_and_requeues_at_its_end() {
        let t = task(TaskStatus::EpochCommitting, 3);
        // Deadline 1_000 plus a 300 second window: at 1_100 there are 200 seconds left.
        assert_eq!(
            finalize_gate(&t, 3, 1_100, false),
            Gate::Wait(Duration::from_secs(200))
        );
        assert_eq!(finalize_gate(&t, 3, 1_300, false), Gate::Ready);
    }

    #[test]
    fn a_dispute_quorum_ends_the_window_early() {
        let t = task(TaskStatus::EpochCommitting, 3);
        assert_eq!(finalize_gate(&t, 3, 1_000, true), Gate::Ready);
    }

    #[test]
    fn finalize_does_not_replay_an_epoch_somebody_else_closed() {
        let mut t = task(TaskStatus::EpochCommitting, 3);
        t.status = TaskStatus::EpochSettled as u8;
        t.next_epoch = 4;
        assert!(matches!(
            finalize_gate(&t, 3, 5_000, false),
            Gate::Skip("the epoch is not in its dispute window")
        ));
    }

    #[test]
    fn settling_early_is_refused() {
        let t = task(TaskStatus::EpochSettled, 2);
        // Two of four epochs are still owed; the escrow must not move.
        assert!(matches!(
            settle_gate(&t),
            Gate::Skip("the buyer asked for epochs that have not run yet")
        ));
    }

    #[test]
    fn settling_a_locked_epoch_is_refused() {
        let mut t = task(TaskStatus::EpochSettled, 4);
        t.locked = 1;
        assert!(matches!(
            settle_gate(&t),
            Gate::Skip("the last epoch still holds its lock")
        ));
    }

    #[test]
    fn the_last_epoch_is_the_one_that_settles_and_then_stops() {
        assert_eq!(settle_gate(&task(TaskStatus::EpochSettled, 4)), Gate::Ready);
        // The final page moves the status to `Settling`, so the re-armed nudge vetoes itself there
        // rather than paying gas for `InvalidTaskStatus`.
        let t = task(TaskStatus::Settling, 4);
        assert!(matches!(
            settle_gate(&t),
            Gate::Skip("the task is not waiting to be settled")
        ));
    }

    #[test]
    fn an_unreadable_channel_is_retried_not_dropped() {
        // The vault returns zeroes for an id it has not seen yet. Reading that as "not ours" would
        // lose the reward for good.
        assert_eq!(
            redeem_gate(&ChannelOnChain::default(), ME, RETRY),
            Gate::Wait(RETRY)
        );
        assert_eq!(
            reclaim_gate(&ChannelOnChain::default(), ME, 5_000, RETRY),
            Gate::Wait(RETRY)
        );
    }

    #[test]
    fn a_full_channel_is_redeemable_and_a_drawn_one_is_not() {
        let ch = channel(ME);
        assert_eq!(redeem_gate(&ch, ME, RETRY), Gate::Ready);

        let mut drawn = ch;
        drawn.consumed = 1;
        drawn.withdrawn = drawn.max_cumulative;
        assert!(!drawn.accepts_slice(slice::SLICE_INDEX), "slice 0 is gone");
        assert!(matches!(
            redeem_gate(&drawn, ME, RETRY),
            Gate::Skip("the authorised slice has been consumed")
        ));
    }

    #[test]
    fn a_channel_is_redeemed_once_because_only_slice_zero_is_authorised() {
        // `consumed` is the contract's replay guard, and it moves even when `redeem` pays zero, so
        // the same nudge must never produce the same transaction twice.
        let mut ch = channel(ME);
        assert_eq!(ch.accepts_slice(slice::SLICE_INDEX), true);
        ch.consumed = slice::SLICE_INDEX + 1;
        assert_eq!(ch.accepts_slice(slice::SLICE_INDEX), false);
    }

    #[test]
    fn a_zero_authorisation_channel_is_never_redeemed() {
        let mut ch = channel(ME);
        ch.max_cumulative = 0;
        assert!(matches!(
            redeem_gate(&ch, ME, RETRY),
            Gate::Skip("the channel authorises nothing left")
        ));
    }

    #[test]
    fn somebody_elses_channel_is_never_ours_to_draw_or_close() {
        let ch = channel(OTHER);
        assert!(matches!(
            redeem_gate(&ch, ME, RETRY),
            Gate::Skip("the channel pays a different node")
        ));
        assert!(matches!(
            reclaim_gate(&ch, ME, 5_000, RETRY),
            Gate::Skip("the channel pays a different node")
        ));
    }

    #[test]
    fn reclaim_waits_for_the_unlock_and_then_runs() {
        let ch = channel(ME);
        assert_eq!(
            reclaim_gate(&ch, ME, 1_900, RETRY),
            Gate::Wait(Duration::from_secs(100))
        );
        assert_eq!(reclaim_gate(&ch, ME, 2_000, RETRY), Gate::Ready);

        let mut closed = ch;
        closed.closed = true;
        assert!(matches!(
            reclaim_gate(&closed, ME, 5_000, RETRY),
            Gate::Skip("the channel is already reclaimed or closed")
        ));
    }

    #[test]
    fn claiming_nothing_is_refused_locally() {
        assert!(matches!(
            claim_gate(U256::ZERO),
            Gate::Skip("nothing is credited to the operator")
        ));
        assert_eq!(claim_gate(U256::from(1)), Gate::Ready);
    }

    #[test]
    fn releasing_without_a_bond_is_refused_locally() {
        assert!(matches!(
            release_gate(0),
            Gate::Skip("no registration bond on this task")
        ));
        assert_eq!(release_gate(1), Gate::Ready);
    }

    #[test]
    fn a_finished_task_with_our_registration_gets_its_bond_released() {
        // The repair pass covers the watcher that started mid-history and never saw the terminal
        // event: the fold says finished and registered, the arm re-reads the vault, and a gone
        // bond is a skip rather than a revert.
        let state = Arc::new(NodeState::new());
        state.set_operator(ME);
        state.mark_registered(U256::from(44), true);
        state.apply(&ChainEvent::TaskAborted {
            task_id: U256::from(44),
            reason: [0xb5, 0x51, 0xa2, 0x2b],
        });
        let worker = worker_with(state.clone());
        assert_eq!(
            worker.bonds_to_release(),
            vec![Work::ReleaseBond {
                task_id: U256::from(44)
            }]
        );

        // Live tasks and tasks we never registered for are not ours to exit.
        let live = Arc::new(NodeState::new());
        live.set_operator(ME);
        live.apply(&ChainEvent::EpochOpened {
            task_id: U256::from(45),
            epoch: 0,
            enc_weights_cid: B256::repeat_byte(0x0e),
            weights_digest: B256::repeat_byte(0x0f),
        });
        let worker = worker_with(live.clone());
        assert!(worker.bonds_to_release().is_empty());
    }

    #[test]
    fn disputing_requires_a_verified_commit_of_ours() {
        let t = task(TaskStatus::EpochCommitting, 3);
        let ours = B256::repeat_byte(0xbb);

        // No commit at all: the contract reverts `DisputeWithoutVerifiedCommit`.
        assert!(matches!(
            dispute_gate(&t, None, false, ours),
            Gate::Skip("we never committed to this epoch")
        ));
        assert!(matches!(
            dispute_gate(&t, Some(&commit(0xbb, false)), false, ours),
            Gate::Skip("our commit did not verify, so we have no standing to report")
        ));
        // A digest that is not what we committed: `DisputeDigestMismatch`.
        assert!(matches!(
            dispute_gate(
                &t,
                Some(&commit(0xbb, true)),
                false,
                B256::repeat_byte(0xcc)
            ),
            Gate::Skip("the digest to report is not the one we committed")
        ));
        // The claim is already ours: `DisputeAgreesWithClaim`.
        assert!(matches!(
            dispute_gate(&t, Some(&commit(0xbb, true)), true, ours),
            Gate::Skip("the chain already holds our digest as the claim")
        ));
        // Everything the contract asks for is present.
        assert_eq!(
            dispute_gate(&t, Some(&commit(0xbb, true)), false, ours),
            Gate::Ready
        );
    }

    #[test]
    fn a_closed_epoch_is_not_disputable() {
        let t = task(TaskStatus::EpochSettled, 3);
        assert!(matches!(
            dispute_gate(
                &t,
                Some(&commit(0xbb, true)),
                false,
                B256::repeat_byte(0xbb)
            ),
            Gate::Skip("the epoch is no longer disputable")
        ));
    }

    #[test]
    fn the_redeem_blob_carries_the_channels_own_authorisation() {
        // The worker redeems at the channel's `maxCumulative`, so the 96-byte blob it sends must
        // decode back to exactly that figure: the contract looks the authorisation up under the
        // blob's own words, and a mismatch is an `InvalidSignature` revert.
        let ch = channel(ME);
        let id = U256::from(9);
        let blob = slice::encode(&Slice::epoch_reward(id, ch.max_cumulative));
        let back = slice::decode(&blob).expect("a 96-byte blob");
        assert_eq!(back.channel_id, id);
        assert_eq!(back.index, slice::SLICE_INDEX);
        assert_eq!(back.amount, ch.max_cumulative);
    }

    #[test]
    fn an_unknown_status_byte_asks_for_nothing() {
        // `TaskStatus::from_u8` has no variant for 11, so a gate must not read a status it does not
        // understand as one it does.
        let t = TaskOnChain {
            status: 11,
            ..task(TaskStatus::EpochCommitting, 3)
        };
        assert!(matches!(
            finalize_gate(&t, 3, 5_000, true),
            Gate::Skip("the epoch is not in its dispute window")
        ));
        assert!(matches!(
            commit_gate(&t, 3, 100, Duration::from_secs(0)),
            Gate::Skip("the task is not accepting commits")
        ));
    }

    #[test]
    fn backoff_grows_and_is_bounded() {
        let worker = worker();
        let base = worker.cfg.chain.poll_interval;
        assert_eq!(worker.backoff(1), base * 2);
        assert_eq!(worker.backoff(4), base * 16);
        // The shift is clamped, so a long failure streak cannot ask for an absurd delay.
        assert_eq!(worker.backoff(40), base * 16);
    }

    #[test]
    fn a_duplicate_nudge_is_not_queued_twice() {
        let mut queue: VecDeque<(Work, u32)> = VecDeque::new();
        push_work(&mut queue, &[], Work::Claim, 0);
        push_work(&mut queue, &[], Work::Claim, 0);
        assert_eq!(queue.len(), 1);

        // A nudge already waiting for its deadline is not queued either, or the deadline and the
        // queue would both fire the same transaction.
        let settle = Work::Settle {
            task_id: U256::from(5),
        };
        let waiting = vec![Deferred {
            due: Instant::now(),
            attempts: 0,
            work: settle.clone(),
        }];
        push_work(&mut queue, &waiting, settle, 0);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn a_channels_first_redeem_is_debounced_and_its_second_is_not() {
        let worker = worker();
        let nudge = Work::Redeem {
            channel_id: U256::from(12),
        };
        let delay = worker.cfg.payment.redeem_delay;
        assert_eq!(worker.first_redeem_sight(&nudge), Some(delay));
        assert_eq!(worker.first_redeem_sight(&nudge), None);
        // A different channel is a different reward, and it gets its own debounce.
        assert_eq!(
            worker.first_redeem_sight(&Work::Redeem {
                channel_id: U256::from(13)
            }),
            Some(delay)
        );
        // Nothing else is debounced at all.
        assert_eq!(worker.first_redeem_sight(&Work::Claim), None);
    }

    #[test]
    fn a_task_the_fold_never_saw_sealed_still_gets_registered() {
        // A watcher that starts mid-history sees `EpochOpened` and nothing else. Without this pass
        // the node can see the epochs it is missing and never ask to be registered for them.
        let state = Arc::new(NodeState::new());
        state.set_operator(ME);
        state.apply(&ChainEvent::EpochOpened {
            task_id: U256::from(42),
            epoch: 2,
            enc_weights_cid: B256::repeat_byte(0x0e),
            weights_digest: B256::repeat_byte(0x0f),
        });
        let worker = worker_with(state.clone());
        assert_eq!(
            worker.registrations_to_repair(),
            vec![Work::Register {
                task_id: U256::from(42)
            }]
        );

        state.mark_registered(U256::from(42), true);
        assert!(worker.registrations_to_repair().is_empty());
    }

    #[test]
    fn a_sealed_task_without_epochs_and_a_settled_one_are_not_repaired() {
        let state = Arc::new(NodeState::new());
        state.set_operator(ME);
        state.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(43),
            ct_root: B256::repeat_byte(0xaa),
            shards: 1,
            contributors: 1,
        });
        let worker = worker_with(state.clone());
        assert!(
            worker.registrations_to_repair().is_empty(),
            "the fold already nudged this one at the seal"
        );

        // An epoch appears, so the repair pass takes over ...
        state.apply(&ChainEvent::EpochOpened {
            task_id: U256::from(43),
            epoch: 0,
            enc_weights_cid: B256::repeat_byte(0x0e),
            weights_digest: B256::repeat_byte(0x0f),
        });
        assert_eq!(worker.registrations_to_repair().len(), 1);

        // ... and stops once the escrow has been distributed: there is nothing left to work on.
        state.apply(&ChainEvent::TaskSettled {
            task_id: U256::from(43),
            user_pool: 1,
            node_pool: 1,
            committee_pool: 1,
        });
        assert!(worker.registrations_to_repair().is_empty());
    }

    #[test]
    fn a_gate_that_vetoes_becomes_an_outcome_that_costs_no_gas() {
        assert_eq!(outcome_of(Gate::Skip("x")), Outcome::Skipped("x"));
        assert_eq!(
            outcome_of(Gate::Wait(Duration::from_secs(1))),
            Outcome::Retry(Duration::from_secs(1))
        );
        assert_eq!(outcome_of(Gate::Ready), Outcome::Done);
    }

    #[test]
    fn the_worker_and_the_state_agree_on_who_the_operator_is() {
        let worker = worker();
        assert_eq!(worker.state.operator(), Some(worker.client.operator()));
    }
}
