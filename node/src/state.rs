//! Derived state: the node's fold over chain events.
//!
//! Everything here is *derived* — it can always be rebuilt from logs plus a checkpoint, and
//! `reset()` throws it away wholesale when a reorg invalidates the fold. Nothing in this module
//! is authoritative. The contract is; if the two ever disagree the contract wins and the node
//! re-syncs. That asymmetry is deliberate: a bug in the fold must never be able to make the node
//! claim a payment or a proof it did not earn.
//!
//! [`NodeState::apply`] returns *nudges* ([`Work`]), not decisions. A nudge says "something
//! happened that may make an on-chain action possible"; the worker re-reads the contract before
//! it spends gas, so a missing, duplicate or out-of-order log can at worst cost a point read,
//! never a wrong payment.
//!
//! Two things the fold cannot know from logs alone and therefore asks the chain for:
//!
//! * whether *we* are registered on a task (registration is our own action, confirmed by the
//!   `nodeRegistered` view — see [`NodeState::mark_registered`]);
//! * epoch deadlines and the settlement boundary, which live in the `Task` struct.
//!
//! The state is folded under a single `RwLock` and is small (a few thousand tasks at most), so
//! a coarse lock is cheaper than the alternative of splitting invariants across locks.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::{
    chain::{
        transcript,
        watcher::{ChainEvent, Checkpoint},
    },
    error::{Error, Result},
};

/// `TaskStatus` mirrors `ICipherTask.TaskStatus`. Duplicated as a plain enum so the state machine
/// can be unit-tested without a chain, and so a contract-side reordering surfaces as a
/// non-exhaustive-match compile error rather than a wrong branch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TaskStatus {
    #[default]
    None = 0,
    Opening = 1,
    Collecting = 2,
    Sealed = 3,
    EpochOpen = 4,
    EpochCommitting = 5,
    EpochSettled = 6,
    Settling = 7,
    Revealing = 8,
    Disclosed = 9,
    Aborted = 10,
}

impl TaskStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => TaskStatus::None,
            1 => TaskStatus::Opening,
            2 => TaskStatus::Collecting,
            3 => TaskStatus::Sealed,
            4 => TaskStatus::EpochOpen,
            5 => TaskStatus::EpochCommitting,
            6 => TaskStatus::EpochSettled,
            7 => TaskStatus::Settling,
            8 => TaskStatus::Revealing,
            9 => TaskStatus::Disclosed,
            10 => TaskStatus::Aborted,
            _ => return Option::None,
        })
    }

    /// Whether no further work is expected for this task.
    pub fn is_terminal(self) -> bool {
        matches!(self, TaskStatus::Disclosed | TaskStatus::Aborted)
    }
}

/// A shard a contributor pinned, in the order the contract numbered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    pub contributor: Address,
    pub cid: B256,
    pub rows: u32,
}

/// Per-epoch record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochState {
    /// `EpochOpened` was folded for this epoch. Set by nothing else: an epoch the watcher never
    /// saw open (a backfill that started mid-chain) must not look like one we owe work on.
    pub opened: bool,
    /// Encrypted weights the buyer pinned for this epoch, and their digest. From `EpochOpened`.
    pub enc_weights_cid: B256,
    pub weights_digest: B256,
    /// Commits by node. The contract accepts one per node per epoch, so a second entry for the
    /// same node is either a replay (same digest) or a state bug (different digest).
    pub commits: BTreeMap<Address, CommitRecord>,
    /// Re-execution digests reported by disputing nodes, and who reported them.
    pub disputes: BTreeMap<Address, B256>,
    /// Reward channel the settlement opened for the winner, if any.
    pub channel: Option<U256>,
    pub settled: bool,
    /// The dispute quorum was reached: nobody is paid for this epoch.
    pub rejected: bool,
    pub winner: Option<Address>,
    pub amount: u128,
}

impl EpochState {
    /// The digest the contract holds as this epoch's claim.
    ///
    /// `commitEpoch` writes `_claimedDigest` every time the committer takes the winner slot, and
    /// it takes the slot when it is the first commit **or when its address is lower than the
    /// incumbent's** (the `incumbent == address(0) || msg.sender < incumbent` branch in
    /// `CipherTask::commitEpoch`). So the claim belongs to the lowest-address committer, not the
    /// earliest one. Reading it as "first come" would have a node dispute a digest the chain is
    /// not holding, and `reportDispute` reverts exactly that case.
    pub fn claimed_digest(&self) -> Option<B256> {
        self.commits.first_key_value().map(|(_, c)| c.trace_digest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRecord {
    pub trace_digest: B256,
    /// `reportDispute` requires *our own* commit to be verified, so this is what makes a dispute
    /// callable at all.
    ///
    /// An observable `EpochCommitted` already means the proof verified: `commitEpoch` reverts
    /// with `ProofRejected` when the verifier says no, and a revert takes the log with it.
    /// `EpochVerified` is folded as well because it is the chain's own statement, and it is the
    /// only path on which this can ever be set to `false`.
    pub verified: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskState {
    pub task_id: U256,
    pub status: TaskStatus,
    pub ct_root: B256,
    pub shards: u32,
    pub contributors: u32,
    /// We are registered for this task. Our own knowledge, not a fold output: see
    /// [`NodeState::mark_registered`].
    pub registered: bool,
    /// `TaskSettled` was folded: the escrow is fully distributed and there is nothing left to do.
    pub settled: bool,
    /// Contributions seen, keyed by the contract's leaf index. Used to re-derive `ctRoot`.
    pub leaves: BTreeMap<u32, Leaf>,
    pub epochs: BTreeMap<u32, EpochState>,
    /// Latest accepted weights, carried across epochs. The optimiser seeds from this.
    pub last_weights: Option<(B256, B256)>,
}

impl TaskState {
    pub fn epoch(&self, epoch: u32) -> Option<&EpochState> {
        self.epochs.get(&epoch)
    }

    /// Our own commit for `epoch`, if we made one.
    pub fn our_commit(&self, epoch: u32, me: Address) -> Option<&CommitRecord> {
        self.epochs.get(&epoch)?.commits.get(&me)
    }

    /// The `ctRoot` implied by the contributions we have seen, or `None` when the history is
    /// incomplete — which is normal for a watcher that started mid-chain, and must not be
    /// reported as a mismatch.
    pub fn derived_ct_root(&self) -> Option<B256> {
        let count = self.leaves.len();
        if count == 0 || count != self.contributors as usize {
            return None;
        }
        // Contiguous 0..count, otherwise the fold is missing a leaf.
        if self.leaves.keys().next() != Some(&0)
            || self.leaves.keys().next_back() != Some(&(count as u32 - 1))
        {
            return None;
        }
        let cids: Vec<B256> = self.leaves.values().map(|l| l.cid).collect();
        Some(transcript::ct_root(&cids))
    }

    /// Epochs that were actually opened, are not settled or rejected, and that we have not
    /// committed to. The `opened` flag matters: a commit for an epoch whose `EpochOpened` the
    /// watcher never saw (backfill started mid-chain) would otherwise look like an epoch we
    /// still owe work on.
    pub fn epochs_to_execute(&self, me: Address) -> Vec<u32> {
        self.epochs
            .iter()
            .filter(|(_, e)| e.opened && !e.settled && !e.rejected && !e.commits.contains_key(&me))
            .map(|(epoch, _)| *epoch)
            .collect()
    }
}

/// Reward channel tracking. Mirrors `PaymentVault.Channel`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelState {
    pub channel_id: U256,
    pub task_id: U256,
    pub node: Address,
    pub streamer: Address,
    pub max_cumulative: u128,
    pub withdrawn: u128,
    /// Next slice index the contract will accept.
    pub consumed: u64,
    pub unlock_at: u64,
    pub closed: bool,
}

impl ChannelState {
    /// Remaining authorisation. The node never claims more than this, no matter what a peer
    /// says it is owed.
    pub fn remaining(&self) -> u128 {
        self.max_cumulative.saturating_sub(self.withdrawn)
    }

    pub fn unlocked(&self, now: u64) -> bool {
        now >= self.unlock_at
    }

    /// Fully drawn: every authorised token has been redeemed, so the channel is only worth
    /// reclaiming once `unlockAt` passes.
    pub fn exhausted(&self) -> bool {
        self.withdrawn >= self.max_cumulative
    }
}

/// Work the scheduler should pick up. Produced by the fold, consumed by the worker loop.
///
/// Each variant is a *nudge*: the worker re-reads the chain and may find the action already
/// taken by a peer, which is a no-op rather than an error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Work {
    /// Epoch `epoch` of `task_id` is open and we owe a commit.
    Execute { task_id: U256, epoch: u32 },
    /// We can see work on this task but are not registered, so no commit of ours would be
    /// accepted. `registerNode` is once per task and is the prerequisite for both committing and
    /// disputing.
    Register { task_id: U256 },
    /// Re-derive the trace digest for a claim we did not make. Advisory: only a node that holds
    /// a verified commit for the epoch can file, and re-execution is how a dispute-only operator
    /// forms an opinion.
    Reexecute {
        task_id: U256,
        epoch: u32,
        claimed_digest: B256,
    },
    /// Our verified commit disagrees with the claim, so `reportDispute` is callable.
    /// `our_digest` is the digest to report: the contract requires it to equal our own commit.
    FileDispute {
        task_id: U256,
        epoch: u32,
        our_digest: B256,
    },
    /// The epoch's dispute window needs closing; `finalizeEpoch` releases the lock and pays the
    /// winner. Callable by anyone, so the worker times it rather than racing for it.
    Finalize { task_id: U256, epoch: u32 },
    /// Distribute the escrow, if this task's epochs are all done.
    Settle { task_id: U256 },
    /// Redeem the authorised slice of a channel we own. The amount is read from the channel, not
    /// taken from the event, so a stale fold cannot over-claim.
    Redeem { channel_id: U256 },
    /// A channel we own is fully drawn and past `unlockAt`; reclaim it so the remainder (if the
    /// contract ever leaves one) returns to the streamer and the channel stops counting.
    Reclaim { channel_id: U256 },
    /// `pendingWithdrawal` for the operator is non-zero; call `claim`.
    Claim,
}

/// Inner state, guarded by one lock.
#[derive(Debug, Default)]
struct Inner {
    operator: Option<Address>,
    tasks: HashMap<U256, TaskState>,
    channels: HashMap<U256, ChannelState>,
    queue: Vec<Work>,
    /// Set when a fold event was dropped or applied out of order, which means the local view
    /// cannot be trusted until the next checkpoint replay.
    tainted: bool,
    last_checkpoint: Option<Checkpoint>,
    chain_id: Option<u64>,
}

/// Handle to the derived state. Cheap to clone; all clones share one state.
#[derive(Debug, Clone)]
pub struct NodeState {
    inner: Arc<RwLock<Inner>>,
    /// Work notifications, so the worker loop can `select!` on state changes and RPC traffic.
    tx: broadcast::Sender<Work>,
}

impl NodeState {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(1_024);
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Work> {
        self.tx.subscribe()
    }

    pub fn chain_id(&self) -> u64 {
        self.read().chain_id.unwrap_or_default()
    }

    pub fn set_chain_id(&self, id: u64) {
        self.write().chain_id = Some(id);
    }

    /// The address the fold attributes commits and channels to. Without it the fold cannot tell
    /// "a channel we are owed" from "a channel somebody else is owed", and would try to redeem
    /// the whole world's slices.
    pub fn set_operator(&self, me: Address) {
        self.write().operator = Some(me);
    }

    pub fn operator(&self) -> Option<Address> {
        self.read().operator
    }

    /// Record that we are registered on a task. Called by the worker after its own
    /// `registerNode` lands, and again after a reorg replay from the `nodeRegistered` view.
    pub fn mark_registered(&self, task_id: U256, registered: bool) {
        let mut g = self.write();
        let t = g.tasks.entry(task_id).or_insert(TaskState {
            task_id,
            ..Default::default()
        });
        t.registered = registered;
    }

    /// Throw away everything derived and start over. Called on a reorg deeper than the anchor
    /// ring, where the correct answer is "replay", never "patch".
    pub fn reset(&self) {
        let mut g = self.write();
        let n_tasks = g.tasks.len();
        g.tasks.clear();
        g.channels.clear();
        g.queue.clear();
        g.tainted = false;
        // The checkpoint names a cursor *into the fold this reset just threw away*, so
        // keeping it would have a restart resume from a block whose events the rebuilt fold
        // has not seen. It is rewritten by the next `maybe_checkpoint`.
        g.last_checkpoint = None;
        // `chain_id` and `operator` are not derived from logs, so they survive a reorg.
        drop(g);
        debug!(tasks = n_tasks, "derived state reset");
    }

    /// Persist the watcher cursor. Written separately from the derived state because the
    /// derived state is rebuildable and the cursor is what bounds the rebuild.
    pub async fn write_checkpoint(&self, cp: &Checkpoint) -> Result<()> {
        {
            let mut g = self.write();
            g.last_checkpoint = Some(cp.clone());
        }
        let dir = self.checkpoint_dir();
        tokio::fs::create_dir_all(&dir).await?;
        // Write-then-rename: a torn checkpoint file is worse than a missing one, because the
        // code above trusts a present file to be complete.
        let tmp = dir.join("watcher.json.tmp");
        let final_path = dir.join("watcher.json");
        let bytes = serde_json::to_vec_pretty(cp)?;
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &final_path).await?;
        Ok(())
    }

    pub async fn read_checkpoint(&self) -> Result<Option<Checkpoint>> {
        let path = self.checkpoint_dir().join("watcher.json");
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    pub fn checkpoint_dir(&self) -> PathBuf {
        // Injected by `main` through the env so the state layer stays free of config types.
        std::env::var_os("CM_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./data"))
            .join("state")
    }

    /// Fold one event in. Returns the work it implies, if any.
    ///
    /// Total by construction: an event the node has never seen before for a task it does not
    /// track is *not* an error, because the watcher may start mid-history. What matters is
    /// that the fold never applies a second, contradictory event for the same (task, epoch,
    /// node) — that is the case `tainted` exists for.
    pub fn apply(&self, ev: &ChainEvent) -> Vec<Work> {
        let mut g = self.write();
        let me = g.operator;
        let mut work = Vec::new();
        match ev {
            ChainEvent::ContributionSubmitted {
                task_id,
                contributor,
                leaf_index,
                ciphertext_cid,
                rows,
            } => {
                let t = g.tasks.entry(*task_id).or_default();
                t.task_id = *task_id;
                t.leaves.insert(
                    *leaf_index,
                    Leaf {
                        contributor: *contributor,
                        cid: *ciphertext_cid,
                        rows: *rows,
                    },
                );
                // A contribution after the seal is impossible on chain (`sealTask` freezes the
                // root), so if we see one the fold itself is out of order.
                if t.status == TaskStatus::Sealed || t.ct_root != B256::ZERO {
                    g.tainted = true;
                    warn!(task = %task_id, leaf = leaf_index, "contribution folded onto a sealed task; state is tainted");
                }
            }
            ChainEvent::TaskSealed {
                task_id,
                ct_root,
                shards,
                contributors,
            } => {
                // `t` borrows `g.tasks`, so the taint flag (which lives on `g` itself) cannot
                // be written while `t` is alive. Decide everything inside the block, write the
                // flag after the borrow ends. The order matters the other way too: `derived`
                // must be computed *after* `shards`/`contributors` land, or the fold compares
                // the leaves against a zeroed count, derives `None`, and never taints.
                let (root_changed, derived, needs_register) = {
                    let t = g.tasks.entry(*task_id).or_default();
                    t.task_id = *task_id;
                    let root_changed = t.ct_root != B256::ZERO && t.ct_root != *ct_root;
                    t.ct_root = *ct_root;
                    t.shards = *shards;
                    t.contributors = *contributors;
                    t.status = TaskStatus::Sealed;
                    // Cross-check the seal against the contributions we saw. This is the only
                    // place the node can catch a wrong `ctRoot` before it executes against it.
                    let derived = t.derived_ct_root();
                    (root_changed, derived, !t.registered)
                };

                // The seal is the last moment registration is still early: `registerNode` is
                // documented as "once per task before the first epoch opens", and until it lands
                // the node can neither commit nor dispute anything on this task.
                if needs_register {
                    work.push(Work::Register { task_id: *task_id });
                }
                if root_changed {
                    g.tainted = true;
                    warn!(task = %task_id, "ctRoot changed for an already-seen task; state is tainted");
                }
                if let Some(derived) = derived.filter(|d| d != ct_root) {
                    g.tainted = true;
                    warn!(
                        task = %task_id,
                        on_chain = %ct_root,
                        derived = %derived,
                        "our ctRoot does not match the chain; state is tainted"
                    );
                }
            }
            ChainEvent::EpochOpened {
                task_id,
                epoch,
                enc_weights_cid,
                weights_digest,
            } => {
                let t = g.tasks.entry(*task_id).or_default();
                t.task_id = *task_id;
                t.status = TaskStatus::EpochOpen;
                let e = t.epochs.entry(*epoch).or_default();
                e.opened = true;
                e.enc_weights_cid = *enc_weights_cid;
                e.weights_digest = *weights_digest;
                // The first `EpochOpened` of an epoch carries the seed weights; later opens carry
                // the previous winner's, which the optimiser warm-starts from.
                t.last_weights = Some((*enc_weights_cid, *weights_digest));
                if t.registered && me.is_some_and(|me| !e.commits.contains_key(&me)) {
                    work.push(Work::Execute {
                        task_id: *task_id,
                        epoch: *epoch,
                    });
                } else if !t.registered {
                    // Late but not too late: registering now means the *next* epoch is ours to
                    // commit. Committing without registering reverts `NodeNotRegistered`, so the
                    // worker registers first and does not send the commit in this round.
                    work.push(Work::Register { task_id: *task_id });
                }
            }
            ChainEvent::EpochCommitted {
                task_id,
                epoch,
                node,
                trace_digest,
            } => {
                // The watcher can join mid-history, so a commit for a task we never saw sealed
                // is normal — and it is exactly what a late node needs in order to dispute or
                // settle. Skip it and the task is invisible forever.
                let t = g.tasks.entry(*task_id).or_default();
                t.task_id = *task_id;
                t.status = TaskStatus::EpochCommitting;
                let e = t.epochs.entry(*epoch).or_default();
                let first_for_epoch = e.commits.is_empty();
                match e.commits.get(node) {
                    Some(prev) if prev.trace_digest != *trace_digest => {
                        g.tainted = true;
                        warn!(task = %task_id, epoch, %node, "node committed twice with different digests; the contract should have rejected this");
                        return work;
                    }
                    Some(_) => return work,
                    None => {}
                }
                e.commits.insert(
                    *node,
                    CommitRecord {
                        trace_digest: *trace_digest,
                        // A commit that exists on chain has verified: `ProofRejected` reverts the
                        // whole `commitEpoch` transaction, log included.
                        verified: true,
                    },
                );

                // `finalizeEpoch` is permissionless on chain: anybody may close the epoch, and
                // nobody implies the node cannot. So this is queued *before* the operator
                // check below - without an identity the fold still wants the epoch closed, it
                // just cannot tell which commits are its own.
                if first_for_epoch {
                    // Somebody has claimed the epoch, so its window is now running and someone
                    // has to close it.
                    work.push(Work::Finalize {
                        task_id: *task_id,
                        epoch: *epoch,
                    });
                }

                let Some(me) = me else {
                    // Without an operator identity the fold cannot tell its own commits from
                    // anybody else's, so it queues nothing rather than queueing everything.
                    return work;
                };

                if *node == me {
                    // The common order for a late honest node: a peer claimed the epoch first,
                    // our own commit lands second, and the claim on chain is not ours. That is
                    // precisely the state in which `reportDispute` is callable.
                    if let Some(claimed) = e.claimed_digest() {
                        if claimed != *trace_digest {
                            work.push(Work::FileDispute {
                                task_id: *task_id,
                                epoch: *epoch,
                                our_digest: *trace_digest,
                            });
                        }
                    }
                    return work;
                }

                if let Some(ours) = e.commits.get(&me) {
                    if ours.verified && ours.trace_digest != *trace_digest {
                        work.push(Work::FileDispute {
                            task_id: *task_id,
                            epoch: *epoch,
                            our_digest: ours.trace_digest,
                        });
                    }
                } else {
                    work.push(Work::Reexecute {
                        task_id: *task_id,
                        epoch: *epoch,
                        claimed_digest: *trace_digest,
                    });
                }
            }
            ChainEvent::EpochVerified {
                task_id,
                epoch,
                node,
                ok,
            } => {
                let Some(t) = g.tasks.get_mut(task_id) else {
                    return work;
                };
                let Some(c) = t
                    .epochs
                    .get_mut(epoch)
                    .and_then(|e| e.commits.get_mut(node))
                else {
                    // Normal, not exceptional: inside `commitEpoch` the `EpochVerified` log is
                    // emitted before `EpochCommitted`, so in the same transaction the verifier's
                    // statement always arrives first. The commit arm records `verified = true` for
                    // it, and a verification for a commit that never arrives is a revert, which
                    // has no logs at all.
                    return work;
                };
                c.verified = *ok;
                // Copy the digest out of the commit before anything else borrows the epoch: the
                // lookup below takes `t.epochs` immutably, and the mutable borrow that produced
                // `c` is still live as long as `c` is used.
                let our_digest = c.trace_digest;

                let Some(me) = me else { return work };
                if *node != me || !*ok {
                    return work;
                }
                // Our proof just became disputable material: if the epoch's claim is not ours,
                // the contract will accept a report of our own digest.
                let e = t.epochs.get(epoch).expect("epoch exists");
                if let Some(claimed) = e.claimed_digest() {
                    if claimed != our_digest {
                        work.push(Work::FileDispute {
                            task_id: *task_id,
                            epoch: *epoch,
                            our_digest,
                        });
                    }
                }
            }
            ChainEvent::EpochRejected {
                task_id,
                epoch,
                reporters,
            } => {
                let t = g.tasks.entry(*task_id).or_default();
                t.task_id = *task_id;
                let e = t.epochs.entry(*epoch).or_default();
                e.rejected = true;
                e.settled = true;
                // The contract moves the task to `EpochSettled` here and pays the reporters out
                // of the lock, so the epoch is closed even though no node won it.
                t.status = TaskStatus::EpochSettled;
                debug!(task = %task_id, epoch, reporters, "epoch rejected by dispute quorum");
            }
            ChainEvent::EpochSettled {
                task_id,
                epoch,
                node,
                amount,
            } => {
                let t = g.tasks.entry(*task_id).or_default();
                t.task_id = *task_id;
                let e = t.epochs.entry(*epoch).or_default();
                if e.settled {
                    return work;
                }
                e.settled = true;
                e.winner = Some(*node);
                e.amount = *amount;
                t.status = TaskStatus::EpochSettled;
                // Whether the *task* is settleable depends on `params.epochs`, which no event
                // carries, so this is a nudge and the worker checks the view.
                work.push(Work::Settle { task_id: *task_id });
            }
            ChainEvent::DisputeReported {
                task_id,
                epoch,
                reporter,
                digest,
            } => {
                let t = g.tasks.entry(*task_id).or_default();
                t.task_id = *task_id;
                let e = t.epochs.entry(*epoch).or_default();
                let already = e.disputes.contains_key(reporter);
                e.disputes.insert(*reporter, *digest);
                if already || Some(*reporter) == me {
                    return work;
                }
                work.push(Work::Reexecute {
                    task_id: *task_id,
                    epoch: *epoch,
                    claimed_digest: *digest,
                })
            }
            ChainEvent::TaskAborted { task_id, reason } => {
                let t = g.tasks.entry(*task_id).or_default();
                t.task_id = *task_id;
                t.status = TaskStatus::Aborted;
                t.epochs.values_mut().for_each(|e| {
                    e.winner = None;
                });
                debug!(task = %task_id, reason = %hex::encode(reason), "task aborted");
            }
            ChainEvent::TaskSettled {
                task_id,
                user_pool,
                node_pool,
                committee_pool,
            } => {
                let t = g.tasks.entry(*task_id).or_default();
                t.task_id = *task_id;
                t.settled = true;
                info!(
                    task = %task_id,
                    user_pool, node_pool, committee_pool,
                    "task escrow distributed"
                );
            }
            ChainEvent::NodeRewardChannelOpened {
                task_id,
                epoch,
                node: _,
                channel_id,
                max_cumulative,
                unlock_at,
                first_slice,
            } => {
                // The only log that links an epoch to the channel that pays it. The vault's own
                // `ChannelOpened` follows in the same transaction and carries the amounts; this
                // one carries the epoch.
                let t = g.tasks.entry(*task_id).or_default();
                t.task_id = *task_id;
                let e = t.epochs.entry(*epoch).or_default();
                e.channel = Some(*channel_id);
                e.amount = *max_cumulative;
                debug!(
                    task = %task_id,
                    epoch,
                    channel = %channel_id,
                    unlock_at,
                    first_slice,
                    "reward channel announced"
                );
            }
            ChainEvent::ChannelOpened {
                channel_id,
                task_id,
                node,
                streamer,
                max_cumulative,
                unlock_at,
            } => {
                let fresh = !g.channels.contains_key(channel_id);
                // Replace, never merge: a `ChannelOpened` for a channel we already hold is a
                // replay (reorg recovery, or the same log re-read after a restart). Overwriting
                // it would reset `withdrawn` to zero and make the node try to `redeem` slices
                // the contract has already paid, and the fold would lose the reclaim bookkeeping
                // with them.
                if fresh {
                    g.channels.insert(
                        *channel_id,
                        ChannelState {
                            channel_id: *channel_id,
                            task_id: *task_id,
                            node: *node,
                            streamer: *streamer,
                            max_cumulative: *max_cumulative,
                            withdrawn: 0,
                            consumed: 0,
                            unlock_at: *unlock_at,
                            closed: false,
                        },
                    );
                    if *node == me.unwrap_or(Address::ZERO) && *max_cumulative > 0 {
                        work.push(Work::Redeem {
                            channel_id: *channel_id,
                        });
                    }
                }
            }
            ChainEvent::SliceRedeemed {
                channel_id,
                node,
                cumulative,
                amount,
                slice_index,
            } => {
                let (went_backwards, ours, exhausted) = {
                    let Some(c) = g.channels.get_mut(channel_id) else {
                        return work;
                    };
                    let went_backwards = *cumulative < c.withdrawn;
                    if !went_backwards {
                        c.withdrawn = *cumulative;
                        c.node = *node;
                        // `slice_index` is the low 64 bits of a `uint256` data word (`u64_of`
                        // truncates, it does not reject), so nothing bounds it below `u64::MAX`:
                        // a plain `+ 1` would panic in debug and wrap in release.
                        c.consumed = c.consumed.max(slice_index.saturating_add(1));
                    }
                    (
                        went_backwards,
                        Some(*node) == me,
                        c.withdrawn >= c.max_cumulative,
                    )
                };
                if went_backwards {
                    g.tainted = true;
                    warn!(channel = %channel_id, "cumulative went backwards; state is tainted");
                    return work;
                }
                if ours && *amount > 0 {
                    // `redeem` *credits* `pendingWithdrawal` rather than transferring, so the
                    // tokens are earned but not held until `claim` lands.
                    work.push(Work::Claim);
                }
                if ours && exhausted {
                    work.push(Work::Reclaim {
                        channel_id: *channel_id,
                    });
                }
            }
            ChainEvent::ChannelReclaimed {
                channel_id,
                node,
                amount,
            } => {
                if let Some(c) = g.channels.get_mut(channel_id) {
                    c.closed = true;
                    c.node = *node;
                }
                // `reclaim` pays the *unwithdrawn* remainder to the node that called it, so a
                // reclaim with a non-zero amount is more credited balance to collect.
                if Some(*node) == me && *amount > 0 {
                    work.push(Work::Claim);
                }
                debug!(channel = %channel_id, amount, "channel reclaimed");
            }
        }

        if !work.is_empty() {
            g.queue.extend(work.iter().cloned());
        }
        drop(g);
        for w in &work {
            // `send` only fails with no subscribers, which is normal at start-up.
            let _ = self.tx.send(w.clone());
        }
        work
    }

    /// Drain queued work. Used by the worker loop.
    pub fn take_work(&self) -> Vec<Work> {
        std::mem::take(&mut self.write().queue)
    }

    /// Queue a nudge the fold could not produce from a log.
    ///
    /// Registration is the case this exists for: `registerNode` emits nothing, so a node that
    /// registers while an epoch is already open would otherwise never be told that the epoch is now
    /// executable by it. A nudge carries no derived fact — it changes nothing in the fold, and the
    /// worker still re-reads the contract before spending gas, so a wrong nudge costs one point read.
    pub fn nudge(&self, work: Work) {
        self.write().queue.push(work.clone());
        let _ = self.tx.send(work);
    }

    pub fn task(&self, id: U256) -> Option<TaskState> {
        self.read().tasks.get(&id).cloned()
    }

    pub fn task_ids(&self) -> Vec<U256> {
        let mut ids: Vec<U256> = self.read().tasks.keys().copied().collect();
        ids.sort();
        ids
    }

    pub fn channel(&self, id: U256) -> Option<ChannelState> {
        self.read().channels.get(&id).cloned()
    }

    pub fn channels_for(&self, node: Address) -> Vec<ChannelState> {
        self.read()
            .channels
            .values()
            .filter(|c| c.node == node)
            .cloned()
            .collect()
    }

    pub fn is_tainted(&self) -> bool {
        self.read().tainted
    }

    pub fn clear_tainted(&self) {
        self.write().tainted = false;
    }

    pub fn task_count(&self) -> usize {
        self.read().tasks.len()
    }

    /// Tasks that still expect an epoch from us.
    pub fn pending_epochs(&self, me: Address) -> Vec<(U256, u32)> {
        let g = self.read();
        // A fold that flagged itself as inconsistent must not drive execution: the Execute
        // nudge would send the node off to compute an epoch against state it has already
        // declared wrong. The only exit is a re-anchored replay, which calls `reset()` and
        // clears the flag (and `clear_tainted` for the test/embed path).
        if g.tainted {
            return Vec::new();
        }
        let mut out = Vec::new();
        for t in g.tasks.values() {
            if !t.registered || t.status.is_terminal() || t.settled {
                continue;
            }
            out.extend(t.epochs_to_execute(me).into_iter().map(|e| (t.task_id, e)));
        }
        out.sort_by_key(|(task, epoch)| (*task, *epoch));
        out
    }

    pub fn last_checkpoint(&self) -> Option<Checkpoint> {
        self.read().last_checkpoint.clone()
    }

    /// Persist the whole derived state. Optional: it is rebuildable, but keeping it makes a
    /// cold start fast and gives an operator something to inspect.
    pub async fn snapshot(&self, dir: &Path) -> Result<()> {
        #[derive(Serialize)]
        struct SnapshotOwned {
            tasks: HashMap<U256, TaskState>,
            channels: HashMap<U256, ChannelState>,
            checkpoint: Option<Checkpoint>,
        }
        let snap = {
            let g = self.read();
            SnapshotOwned {
                tasks: g.tasks.clone(),
                channels: g.channels.clone(),
                checkpoint: g.last_checkpoint.clone(),
            }
        };
        let bytes = serde_json::to_vec_pretty(&snap)?;
        tokio::fs::create_dir_all(dir).await?;
        let tmp = dir.join("derived.json.tmp");
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, dir.join("derived.json")).await?;
        Ok(())
    }

    /// Load the snapshot written by [`NodeState::snapshot`]. `Ok(false)` means there was nothing
    /// usable to load, which is a normal state and not an error.
    ///
    /// The snapshot is what makes a restart cheap *and* correct. Resuming the watcher cursor
    /// without it leaves every task whose last event sits behind the checkpoint invisible until
    /// its next event arrives, so a node restarting mid-epoch would redeem nothing, finalize
    /// nothing and reclaim nothing until the chain moved on its own.
    pub async fn restore_snapshot(&self, dir: &Path) -> Result<bool> {
        #[derive(Deserialize)]
        struct SnapshotOwned {
            tasks: HashMap<U256, TaskState>,
            channels: HashMap<U256, ChannelState>,
            checkpoint: Option<Checkpoint>,
        }
        let Ok(bytes) = tokio::fs::read(dir.join("derived.json")).await else {
            return Ok(false);
        };
        let Ok(snap) = serde_json::from_slice::<SnapshotOwned>(&bytes) else {
            // A snapshot we cannot parse is a snapshot we must not use. The fold rebuilds
            // from the watcher's backfill; starting without one only costs time.
            warn!("derived snapshot is unreadable; the fold rebuilds from the chain");
            return Ok(false);
        };
        {
            let mut g = self.write();
            g.tasks = snap.tasks;
            g.channels = snap.channels;
            g.last_checkpoint = snap.checkpoint;
            g.queue.clear();
            g.tainted = false;
        }
        Ok(true)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        // A poisoned lock means some other thread panicked while folding. The state is derived
        // and rebuildable, so recovering is strictly better than propagating a panic through
        // the whole node — and it is logged so the bug is still visible.
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: Address = Address::repeat_byte(0x99);
    const OTHER: Address = Address::repeat_byte(0x11);

    fn state() -> NodeState {
        let s = NodeState::new();
        s.set_operator(NODE);
        s
    }

    fn sealed(s: &NodeState, task: u32) {
        s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(task),
            ct_root: B256::repeat_byte(0xaa),
            shards: 1,
            contributors: 1,
        });
    }

    fn opened(s: &NodeState, task: u32, epoch: u32) {
        s.apply(&ChainEvent::EpochOpened {
            task_id: U256::from(task),
            epoch,
            enc_weights_cid: B256::repeat_byte(0x0e),
            weights_digest: B256::repeat_byte(0x0f),
        });
    }

    fn committed(s: &NodeState, task: u32, epoch: u32, node: Address, d: u8) -> Vec<Work> {
        s.apply(&ChainEvent::EpochCommitted {
            task_id: U256::from(task),
            epoch,
            node,
            trace_digest: B256::repeat_byte(d),
        })
    }

    #[test]
    fn sealing_a_task_asks_to_register_and_nothing_else() {
        let s = state();
        sealed(&s, 1);
        assert_eq!(
            s.take_work(),
            vec![Work::Register {
                task_id: U256::from(1)
            }],
            "the seal is the last moment `registerNode` is early"
        );
        assert!(
            s.take_work().is_empty(),
            "the queued nudge is consumed by the drain"
        );
        assert_eq!(s.task(U256::from(1)).unwrap().status, TaskStatus::Sealed);
    }

    #[test]
    fn an_open_epoch_we_can_take_produces_execute_work() {
        let s = state();
        sealed(&s, 2);
        s.mark_registered(U256::from(2), true);
        s.take_work();
        opened(&s, 2, 0);
        assert_eq!(
            s.take_work(),
            vec![Work::Execute {
                task_id: U256::from(2),
                epoch: 0
            }]
        );
    }

    #[test]
    fn an_open_epoch_before_registration_asks_to_register() {
        // Committing without registering reverts `NodeNotRegistered`, so the prerequisite is the
        // only useful nudge — and the next epoch is then ours to execute.
        let s = state();
        sealed(&s, 3);
        s.take_work();
        opened(&s, 3, 0);
        assert_eq!(
            s.take_work(),
            vec![Work::Register {
                task_id: U256::from(3)
            }]
        );
        s.mark_registered(U256::from(3), true);
        opened(&s, 3, 1);
        assert_eq!(
            s.take_work(),
            vec![Work::Execute {
                task_id: U256::from(3),
                epoch: 1
            }]
        );
    }

    #[test]
    fn a_second_commit_from_the_same_node_is_ignored() {
        let s = state();
        s.mark_registered(U256::from(4), true);
        committed(&s, 4, 0, OTHER, 0xaa);
        s.take_work();
        let work = committed(&s, 4, 0, OTHER, 0xbb);
        assert!(work.is_empty(), "a duplicate commit must not produce work");
        let t = s.task(U256::from(4)).unwrap();
        assert_eq!(t.epoch(0).unwrap().commits.len(), 1);
        assert_eq!(
            t.epoch(0).unwrap().commits[&OTHER].trace_digest,
            B256::repeat_byte(0xaa)
        );
        assert!(s.is_tainted(), "contradictory commits must taint the state");
    }

    #[test]
    fn our_own_commit_queues_only_the_finalize() {
        let s = state();
        s.mark_registered(U256::from(5), true);
        opened(&s, 5, 0);
        s.take_work();
        // Our own commit is verified by inclusion (`commitEpoch` reverts on a bad proof, and a
        // revert takes the log with it), and somebody still has to close the window:
        // `finalizeEpoch` is permissionless, so the fold nudges it. No dispute: the claim is
        // ours, and no re-execution: there is nothing to re-derive an opinion about.
        assert_eq!(
            committed(&s, 5, 0, NODE, 0xaa),
            vec![Work::Finalize {
                task_id: U256::from(5),
                epoch: 0
            }]
        );
    }

    #[test]
    fn a_foreign_commit_queues_a_finalize_and_a_reexecution_when_we_have_not_committed() {
        let s = state();
        s.mark_registered(U256::from(6), true);
        opened(&s, 6, 0);
        s.take_work();
        let work = committed(&s, 6, 0, OTHER, 0xaa);
        assert!(
            work.contains(&Work::Finalize {
                task_id: U256::from(6),
                epoch: 0
            }),
            "the epoch window needs closing: {work:?}"
        );
        assert!(
            work.contains(&Work::Reexecute {
                task_id: U256::from(6),
                epoch: 0,
                claimed_digest: B256::repeat_byte(0xaa)
            }),
            "we have no commit yet, so this is the re-executor's job: {work:?}"
        );
    }

    #[test]
    fn a_dispute_needs_our_verified_commit_and_a_different_claim() {
        let s = state();
        s.mark_registered(U256::from(7), true);
        opened(&s, 7, 0);
        // We commit first, so ours is the claim until the lower address takes it.
        committed(&s, 7, 0, NODE, 0xaa);
        s.take_work();
        // A peer commits a different digest. Our commit is verified by inclusion —
        // `commitEpoch` emits `EpochCommitted` only after the verifier said yes, and a revert
        // takes the log with it — so there is nothing to wait for: the claim (the lower
        // address, the peer's `0xbb`) disagrees with our verified `0xaa`, and `reportDispute`
        // is callable.
        let work = committed(&s, 7, 0, OTHER, 0xbb);
        assert_eq!(
            work,
            vec![Work::FileDispute {
                task_id: U256::from(7),
                epoch: 0,
                // The contract requires the reported digest to equal our own commit, not the
                // peer's claim.
                our_digest: B256::repeat_byte(0xaa)
            }],
            "a verified commit against a foreign claim disputes at once: {work:?}"
        );
        // Verification re-lands (same-transaction log order on replay, or a re-read window):
        // an idempotent re-nudge, which the worker dedups rather than double-filing.
        let work = s.apply(&ChainEvent::EpochVerified {
            task_id: U256::from(7),
            epoch: 0,
            node: NODE,
            ok: true,
        });
        assert_eq!(
            work,
            vec![Work::FileDispute {
                task_id: U256::from(7),
                epoch: 0,
                // The contract requires the reported digest to equal our own commit, not the
                // peer's claim.
                our_digest: B256::repeat_byte(0xaa)
            }]
        );
    }

    #[test]
    fn a_verified_commit_that_matches_the_claim_files_nothing() {
        let s = state();
        s.mark_registered(U256::from(8), true);
        opened(&s, 8, 0);
        committed(&s, 8, 0, OTHER, 0xaa);
        s.take_work();
        committed(&s, 8, 0, NODE, 0xaa);
        s.take_work();
        let work = s.apply(&ChainEvent::EpochVerified {
            task_id: U256::from(8),
            epoch: 0,
            node: NODE,
            ok: true,
        });
        assert!(
            work.is_empty(),
            "agreeing with the claim must not file: {work:?}"
        );
    }

    #[test]
    fn a_failed_verification_files_nothing() {
        let s = state();
        s.mark_registered(U256::from(9), true);
        opened(&s, 9, 0);
        committed(&s, 9, 0, NODE, 0xaa);
        s.take_work();
        committed(&s, 9, 0, OTHER, 0xbb);
        s.take_work();
        let work = s.apply(&ChainEvent::EpochVerified {
            task_id: U256::from(9),
            epoch: 0,
            node: NODE,
            ok: false,
        });
        assert!(
            work.is_empty(),
            "a proof the verifier rejected cannot back a dispute"
        );
        assert!(!s.task(U256::from(9)).unwrap().epoch(0).unwrap().commits[&NODE].verified);
    }

    #[test]
    fn a_rejected_epoch_still_counts_as_closed() {
        let s = state();
        let work = s.apply(&ChainEvent::EpochRejected {
            task_id: U256::from(10),
            epoch: 0,
            reporters: 3,
        });
        assert!(work.is_empty());
        let t = s.task(U256::from(10)).unwrap();
        assert!(t.epoch(0).unwrap().rejected);
        assert_eq!(t.status, TaskStatus::EpochSettled);
    }

    #[test]
    fn epoch_settled_nudges_a_settle_once() {
        let s = state();
        let ev = ChainEvent::EpochSettled {
            task_id: U256::from(11),
            epoch: 0,
            node: OTHER,
            amount: 100,
        };
        assert_eq!(
            s.apply(&ev),
            vec![Work::Settle {
                task_id: U256::from(11)
            }]
        );
        assert!(
            s.apply(&ev).is_empty(),
            "replaying the log must not queue it twice"
        );
    }

    #[test]
    fn only_our_own_channel_is_queued_for_a_redeem() {
        let s = state();
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(1),
            task_id: U256::from(11),
            node: OTHER,
            streamer: Address::repeat_byte(0x33),
            max_cumulative: 1_000,
            unlock_at: 100,
        });
        assert!(
            s.take_work().is_empty(),
            "a channel owed to another node is not ours to redeem"
        );
        let work = s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(2),
            task_id: U256::from(11),
            node: NODE,
            streamer: Address::repeat_byte(0x33),
            max_cumulative: 1_000,
            unlock_at: 100,
        });
        assert_eq!(
            work,
            vec![Work::Redeem {
                channel_id: U256::from(2)
            }]
        );
    }

    #[test]
    fn a_fully_drawn_channel_is_queued_for_reclaim() {
        let s = state();
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(3),
            task_id: U256::from(11),
            node: NODE,
            streamer: Address::repeat_byte(0x33),
            max_cumulative: 1_000,
            unlock_at: 100,
        });
        s.take_work();
        let work = s.apply(&ChainEvent::SliceRedeemed {
            channel_id: U256::from(3),
            node: NODE,
            cumulative: 1_000,
            amount: 1_000,
            slice_index: 0,
        });
        assert_eq!(
            work,
            vec![
                Work::Claim,
                Work::Reclaim {
                    channel_id: U256::from(3)
                }
            ]
        );
        assert_eq!(s.channel(U256::from(3)).unwrap().consumed, 1);
        assert_eq!(s.channel(U256::from(3)).unwrap().remaining(), 0);
    }

    #[test]
    fn a_partial_redeem_asks_for_a_claim_but_not_a_reclaim() {
        // `redeem` credits `pendingWithdrawal` instead of transferring, so even a partial draw
        // leaves tokens the node does not yet hold. Reclaiming would be wrong: the channel still
        // has authorisation left to draw.
        let s = state();
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(4),
            task_id: U256::from(11),
            node: NODE,
            streamer: Address::repeat_byte(0x33),
            max_cumulative: 1_000,
            unlock_at: 100,
        });
        let work = s.apply(&ChainEvent::SliceRedeemed {
            channel_id: U256::from(4),
            node: NODE,
            cumulative: 400,
            amount: 400,
            slice_index: 0,
        });
        assert_eq!(work, vec![Work::Claim], "{work:?}");
    }

    #[test]
    fn a_redeem_of_someone_elses_channel_asks_for_nothing() {
        let s = state();
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(12),
            task_id: U256::from(11),
            node: OTHER,
            streamer: Address::repeat_byte(0x33),
            max_cumulative: 1_000,
            unlock_at: 100,
        });
        let work = s.apply(&ChainEvent::SliceRedeemed {
            channel_id: U256::from(12),
            node: OTHER,
            cumulative: 1_000,
            amount: 1_000,
            slice_index: 0,
        });
        assert!(
            work.is_empty(),
            "another node's payout is not ours to claim: {work:?}"
        );
    }

    #[test]
    fn a_zero_amount_reclaim_credits_nothing_to_claim() {
        let s = state();
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(13),
            task_id: U256::from(11),
            node: NODE,
            streamer: Address::repeat_byte(0x33),
            max_cumulative: 1_000,
            unlock_at: 100,
        });
        s.apply(&ChainEvent::SliceRedeemed {
            channel_id: U256::from(13),
            node: NODE,
            cumulative: 1_000,
            amount: 1_000,
            slice_index: 0,
        });
        s.take_work();
        let work = s.apply(&ChainEvent::ChannelReclaimed {
            channel_id: U256::from(13),
            node: NODE,
            amount: 0,
        });
        assert!(
            work.is_empty(),
            "nothing was pushed, so there is nothing to claim: {work:?}"
        );
    }

    #[test]
    fn a_backwards_cumulative_taints_the_state() {
        let s = state();
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(5),
            task_id: U256::from(11),
            node: NODE,
            streamer: Address::repeat_byte(0x33),
            max_cumulative: 1_000,
            unlock_at: 100,
        });
        s.apply(&ChainEvent::SliceRedeemed {
            channel_id: U256::from(5),
            node: NODE,
            cumulative: 400,
            amount: 400,
            slice_index: 0,
        });
        assert!(!s.is_tainted());
        s.apply(&ChainEvent::SliceRedeemed {
            channel_id: U256::from(5),
            node: NODE,
            cumulative: 200,
            amount: 100,
            slice_index: 1,
        });
        assert!(s.is_tainted());
        assert_eq!(
            s.channel(U256::from(5)).unwrap().withdrawn,
            400,
            "a bad event must not corrupt the recorded cumulative"
        );
    }

    #[test]
    fn reclaiming_closes_the_channel() {
        let s = state();
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(6),
            task_id: U256::from(11),
            node: NODE,
            streamer: Address::repeat_byte(0x33),
            max_cumulative: 1_000,
            unlock_at: 100,
        });
        s.apply(&ChainEvent::ChannelReclaimed {
            channel_id: U256::from(6),
            node: NODE,
            amount: 0,
        });
        let c = s.channel(U256::from(6)).unwrap();
        assert!(c.closed);
        assert_eq!(
            c.remaining(),
            1_000,
            "a reclaim does not erase the authorisation"
        );
    }

    #[test]
    fn the_reward_channel_announcement_links_the_epoch_to_its_channel() {
        let s = state();
        s.apply(&ChainEvent::NodeRewardChannelOpened {
            task_id: U256::from(12),
            epoch: 1,
            node: NODE,
            channel_id: U256::from(9),
            max_cumulative: 75_000_000,
            unlock_at: 1_792_254_461,
            first_slice: 75_000_000,
        });
        let t = s.task(U256::from(12)).unwrap();
        assert_eq!(t.epoch(1).unwrap().channel, Some(U256::from(9)));
    }

    #[test]
    fn contributions_rebuild_the_ct_root_the_chain_sealed() {
        // The three leaves are the `ciphertextCid`s of the Hardhat run the fixtures came from and
        // the root below is what `ctRootOf` returned after them — the same value
        // `chain::transcript::ct_root_steps_match_the_chain` pins. Asserting our fold against that
        // constant is the point: comparing the fold with itself would pass on any seed.
        let s = state();
        let cids = [
            "0x7cb28e2fbd63cc4d4a519f09950cf70541ff7d13878e887d59fb1341ac17890c",
            "0x444d61d4497174c690bdb4fd4bbcac1a652b91a47223a97074a78dbd5496f6e3",
            "0x4780e827121b4e535b1661f87ed03f1ea1c3845f7c059087f524423d53238403",
        ];
        for (i, cid) in cids.iter().enumerate() {
            s.apply(&ChainEvent::ContributionSubmitted {
                task_id: U256::from(13),
                contributor: OTHER,
                leaf_index: i as u32,
                ciphertext_cid: cid.parse::<B256>().expect("fixture cid"),
                rows: 1_000,
            });
        }
        // `derived_ct_root` is gated on the sealed contributor count (a prefix of the leaves
        // must not read as a mismatch for a watcher that joined mid-chain), so the comparison
        // happens after the seal lands — with the fixture root the chain reported.
        let fixture: B256 = "0xa3d7329343c8b278393d3e6d990e99e514d3474f8d4f4df834630ecbdf9d0827"
            .parse()
            .expect("fixture root");
        s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(13),
            ct_root: fixture,
            shards: 3,
            contributors: 3,
        });
        let derived = s
            .task(U256::from(13))
            .unwrap()
            .derived_ct_root()
            .expect("three contiguous leaves");
        assert_eq!(
            derived, fixture,
            "the fold must reproduce the root the chain sealed"
        );
        assert!(!s.is_tainted(), "a matching ctRoot must not taint");
    }

    #[test]
    fn a_seal_that_disagrees_with_our_leaves_taints_the_state() {
        let s = state();
        for i in 0..2u32 {
            s.apply(&ChainEvent::ContributionSubmitted {
                task_id: U256::from(14),
                contributor: OTHER,
                leaf_index: i,
                ciphertext_cid: B256::repeat_byte(i as u8 + 1),
                rows: 10,
            });
        }
        s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(14),
            ct_root: B256::repeat_byte(0xff),
            shards: 1,
            contributors: 2,
        });
        assert!(s.is_tainted(), "a wrong ctRoot must stop the node");
    }

    #[test]
    fn an_incomplete_leaf_history_is_not_reported_as_a_mismatch() {
        // A watcher that joined mid-chain has some but not all contributions. Deriving a root
        // from a prefix would flag every historical task as corrupt.
        let s = state();
        s.apply(&ChainEvent::ContributionSubmitted {
            task_id: U256::from(15),
            contributor: OTHER,
            leaf_index: 1,
            ciphertext_cid: B256::repeat_byte(2),
            rows: 10,
        });
        assert_eq!(s.task(U256::from(15)).unwrap().derived_ct_root(), None);
        s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(15),
            ct_root: B256::repeat_byte(0xff),
            shards: 1,
            contributors: 7,
        });
        assert!(!s.is_tainted());
    }

    #[test]
    fn pending_epochs_requires_registration_and_skips_ours_and_closed_ones() {
        let s = state();
        opened(&s, 16, 0);
        assert!(s.pending_epochs(NODE).is_empty(), "not registered yet");
        s.mark_registered(U256::from(16), true);
        assert_eq!(s.pending_epochs(NODE), vec![(U256::from(16), 0)]);
        committed(&s, 16, 0, NODE, 0xaa);
        assert!(s.pending_epochs(NODE).is_empty(), "we already committed");
        s.apply(&ChainEvent::EpochSettled {
            task_id: U256::from(16),
            epoch: 0,
            node: NODE,
            amount: 1,
        });
        assert!(s.pending_epochs(NODE).is_empty());
    }

    #[test]
    fn a_settled_task_is_not_pending() {
        let s = state();
        s.mark_registered(U256::from(17), true);
        opened(&s, 17, 0);
        s.apply(&ChainEvent::TaskSettled {
            task_id: U256::from(17),
            user_pool: 800_000_000,
            node_pool: 150_000_000,
            committee_pool: 50_000_000,
        });
        assert!(s.pending_epochs(NODE).is_empty());
        assert!(s.task(U256::from(17)).unwrap().settled);
    }

    #[test]
    fn an_abort_makes_the_task_terminal() {
        let s = state();
        s.mark_registered(U256::from(18), true);
        opened(&s, 18, 0);
        s.apply(&ChainEvent::TaskAborted {
            task_id: U256::from(18),
            reason: [0xb5, 0x51, 0xa2, 0x2b],
        });
        assert_eq!(s.task(U256::from(18)).unwrap().status, TaskStatus::Aborted);
        assert!(s.pending_epochs(NODE).is_empty());
    }

    #[test]
    fn without_an_operator_the_fold_queues_only_the_permissionless_work() {
        let s = NodeState::new();
        s.mark_registered(U256::from(19), true);
        let work = s.apply(&ChainEvent::EpochCommitted {
            task_id: U256::from(19),
            epoch: 0,
            node: OTHER,
            trace_digest: B256::repeat_byte(1),
        });
        // `finalizeEpoch` restricts no caller, so an open epoch still has to be closed without an
        // identity: this is the chain's work, not the node's. Everything that *is* the node's -
        // redeeming, disputing, claiming - stays unqueued until the fold knows the operator.
        assert_eq!(
            work,
            vec![Work::Finalize {
                task_id: U256::from(19),
                epoch: 0
            }]
        );
    }

    #[test]
    fn channel_remaining_never_goes_negative() {
        let c = ChannelState {
            max_cumulative: 100,
            withdrawn: 250,
            ..Default::default()
        };
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn reset_clears_tasks_and_channels_but_keeps_the_chain_id_and_operator() {
        let s = state();
        s.set_chain_id(31_338);
        sealed(&s, 20);
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(1),
            task_id: U256::from(20),
            node: NODE,
            streamer: Address::ZERO,
            max_cumulative: 1,
            unlock_at: 0,
        });
        s.reset();
        assert_eq!(s.task_count(), 0);
        assert!(s.channel(U256::from(1)).is_none());
        assert_eq!(s.chain_id(), 31_338);
        assert_eq!(s.operator(), Some(NODE));
    }

    #[test]
    fn a_ct_root_change_for_a_seen_task_taints_the_state() {
        let s = state();
        sealed(&s, 21);
        s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(21),
            ct_root: B256::repeat_byte(0xbb),
            shards: 1,
            contributors: 1,
        });
        assert!(s.is_tainted());
    }

    #[test]
    fn a_commit_without_a_preceding_open_or_seal_still_lands() {
        // Mid-history start: the fold must not need the earlier logs to record a claim.
        let s = state();
        committed(&s, 22, 3, OTHER, 0xaa);
        let t = s.task(U256::from(22)).unwrap();
        assert_eq!(t.epoch(3).unwrap().commits.len(), 1);
        assert_eq!(t.status, TaskStatus::EpochCommitting);
    }

    #[test]
    fn status_round_trips_through_u8() {
        for s in [
            TaskStatus::None,
            TaskStatus::Opening,
            TaskStatus::Collecting,
            TaskStatus::Sealed,
            TaskStatus::EpochOpen,
            TaskStatus::EpochCommitting,
            TaskStatus::EpochSettled,
            TaskStatus::Settling,
            TaskStatus::Revealing,
            TaskStatus::Disclosed,
            TaskStatus::Aborted,
        ] {
            assert_eq!(TaskStatus::from_u8(s as u8), Some(s));
        }
        // The contract has no `Paused` status; a fabricated 11th value would make
        // `from_u8(11)` succeed on chain data that cannot exist.
        assert_eq!(TaskStatus::from_u8(11), None);
        assert_eq!(TaskStatus::from_u8(200), None);
    }

    #[test]
    fn terminal_statuses_are_recognised() {
        assert!(TaskStatus::Disclosed.is_terminal());
        assert!(TaskStatus::Aborted.is_terminal());
        assert!(!TaskStatus::EpochCommitting.is_terminal());
        assert!(!TaskStatus::EpochSettled.is_terminal());
    }

    fn commit(digest: u8) -> CommitRecord {
        CommitRecord {
            trace_digest: B256::repeat_byte(digest),
            verified: true,
        }
    }

    #[test]
    fn claimed_digest_is_the_lowest_address_committer() {
        let mut e = EpochState::default();
        e.commits.insert(NODE, commit(0xaa));
        e.commits.insert(OTHER, commit(0xbb));
        // `BTreeMap` orders by address, which is not insertion order — and that is the point:
        // `commitEpoch` takes the winner slot when `incumbent == address(0) || sender < incumbent`,
        // so the claim on chain belongs to the *lowest* address among the committers. Here that is
        // `OTHER` (`0x11..`), whose commit was inserted second.
        assert_eq!(e.claimed_digest(), Some(B256::repeat_byte(0xbb)));
    }

    #[test]
    fn a_nudge_from_outside_the_fold_is_drained_like_any_other() {
        let s = NodeState::new();
        s.nudge(Work::Execute {
            task_id: U256::from(9),
            epoch: 2,
        });
        assert_eq!(
            s.take_work(),
            vec![Work::Execute {
                task_id: U256::from(9),
                epoch: 2
            }]
        );
        assert!(s.take_work().is_empty(), "the queue is drained, not peeked");
    }
}
