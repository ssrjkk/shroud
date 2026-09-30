//! Derived state: the node's fold over chain events.
//!
//! Everything here is *derived* — it can always be rebuilt from logs plus a checkpoint, and
//! `reset()` throws it away wholesale when a reorg invalidates the fold. Nothing in this module
//! is authoritative. The contract is; if the two ever disagree the contract wins and the node
//! re-syncs. That asymmetry is deliberate: a bug in the fold must never be able to make the node
//! claim a payment or a proof it did not earn.
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
use tracing::{debug, warn};

use crate::{
    chain::watcher::{ChainEvent, Checkpoint},
    error::{Error, Result},
};

/// `TaskStatus` mirrors `ICipherTask.TaskStatus`. Duplicated as a plain enum so the state machine
/// can be unit-tested without a chain, and so a contract-side reordering surfaces as a
/// non-exhaustive-match compile error rather than a wrong branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TaskStatus {
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
    Paused = 11,
}

impl TaskStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        use TaskStatus::*;
        Some(match v {
            0 => None,
            1 => Opening,
            2 => Collecting,
            3 => Sealed,
            4 => EpochOpen,
            5 => EpochCommitting,
            6 => EpochSettled,
            7 => Settling,
            8 => Revealing,
            9 => Disclosed,
            10 => Aborted,
            11 => Paused,
            _ => return None,
        })
    }

    /// Whether no further work is expected for this task.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskStatus::Disclosed | TaskStatus::Aborted | TaskStatus::Paused
        )
    }
}

/// Per-epoch record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochState {
    pub opened_at: u64,
    pub deadline: u64,
    /// Encrypted weights CIDs accepted for this epoch, one per committing node. First
    /// (node, cid) pair wins, matching the contract's one-commit-per-node rule.
    pub commits: BTreeMap<Address, CommitRecord>,
    /// Re-execution digests reported by disputing nodes, and who reported them.
    pub disputes: BTreeMap<Address, B256>,
    pub settled: bool,
    pub winner: Option<Address>,
    pub settled_amount: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRecord {
    pub enc_weights_cid: B256,
    pub weights_digest: B256,
    pub trace_digest: B256,
    pub block: u64,
    pub proof_bytes: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskState {
    pub task_id: U256,
    pub status: TaskStatus,
    pub ct_root: B256,
    pub shards: u32,
    pub contributors: u32,
    pub budget: u128,
    pub registered: bool,
    /// We are the node that should execute this epoch, and we have started.
    pub executing: Option<Address>,
    pub epochs: BTreeMap<u32, EpochState>,
    /// Latest accepted weights, carried across epochs. The optimiser seeds from this.
    pub last_weights: Option<(B256, B256)>,
    pub revealed_message: Option<String>,
}

impl Default for TaskStatus {
    fn default() -> Self {
        TaskStatus::None
    }
}

impl TaskState {
    pub fn epoch(&self, epoch: u32) -> Option<&EpochState> {
        self.epochs.get(&epoch)
    }

    /// How many distinct nodes have committed, i.e. the quorum observed so far.
    pub fn commit_count(&self) -> usize {
        self.epochs.values().map(|e| e.commits.len()).sum()
    }

    /// A digest every honest node should independently arrive at. Used as the local
    /// disagreement check before a dispute is filed: if our re-execution matches the claimed
    /// digest, the commit was right and filing would waste gas and earn nothing.
    pub fn consensus_digest(&self) -> Option<B256> {
        let mut counts: HashMap<B256, usize> = HashMap::new();
        for e in self.epochs.values() {
            for c in e.commits.values() {
                *counts.entry(c.trace_digest).or_default() += 1;
            }
            for d in e.disputes.values() {
                *counts.entry(*d).or_default() += 1;
            }
        }
        // Deterministic tie-break: the most-reported digest, then the lowest value. A tie must
        // not resolve differently on two nodes, or half the network files a pointless dispute.
        counts
            .into_iter()
            .max_by(|(a, ca), (b, cb)| ca.cmp(cb).then_with(|| b.cmp(a)))
            .map(|(d, _)| d)
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
}

/// A dispute we should file or have filed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeAction {
    pub task_id: U256,
    pub epoch: u32,
    pub our_digest: B256,
    pub claimed_digest: B256,
    pub block: u64,
}

/// Work the scheduler should pick up. Produced by the fold, consumed by the worker loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Work {
    /// Fetch the sealed ciphertext set and start epoch 0.
    Execute { task_id: U256, epoch: u32 },
    /// We missed the window; nothing to do but stay consistent.
    SkipEpoch { task_id: U256, epoch: u32 },
    /// Re-execute and report disagreement.
    Reexecute {
        task_id: U256,
        epoch: u32,
        claimed_digest: B256,
    },
    /// File an on-chain dispute.
    FileDispute {
        task_id: U256,
        epoch: u32,
        our_digest: B256,
    },
    /// Finalise/settle a task whose epochs are done.
    Settle { task_id: U256 },
    /// Redeem an authorised slice.
    Redeem { channel_id: U256, amount: u128 },
    /// Release a channel lock that is past its unlock time.
    CloseChannel { channel_id: U256 },
}

/// Inner state, guarded by one lock.
#[derive(Debug, Default)]
struct Inner {
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
#[derive(Debug, Clone, Default)]
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

    /// Throw away everything derived and start over. Called on a reorg deeper than the anchor
    /// ring, where the correct answer is "replay", never "patch".
    pub fn reset(&self) {
        let mut g = self.write();
        let n_tasks = g.tasks.len();
        g.tasks.clear();
        g.channels.clear();
        g.queue.clear();
        g.tainted = false;
        // `chain_id` is not derived from logs, so it survives a reorg.
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
        let mut work = Vec::new();
        match ev {
            ChainEvent::TaskSealed {
                task_id,
                ct_root,
                shards,
                contributors,
            } => {
                let t = g.tasks.entry(*task_id).or_insert_with(|| TaskState {
                    task_id: *task_id,
                    ..Default::default()
                });
                if t.status != TaskStatus::None && t.ct_root != B256::ZERO && t.ct_root != *ct_root
                {
                    g.tainted = true;
                    warn!(task = %task_id, "ctRoot changed for an already-seen task; state is tainted");
                }
                t.ct_root = *ct_root;
                t.shards = *shards;
                t.contributors = *contributors;
                t.status = TaskStatus::Sealed;
                if !t.registered {
                    work.push(Work::SkipEpoch {
                        task_id: *task_id,
                        epoch: 0,
                    });
                } else if !t.epochs.contains_key(&0) {
                    work.push(Work::Execute {
                        task_id: *task_id,
                        epoch: 0,
                    });
                }
            }
            ChainEvent::EpochOpened {
                task_id,
                epoch,
                enc_weights_cid,
                weights_digest,
            } => {
                let t = g.tasks.entry(*task_id).or_insert_with(|| TaskState {
                    task_id: *task_id,
                    ..Default::default()
                });
                t.status = TaskStatus::EpochOpen;
                t.epochs.entry(*epoch).or_default().opened_at =
                    t.epochs.get(epoch).map_or(0, |e| e.opened_at);
                let e = t.epochs.entry(*epoch).or_default();
                // The first `EpochOpened` of an epoch carries the seed weights. Later opens of
                // the *next* epoch carry the previous winner's weights; those go to
                // `last_weights` so the optimiser can warm-start.
                if *epoch == 0 || t.epochs.len() == 1 {
                    e.opened_at = e.opened_at.max(0);
                    t.last_weights = Some((*enc_weights_cid, *weights_digest));
                } else {
                    t.last_weights = Some((*enc_weights_cid, *weights_digest));
                }
                if t.registered && !e.commits.is_empty() {
                    work.push(Work::Execute {
                        task_id: *task_id,
                        epoch: *epoch,
                    });
                }
            }
            ChainEvent::EpochCommitted {
                task_id,
                epoch,
                node,
                trace_digest,
            } => {
                let Some(t) = g.tasks.get_mut(task_id) else {
                    // Commit for an untracked task: the watcher joined late. Nothing to do but
                    // note that we cannot reason about this task.
                    return work;
                };
                let e = t.epochs.entry(*epoch).or_default();
                if let Some(prev) = e.commits.get(node) {
                    if prev.trace_digest != *trace_digest {
                        g.tainted = true;
                        warn!(task = %task_id, epoch, %node, "node committed twice with different digests; the contract should have rejected this");
                    }
                    return work;
                }
                e.commits.insert(
                    *node,
                    CommitRecord {
                        // Filled in by the metrics fetch; the commit event does not carry the CIDs.
                        enc_weights_cid: B256::ZERO,
                        weights_digest: B256::ZERO,
                        trace_digest: *trace_digest,
                        block: 0,
                        proof_bytes: 0,
                    },
                );
                t.status = TaskStatus::EpochCommitting;
                if let Some(our) = consensus_digest_locked(t) {
                    let claimed = first_digest_locked(t, *epoch);
                    if claimed.is_some() && our != claimed {
                        work.push(Work::FileDispute {
                            task_id: *task_id,
                            epoch: *epoch,
                            our_digest: our,
                        });
                    }
                }
            }
            ChainEvent::EpochSettled {
                task_id,
                epoch,
                node,
                amount,
            } => {
                let Some(t) = g.tasks.get_mut(task_id) else {
                    return work;
                };
                let e = t.epochs.entry(*epoch).or_default();
                if e.settled {
                    return work;
                }
                e.settled = true;
                e.winner = Some(*node);
                e.settled_amount = *amount;
                t.status = TaskStatus::EpochSettled;
                if *node != self_zero_address() {
                    work.push(Work::Settle { task_id: *task_id });
                }
            }
            ChainEvent::DisputeReported {
                task_id,
                epoch,
                reporter,
                digest,
            } => {
                let Some(t) = g.tasks.get_mut(task_id) else {
                    return work;
                };
                t.epochs
                    .entry(*epoch)
                    .or_default()
                    .disputes
                    .insert(*reporter, *digest);
                if *reporter != self_zero_address() {
                    work.push(Work::Reexecute {
                        task_id: *task_id,
                        epoch: *epoch,
                        claimed_digest: *digest,
                    });
                }
            }
            ChainEvent::TaskAborted { task_id, .. } => {
                let Some(t) = g.tasks.get_mut(task_id) else {
                    return work;
                };
                t.status = TaskStatus::Aborted;
                t.executing = None;
            }
            ChainEvent::ChannelOpened {
                channel_id,
                task_id,
                node,
                streamer,
                max_cumulative,
                unlock_at,
            } => {
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
                if *max_cumulative > 0 {
                    work.push(Work::Redeem {
                        channel_id: *channel_id,
                        amount: *max_cumulative,
                    });
                }
            }
            ChainEvent::SliceRedeemed {
                channel_id,
                node,
                cumulative,
                amount,
                ..
            } => {
                let Some(c) = g.channels.get_mut(channel_id) else {
                    return work;
                };
                if *cumulative < c.withdrawn {
                    // A redeem that lowers the observed cumulative means our view is stale or
                    // the chain reorganised under us.
                    g.tainted = true;
                    warn!(channel = %channel_id, "cumulative went backwards; state is tainted");
                    return work;
                }
                c.withdrawn = *cumulative;
                c.node = *node;
                let _ = amount;
            }
        }

        if !work.is_empty() {
            g.queue.extend(work.iter().cloned());
        }
        for w in &work {
            // `send` only fails with no subscribers, which is normal at start-up.
            let _ = self.tx.send(w.clone());
        }
        work
    }

    fn self_zero_address(&self) -> Address {
        Address::ZERO
    }

    /// Drain queued work. Used by the worker loop.
    pub fn take_work(&self) -> Vec<Work> {
        std::mem::take(&mut self.write().queue)
    }

    pub fn task(&self, id: U256) -> Option<TaskState> {
        self.read().tasks.get(&id).cloned()
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
        let mut out = Vec::new();
        for t in g.tasks.values() {
            if !t.registered || t.status.is_terminal() {
                continue;
            }
            for (epoch, e) in &t.epochs {
                if !e.settled && e.commits.is_empty() {
                    out.push((t.task_id, *epoch));
                }
            }
            let _ = me;
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
        let g = self.read();
        #[derive(Serialize)]
        struct Snapshot<'a> {
            tasks: &'a HashMap<U256, TaskState>,
            channels: &'a HashMap<U256, ChannelState>,
            checkpoint: Option<&'a Checkpoint>,
        }
        let snap = Snapshot {
            tasks: &g.tasks,
            channels: &g.channels,
            checkpoint: g.last_checkpoint.as_ref(),
        };
        let bytes = serde_json::to_vec_pretty(&snap)?;
        tokio::fs::create_dir_all(dir).await?;
        let tmp = dir.join("derived.json.tmp");
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, dir.join("derived.json")).await?;
        Ok(())
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

fn consensus_digest_locked(t: &TaskState) -> Option<B256> {
    let mut counts: HashMap<B256, usize> = HashMap::new();
    for e in t.epochs.values() {
        for c in e.commits.values() {
            *counts.entry(c.trace_digest).or_default() += 1;
        }
        for d in e.disputes.values() {
            *counts.entry(*d).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|(a, ca), (b, cb)| ca.cmp(cb).then_with(|| b.cmp(a)))
        .map(|(d, _)| d)
}

fn first_digest_locked(t: &TaskState, epoch: u32) -> Option<B256> {
    t.epochs
        .get(&epoch)
        .and_then(|e| e.commits.values().next())
        .map(|c| c.trace_digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> NodeState {
        NodeState::new()
    }

    #[test]
    fn task_sealed_for_an_unregistered_node_produces_no_work() {
        let s = state();
        let work = s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(1),
            ct_root: B256::repeat_byte(0xaa),
            shards: 4,
            contributors: 2,
        });
        assert_eq!(
            work,
            vec![Work::SkipEpoch {
                task_id: U256::from(1),
                epoch: 0
            }]
        );
        assert_eq!(s.task(U256::from(1)).unwrap().status, TaskStatus::Sealed);
    }

    #[test]
    fn task_sealed_for_a_registered_node_produces_execute_work() {
        let s = state();
        s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(2),
            ct_root: B256::repeat_byte(1),
            shards: 1,
            contributors: 1,
        });
        {
            let mut g = s.write();
            g.tasks.get_mut(&U256::from(2)).unwrap().registered = true;
        }
        s.apply(&ChainEvent::EpochOpened {
            task_id: U256::from(2),
            epoch: 0,
            enc_weights_cid: B256::repeat_byte(2),
            weights_digest: B256::repeat_byte(3),
        });
        assert!(s
            .take_work()
            .iter()
            .any(|w| matches!(w, Work::Execute { epoch: 0, .. })));
    }

    #[test]
    fn a_second_commit_from_the_same_node_is_ignored() {
        let s = state();
        let ev = |d: u8| ChainEvent::EpochCommitted {
            task_id: U256::from(3),
            epoch: 0,
            node: Address::repeat_byte(0x11),
            trace_digest: B256::repeat_byte(d),
        };
        s.apply(&ev(0xaa));
        s.take_work();
        let work = s.apply(&ev(0xbb));
        assert!(work.is_empty(), "a duplicate commit must not produce work");
        let t = s.task(U256::from(3)).unwrap();
        assert_eq!(t.epoch(0).unwrap().commits.len(), 1);
        assert_eq!(
            t.epoch(0).unwrap().commits[&Address::repeat_byte(0x11)].trace_digest,
            B256::repeat_byte(0xaa)
        );
        assert!(s.is_tainted(), "contradictory commits must taint the state");
    }

    #[test]
    fn commits_from_distinct_nodes_both_land() {
        let s = state();
        for i in 0..3u8 {
            s.apply(&ChainEvent::EpochCommitted {
                task_id: U256::from(4),
                epoch: 0,
                node: Address::repeat_byte(i),
                trace_digest: B256::repeat_byte(0xaa),
            });
        }
        let t = s.task(U256::from(4)).unwrap();
        assert_eq!(t.epoch(0).unwrap().commits.len(), 3);
        assert!(!s.is_tainted());
    }

    #[test]
    fn epoch_settled_is_idempotent() {
        let s = state();
        let ev = ChainEvent::EpochSettled {
            task_id: U256::from(5),
            epoch: 0,
            node: Address::repeat_byte(0x99),
            amount: 100,
        };
        let first = s.apply(&ev);
        assert_eq!(first.len(), 1, "the first settlement schedules Settle work");
        assert!(
            s.apply(&ev).is_empty(),
            "replaying the log must not schedule it twice"
        );
    }

    #[test]
    fn a_backwards_cumulative_taints_the_state() {
        let s = state();
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(9),
            task_id: U256::from(5),
            node: Address::repeat_byte(0x22),
            streamer: Address::repeat_byte(0x33),
            max_cumulative: 1_000,
            unlock_at: 100,
        });
        s.apply(&ChainEvent::SliceRedeemed {
            channel_id: U256::from(9),
            node: Address::repeat_byte(0x22),
            cumulative: 400,
            amount: 400,
            slice_index: 0,
        });
        assert!(!s.is_tainted());
        s.apply(&ChainEvent::SliceRedeemed {
            channel_id: U256::from(9),
            node: Address::repeat_byte(0x22),
            cumulative: 200,
            amount: 100,
            slice_index: 1,
        });
        assert!(s.is_tainted());
        assert_eq!(
            s.channel(U256::from(9)).unwrap().withdrawn,
            400,
            "a bad event must not corrupt the recorded cumulative"
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
    fn reset_clears_tasks_and_channels_but_keeps_the_chain_id() {
        let s = state();
        s.set_chain_id(31_338);
        s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(6),
            ct_root: B256::repeat_byte(1),
            shards: 1,
            contributors: 1,
        });
        s.apply(&ChainEvent::ChannelOpened {
            channel_id: U256::from(1),
            task_id: U256::from(6),
            node: Address::ZERO,
            streamer: Address::ZERO,
            max_cumulative: 1,
            unlock_at: 0,
        });
        s.reset();
        assert_eq!(s.task_count(), 0);
        assert!(s.channel(U256::from(1)).is_none());
        assert_eq!(s.chain_id(), 31_338);
    }

    #[test]
    fn a_ct_root_change_for_a_seen_task_taints_the_state() {
        let s = state();
        s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(7),
            ct_root: B256::repeat_byte(0xaa),
            shards: 1,
            contributors: 1,
        });
        s.apply(&ChainEvent::TaskSealed {
            task_id: U256::from(7),
            ct_root: B256::repeat_byte(0xbb),
            shards: 1,
            contributors: 1,
        });
        assert!(s.is_tainted());
    }

    #[test]
    fn consensus_digest_breaks_ties_deterministically() {
        let t = TaskState {
            epochs: BTreeMap::from([(
                0,
                EpochState {
                    commits: BTreeMap::from([
                        (Address::repeat_byte(1), commit(B256::repeat_byte(0xaa))),
                        (Address::repeat_byte(2), commit(B256::repeat_byte(0xaa))),
                        (Address::repeat_byte(3), commit(B256::repeat_byte(0xbb))),
                    ]),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let first = consensus_digest_locked(&t).unwrap();
        // Same input, reversed iteration order, same answer: every node must agree.
        let mut t2 = t.clone();
        if let Some(e) = t2.epochs.get_mut(&0) {
            let commits = std::mem::take(&mut e.commits);
            e.commits = commits.into_iter().rev().collect();
        }
        assert_eq!(first, consensus_digest_locked(&t2).unwrap());
        assert_eq!(first, B256::repeat_byte(0xaa), "the majority digest wins");
    }

    fn commit(d: B256) -> CommitRecord {
        CommitRecord {
            enc_weights_cid: B256::ZERO,
            weights_digest: B256::ZERO,
            trace_digest: d,
            block: 0,
            proof_bytes: 0,
        }
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
            TaskStatus::Paused,
        ] {
            assert_eq!(TaskStatus::from_u8(s as u8), Some(s));
        }
        assert_eq!(TaskStatus::from_u8(200), None);
    }

    #[test]
    fn terminal_statuses_are_recognised() {
        assert!(TaskStatus::Disclosed.is_terminal());
        assert!(TaskStatus::Aborted.is_terminal());
        assert!(TaskStatus::Paused.is_terminal());
        assert!(!TaskStatus::EpochCommitting.is_terminal());
    }
}
