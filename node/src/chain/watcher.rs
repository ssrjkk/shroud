//! Reorg-safe log watcher.
//!
//! The node's view of the chain is a fold over logs. Three properties make it correct rather
//! than merely working:
//!
//! 1. **Only finalised blocks are acted on.** An epoch commit costs a real STARK, so acting on
//!    a log that later disappears means doing the work twice. The watcher holds a cursor that
//!    trails the head by `finality.confirmations` blocks.
//!
//! 2. **A reorg invalidates the fold, so the fold restarts from the fork point.** The hash of
//!    the last block of every scanned window is kept as an anchor. When an anchor no longer
//!    matches the canonical chain the derived state is discarded and the fold replays from
//!    that block; when a recorded block is missing entirely the cursor rewinds to the
//!    cold-start block instead. There is no attempt to "undo" individual events: getting that
//!    wrong is how nodes end up accepting a proof for an epoch that no longer exists.
//!
//! 3. **Decoding and folding happen in one place.** Every log the watcher accepts is applied to
//!    [`NodeState`] before the cursor moves, so there is exactly one driver of the derived
//!    state and no second consumer that could fall behind and see a different chain.
//!
//! The decoders are tested against logs captured from a real chain rather than against
//! hand-written buffers; see `REAL_LOGS` below.

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use alloy::{
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider},
    rpc::types::Log,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use super::{bindings::events, read_provider};
use crate::{
    config::{Config, FinalityConfig},
    error::{Error, Result},
    state::NodeState,
};

/// Sentinel cursor: "no `chain.start_block` was given, derive the start from the head at
/// run-time using `chain.backfill_blocks`".
const DERIVE_START: u64 = u64::MAX;

/// A decoded Shroud event, as the rest of the node sees it.
///
/// The field split follows the contract's `indexed` markers exactly: identifiers are topics,
/// payloads are data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainEvent {
    ContributionSubmitted {
        task_id: U256,
        contributor: Address,
        leaf_index: u32,
        ciphertext_cid: B256,
        rows: u32,
    },
    DisputeReported {
        task_id: U256,
        epoch: u32,
        reporter: Address,
        digest: B256,
    },
    EpochCommitted {
        task_id: U256,
        epoch: u32,
        node: Address,
        trace_digest: B256,
    },
    EpochOpened {
        task_id: U256,
        epoch: u32,
        enc_weights_cid: B256,
        weights_digest: B256,
    },
    EpochRejected {
        task_id: U256,
        epoch: u32,
        reporters: u64,
    },
    EpochSettled {
        task_id: U256,
        epoch: u32,
        node: Address,
        amount: u128,
    },
    EpochVerified {
        task_id: U256,
        epoch: u32,
        node: Address,
        ok: bool,
    },
    NodeRewardChannelOpened {
        task_id: U256,
        epoch: u32,
        node: Address,
        channel_id: U256,
        max_cumulative: u128,
        unlock_at: u64,
        first_slice: u128,
    },
    TaskAborted {
        task_id: U256,
        reason: [u8; 4],
    },
    TaskSealed {
        task_id: U256,
        ct_root: B256,
        shards: u32,
        contributors: u32,
    },
    TaskSettled {
        task_id: U256,
        user_pool: u128,
        node_pool: u128,
        committee_pool: u128,
    },
    ChannelOpened {
        channel_id: U256,
        task_id: U256,
        node: Address,
        streamer: Address,
        max_cumulative: u128,
        unlock_at: u64,
    },
    SliceRedeemed {
        channel_id: U256,
        node: Address,
        cumulative: u128,
        amount: u128,
        slice_index: u64,
    },
    ChannelReclaimed {
        channel_id: U256,
        node: Address,
        amount: u128,
    },
}

impl ChainEvent {
    pub fn task_id(&self) -> Option<U256> {
        match self {
            ChainEvent::ContributionSubmitted { task_id, .. }
            | ChainEvent::DisputeReported { task_id, .. }
            | ChainEvent::EpochCommitted { task_id, .. }
            | ChainEvent::EpochOpened { task_id, .. }
            | ChainEvent::EpochRejected { task_id, .. }
            | ChainEvent::EpochSettled { task_id, .. }
            | ChainEvent::EpochVerified { task_id, .. }
            | ChainEvent::NodeRewardChannelOpened { task_id, .. }
            | ChainEvent::TaskAborted { task_id, .. }
            | ChainEvent::TaskSealed { task_id, .. }
            | ChainEvent::TaskSettled { task_id, .. }
            | ChainEvent::ChannelOpened { task_id, .. } => Some(*task_id),
            ChainEvent::SliceRedeemed { .. } | ChainEvent::ChannelReclaimed { .. } => None,
        }
    }

    /// Set only by the two vault events that identify a channel and nothing else.
    pub fn channel_id(&self) -> Option<U256> {
        match self {
            ChainEvent::SliceRedeemed { channel_id, .. }
            | ChainEvent::ChannelReclaimed { channel_id, .. }
            | ChainEvent::ChannelOpened { channel_id, .. } => Some(*channel_id),
            _ => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ChainEvent::ContributionSubmitted { .. } => "ContributionSubmitted",
            ChainEvent::DisputeReported { .. } => "DisputeReported",
            ChainEvent::EpochCommitted { .. } => "EpochCommitted",
            ChainEvent::EpochOpened { .. } => "EpochOpened",
            ChainEvent::EpochRejected { .. } => "EpochRejected",
            ChainEvent::EpochSettled { .. } => "EpochSettled",
            ChainEvent::EpochVerified { .. } => "EpochVerified",
            ChainEvent::NodeRewardChannelOpened { .. } => "NodeRewardChannelOpened",
            ChainEvent::TaskAborted { .. } => "TaskAborted",
            ChainEvent::TaskSealed { .. } => "TaskSealed",
            ChainEvent::TaskSettled { .. } => "TaskSettled",
            ChainEvent::ChannelOpened { .. } => "ChannelOpened",
            ChainEvent::SliceRedeemed { .. } => "SliceRedeemed",
            ChainEvent::ChannelReclaimed { .. } => "ChannelReclaimed",
        }
    }
}

/// Persisted cursor, so a restart does not replay the whole chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    pub last_scanned: u64,
    /// Highest finalised block at the time of the write. Used to detect a chain reset or a
    /// switch to a different L3, which is not a reorg but must still trigger a full replay.
    pub head_at_write: u64,
    pub chain_id: u64,
    /// Hash of `last_scanned`, so a checkpoint written against a block that is no longer
    /// canonical is detected rather than trusted.
    pub last_scanned_hash: Option<B256>,
}

/// Cursor + reorg policy.
#[derive(Debug)]
pub struct Watcher {
    provider: DynProvider,
    contract: Address,
    vault: Address,
    finality: FinalityConfig,
    poll_interval: Duration,
    get_logs_window: u64,
    get_logs_chunk: u64,
    backfill_blocks: u64,
    /// Where a cold start begins. Kept so a full replay rewinds to the same block this
    /// watcher would have started from, rather than to wherever the cursor happened to be.
    start_block: Option<u64>,
    task_filter: Option<U256>,
    state: Arc<NodeState>,
    cursor: AtomicU64,
    /// `(number, hash)` for the blocks we have folded past, oldest first. Sparse — one entry
    /// per scanned window — but every entry is a block whose logs are already folded, so a
    /// mismatch pins a fork point the replay can start from.
    anchors: tokio::sync::Mutex<VecDeque<(u64, B256)>>,
}

impl Watcher {
    /// Build the watcher and its own provider.
    ///
    /// The provider is deliberately not the client's: the watcher is a long-lived poller and the
    /// client issues bursty writes, so sharing one pool lets a slow `eth_getLogs` window starve a
    /// commit that is racing an epoch deadline.
    pub fn new(cfg: &Config, state: Arc<NodeState>) -> Result<Self> {
        Ok(Self {
            provider: read_provider(cfg)?,
            contract: cfg.contracts.cipher_task,
            vault: cfg.contracts.payment_vault,
            finality: cfg.finality.clone(),
            poll_interval: cfg.chain.poll_interval,
            get_logs_window: cfg.chain.get_logs_window,
            get_logs_chunk: cfg.chain.get_logs_chunk,
            backfill_blocks: cfg.chain.backfill_blocks,
            start_block: cfg.chain.start_block,
            task_filter: cfg.node.task_filter.map(|b| U256::from_be_bytes(b.0)),
            state,
            cursor: AtomicU64::new(cfg.chain.start_block.unwrap_or(DERIVE_START)),
            anchors: tokio::sync::Mutex::new(VecDeque::new()),
        })
    }

    /// Restore a checkpoint, validating it against the canonical chain first.
    ///
    /// A checkpoint is only trusted if it was written for the same `chain_id` **and** the
    /// block it names still has the recorded hash. Otherwise the cursor is left alone, which
    /// means the configured backfill depth applies.
    pub async fn restore(&self, cp: &Checkpoint, chain_id: u64) -> Result<()> {
        if cp.chain_id != chain_id {
            warn!(
                expected = chain_id,
                found = cp.chain_id,
                "checkpoint is for another chain; full replay"
            );
            return Ok(());
        }
        if let Some(h) = cp.last_scanned_hash {
            let Some(block) = self
                .provider
                .get_block_by_number(cp.last_scanned.into())
                .await?
            else {
                warn!(
                    block = cp.last_scanned,
                    "checkpoint block is not in the canonical chain; full replay"
                );
                return Ok(());
            };
            if block.header.hash != h {
                warn!(
                    block = cp.last_scanned,
                    "checkpoint block hash changed; full replay"
                );
                return Ok(());
            }
        }
        self.cursor.store(cp.last_scanned, Ordering::SeqCst);
        info!(block = cp.last_scanned, "resumed from checkpoint");
        Ok(())
    }

    /// Run until `shutdown` resolves. Reorg-safe, idempotent, and safe to restart.
    pub async fn run(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        info!(
            contract = %self.contract,
            confirmations = self.finality.confirmations,
            task_filter = ?self.task_filter.map(|t| format!("{t:#x}")),
            "watcher started"
        );

        loop {
            if *shutdown.borrow() {
                info!("watcher: shutdown requested");
                return Ok(());
            }

            let head = match self.provider.get_block_number().await {
                Ok(h) => h,
                Err(e) => {
                    error!(error = %e, "watcher: head unavailable; retrying");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        _ = shutdown.changed() => return Ok(()),
                    }
                    continue;
                }
            };

            // First run with no checkpoint and no explicit start block: look back a bounded
            // number of blocks rather than from genesis or from the head, which would miss
            // the task that is already mid-epoch.
            if self.cursor.load(Ordering::SeqCst) == DERIVE_START {
                let start = head.saturating_sub(self.backfill_blocks);
                info!(
                    start,
                    backfill = self.backfill_blocks,
                    "no checkpoint; backfilling"
                );
                self.cursor.store(start, Ordering::SeqCst);
            }

            // --- reorg detection -------------------------------------------------------
            if let Err(e) = self.check_reorg().await {
                error!(error = %e, "watcher: reorg handling failed");
            }

            let safe = head.saturating_sub(self.finality.confirmations);
            let from = self.cursor.load(Ordering::SeqCst) + 1;
            if from > safe {
                tokio::select! {
                    _ = tokio::time::sleep(self.poll_interval) => {}
                    _ = shutdown.changed() => return Ok(()),
                }
                continue;
            }

            let to = safe.min(from + self.get_logs_window - 1);
            // Pin the window's end hash *before* folding it. Fetching it afterwards would let a
            // reorg that lands between `get_logs` and the anchor write stamp the post-reorg
            // hash onto pre-reorg logs, and the mismatch would only surface once that block is
            // itself reorged — one detection cycle too late. With the hash captured first, that
            // race produces a spurious mismatch and a replay, which is the safe direction.
            let anchor_hash = self
                .provider
                .get_block_by_number(to.into())
                .await
                .ok()
                .flatten()
                .map(|b| b.header.hash);
            if let Err(e) = self.scan(from, to).await {
                error!(from, to, error = %e, "watcher: scan failed; will retry the same window");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = shutdown.changed() => return Ok(()),
                }
                continue;
            }

            self.cursor.store(to, Ordering::SeqCst);
            if let Some(hash) = anchor_hash {
                self.record_anchor_hash(to, hash).await;
            }
            self.maybe_checkpoint(to, head).await;

            if to >= safe {
                tokio::select! {
                    _ = tokio::time::sleep(self.poll_interval) => {}
                    _ = shutdown.changed() => return Ok(()),
                }
            }
        }
    }

    /// Detect a reorg that invalidates the cursor.
    ///
    /// The watcher records `(number, hash)` for the last block of every scanned window. On each
    /// poll it re-reads those blocks: the first one whose hash is no longer canonical is the
    /// fork point, and the fold restarts from there. If a recorded block is missing entirely
    /// the chain was reset or swapped, which is handled identically — a full replay.
    ///
    /// This is deliberately not a "did the head move backwards" test. On a chain where blocks
    /// arrive out of order or where the provider re-syncs, the head can jump forward and back
    /// without a reorg, and the only sound signal is the hash of a block we already consumed.
    async fn check_reorg(&self) -> Result<()> {
        let anchors = self.anchors.lock().await.clone();
        for (number, expected) in anchors {
            match self.provider.get_block_by_number(number.into()).await {
                Ok(Some(block)) if block.header.hash == expected => {}
                Ok(Some(_)) => {
                    warn!(
                        fork_point = number,
                        "reorg: block hash changed; replaying from the fork point"
                    );
                    return self.replay_from(number).await;
                }
                Ok(None) => {
                    warn!(
                        block = number,
                        "reorg: recorded block is not in the canonical chain; full replay"
                    );
                    self.anchors.lock().await.clear();
                    // `reset()` only clears the derived maps. Without rewinding the cursor as
                    // well, the next poll would scan forward from where this one stopped, the
                    // fold would stay empty forever, and `maybe_checkpoint` would keep writing
                    // that same cursor forward. Rewinding is what makes this a *full* replay.
                    let restart = self.start_block.unwrap_or(DERIVE_START);
                    self.cursor.store(restart, Ordering::SeqCst);
                    self.state.reset();
                    info!(restart, "reorg: rebuild the fold from the cold-start block");
                    return Ok(());
                }
                Err(e) => {
                    // RPC hiccup, not a reorg. Do not throw away a valid fold over a
                    // transport error; the next poll will retry the verification.
                    debug!(block = number, error = %e, "reorg: could not verify anchor; will retry");
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Record the hash of the last block folded, trimming anchors we can no longer need.
    async fn record_anchor_hash(&self, number: u64, hash: B256) {
        // The hash is captured before the window is folded (see `run`), so a `None` here means
        // the block was already gone when the window was pinned: losing an anchor is not fatal,
        // it only means this block will not be used as a fork point.
        let keep = (self.finality.reorg_threshold + self.finality.confirmations + 1) as usize;
        let mut anchors = self.anchors.lock().await;
        anchors.push_back((number, hash));
        while anchors.len() > keep {
            anchors.pop_front();
        }
    }

    async fn replay_from(&self, block: u64) -> Result<()> {
        warn!(
            block,
            depth = self.cursor.load(Ordering::SeqCst).saturating_sub(block),
            "reorg: discarding derived state"
        );
        self.state.reset();
        self.anchors.lock().await.retain(|(n, _)| *n < block);
        self.cursor.store(block, Ordering::SeqCst);
        Ok(())
    }

    /// Fetch, decode and fold one block window.
    async fn scan(&self, from: u64, to: u64) -> Result<()> {
        let mut cursor = from;
        let chunk = self.get_logs_chunk;
        while cursor <= to {
            let end = to.min(cursor + chunk - 1);
            let filter = self.filter().from_block(cursor).to_block(end);

            let logs = self
                .provider
                .get_logs(&filter)
                .await
                .map_err(|e| Error::Chain(format!("eth_getLogs {cursor}..={end}: {e}")))?;

            // Sort by (block, log_index): the fold must be deterministic regardless of the
            // order the RPC returns. A commit and its settlement in the same block applied in
            // the wrong order would re-open an epoch that is already paid.
            let mut ordered: Vec<Log> = logs.into_iter().collect();
            ordered.sort_by_key(|l| {
                (
                    l.block_number.unwrap_or_default(),
                    l.log_index.unwrap_or_default(),
                )
            });

            for log in ordered {
                match self.decode(&log) {
                    Ok(Some(ev)) => {
                        let work = self.state.apply(&ev);
                        debug!(
                            kind = ev.kind(),
                            task = ?ev.task_id(),
                            work = work.len(),
                            "folded event"
                        );
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!(error = %e, tx = %log.address(), "watcher: undecodable log; skipping")
                    }
                }
            }

            cursor = end + 1;
        }
        Ok(())
    }

    fn filter(&self) -> alloy::rpc::types::Filter {
        // Pre-computed topic hashes from `bindings::events::WATCH`, not signature strings: the
        // topics are derived from the signature strings in one place, so asking the provider
        // to hash them again would be redundant and could silently mean something else if the
        // two lists ever drifted.
        //
        // Both addresses go into one `Vec` because `Filter::address` *replaces* the value on
        // each call; calling it twice leaves only the vault, and the node would silently stop
        // seeing task events.
        let addresses = vec![self.contract, self.vault];
        alloy::rpc::types::Filter::new()
            .address(addresses)
            .event_signature(events::WATCH.clone())
    }

    /// Decode a log and apply `node.task_filter`. `Ok(None)` means "not ours".
    ///
    /// Both the indexed arguments (from `log.topics()`) and the data words are needed, and
    /// getting that split wrong is the classic way a log decoder silently reads zeros, so
    /// the two are kept as separate parameters all the way down.
    fn decode(&self, log: &Log) -> Result<Option<ChainEvent>> {
        let ev = decode_any(
            self.contract,
            self.vault,
            log.address(),
            &log.topics(),
            &log.data().data[..],
        );
        Ok(ev.filter(|e| self.passes_filter(e)))
    }

    /// `node.task_filter` narrows the fold to one task.
    ///
    /// `SliceRedeemed` and `ChannelReclaimed` name a channel, not a task, so they are attributed
    /// through the channel the fold already knows about. A channel event for a channel we have
    /// never seen is dropped when filtering: without an owning task there is nothing to say
    /// whether it belongs to the watched one, and guessing would fold another task's payments
    /// into our state.
    fn passes_filter(&self, ev: &ChainEvent) -> bool {
        let Some(watched) = self.task_filter else {
            return true;
        };
        match ev.task_id() {
            Some(task_id) => task_id == watched,
            None => ev
                .channel_id()
                .and_then(|c| self.state.channel(c))
                .is_some_and(|c| c.task_id == watched),
        }
    }

    async fn maybe_checkpoint(&self, scanned: u64, head: u64) {
        if !scanned.is_multiple_of(self.finality.checkpoint_interval) {
            return;
        }
        let cp = match self.build_checkpoint(scanned, head).await {
            Ok(cp) => cp,
            Err(e) => {
                error!(error = %e, "watcher: could not build a checkpoint");
                return;
            }
        };
        if let Err(e) = self.state.write_checkpoint(&cp).await {
            error!(error = %e, "watcher: could not persist a checkpoint");
        }
    }

    async fn build_checkpoint(&self, scanned: u64, head: u64) -> Result<Checkpoint> {
        let hash = self
            .provider
            .get_block_by_number(scanned.into())
            .await?
            .map(|b| b.header.hash);
        Ok(Checkpoint {
            last_scanned: scanned,
            head_at_write: head,
            chain_id: self.state.chain_id(),
            last_scanned_hash: hash,
        })
    }

    /// The current cursor. `0` until the first poll resolves a backfill start.
    pub fn checkpoint(&self) -> Checkpoint {
        let last = self.cursor.load(Ordering::SeqCst);
        Checkpoint {
            last_scanned: if last == DERIVE_START { 0 } else { last },
            head_at_write: 0,
            chain_id: self.state.chain_id(),
            last_scanned_hash: None,
        }
    }
}

// --- decoders ---------------------------------------------------------------------------
//
// Hand-written rather than `alloy::sol!`-generated so the layout is explicit and auditable
// against the Solidity `emit` sites. Every decoder takes *both* `topics` and `data` because
// Shroud marks the entity identifiers `indexed` (they are filters) and the payloads
// non-indexed (they are not). Reading the wrong one yields zeros, so the split is a parameter
// rather than a convention. Each decoder is total: it checks the word count and returns
// `None` on a short buffer instead of reading past the end.
//
// The indexed/data split below is the one the compiler emitted and the chain actually logged,
// pinned by `REAL_LOGS`.

/// Route a log to the decoder for its emitter.
///
/// Routing by address, not by "the first topic that matches", matters: a topic the node
/// subscribes to can only be emitted by the contract that declares it, and feeding vault data
/// words to the task decoder would read an `address` slot as a `uint128` and produce a
/// plausible-looking wrong amount.
pub fn decode_any(
    task: Address,
    vault: Address,
    emitter: Address,
    topics: &[B256],
    data: &[u8],
) -> Option<ChainEvent> {
    let sig = topics.first()?;
    if emitter == task {
        return decode_task_event(sig, topics, data);
    }
    if emitter == vault {
        return decode_vault_event(sig, topics, data);
    }
    None
}

/// Read the `i`-th word of the non-indexed data section.
fn data_word(data: &[u8], i: usize) -> Option<B256> {
    let s = data.get(i * 32..(i + 1) * 32)?;
    (s.len() == 32).then(|| B256::from_slice(s))
}

/// Read indexed argument `i` (index 0 is the event signature).
fn indexed(topics: &[B256], i: usize) -> Option<U256> {
    topics.get(i + 1).map(|b| U256::from_be_bytes(b.0))
}

fn indexed_b256(topics: &[B256], i: usize) -> Option<B256> {
    topics.get(i + 1).copied()
}

fn indexed_address(topics: &[B256], i: usize) -> Option<Address> {
    indexed_b256(topics, i).map(address_of)
}

fn indexed_u32(topics: &[B256], i: usize) -> Option<u32> {
    indexed_b256(topics, i).map(u32_of)
}

fn u128_of(b: B256) -> u128 {
    u128::from_be_bytes(b.0[16..32].try_into().expect("16 bytes"))
}

fn u32_of(b: B256) -> u32 {
    u32::from_be_bytes(b.0[28..32].try_into().expect("4 bytes"))
}

fn u64_of(b: B256) -> u64 {
    u64::from_be_bytes(b.0[24..32].try_into().expect("8 bytes"))
}

fn address_of(b: B256) -> Address {
    Address::from_slice(&b.0[12..32])
}

/// A `bool` is a word that is exactly `0` or `1`. Anything else is a decoding error, not a
/// truthy value.
fn bool_of(b: B256) -> Option<bool> {
    match b {
        B256::ZERO => Some(false),
        b if b.0[..31].iter().all(|x| *x == 0) && b.0[31] == 1 => Some(true),
        _ => None,
    }
}

/// `CipherTask` events.
///
/// | event                     | indexed                        | data                                        |
/// |---------------------------|--------------------------------|---------------------------------------------|
/// | `ContributionSubmitted`   | taskId, contributor, leafIndex | ciphertextCid, rows                         |
/// | `DisputeReported`         | taskId, epoch, reporter        | digest                                      |
/// | `EpochCommitted`          | taskId, epoch, node            | traceDigest                                 |
/// | `EpochOpened`             | taskId, epoch                  | encWeightsCid, weightsDigest                |
/// | `EpochRejected`           | taskId, epoch                  | reporters                                   |
/// | `EpochSettled`            | taskId, epoch, node            | amount                                      |
/// | `EpochVerified`           | taskId, epoch, node            | ok                                          |
/// | `NodeRewardChannelOpened` | taskId, epoch, node            | channelId, maxCumulative, unlockAt, firstSlice |
/// | `TaskAborted`             | taskId                         | reason (bytes4, left-aligned)               |
/// | `TaskSealed`              | taskId                         | ctRoot, shards, contributors                |
/// | `TaskSettled`             | taskId                         | userPool, nodePool, committeePool           |
pub fn decode_task_event(sig: &B256, topics: &[B256], data: &[u8]) -> Option<ChainEvent> {
    if *sig == *events::CONTRIBUTION_SUBMITTED_TOPIC {
        return Some(ChainEvent::ContributionSubmitted {
            task_id: indexed(topics, 0)?,
            contributor: indexed_address(topics, 1)?,
            leaf_index: indexed_u32(topics, 2)?,
            ciphertext_cid: data_word(data, 0)?,
            rows: u32_of(data_word(data, 1)?),
        });
    }
    if *sig == *events::DISPUTE_REPORTED_TOPIC {
        return Some(ChainEvent::DisputeReported {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            reporter: indexed_address(topics, 2)?,
            digest: data_word(data, 0)?,
        });
    }
    if *sig == *events::EPOCH_COMMITTED_TOPIC {
        return Some(ChainEvent::EpochCommitted {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            node: indexed_address(topics, 2)?,
            trace_digest: data_word(data, 0)?,
        });
    }
    if *sig == *events::EPOCH_OPENED_TOPIC {
        return Some(ChainEvent::EpochOpened {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            enc_weights_cid: data_word(data, 0)?,
            weights_digest: data_word(data, 1)?,
        });
    }
    if *sig == *events::EPOCH_REJECTED_TOPIC {
        return Some(ChainEvent::EpochRejected {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            reporters: u64_of(data_word(data, 0)?),
        });
    }
    if *sig == *events::EPOCH_SETTLED_TOPIC {
        return Some(ChainEvent::EpochSettled {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            node: indexed_address(topics, 2)?,
            amount: u128_of(data_word(data, 0)?),
        });
    }
    if *sig == *events::EPOCH_VERIFIED_TOPIC {
        return Some(ChainEvent::EpochVerified {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            node: indexed_address(topics, 2)?,
            ok: bool_of(data_word(data, 0)?)?,
        });
    }
    if *sig == *events::NODE_REWARD_CHANNEL_OPENED_TOPIC {
        return Some(ChainEvent::NodeRewardChannelOpened {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            node: indexed_address(topics, 2)?,
            channel_id: U256::from_be_slice(data_word(data, 0)?.as_slice()),
            max_cumulative: u128_of(data_word(data, 1)?),
            unlock_at: u64_of(data_word(data, 2)?),
            first_slice: u128_of(data_word(data, 3)?),
        });
    }
    if *sig == *events::TASK_ABORTED_TOPIC {
        // `bytes4` is a static value type: it occupies a whole data word and is
        // *left*-aligned in it. The captured `TaskAborted` log is
        // `0xb551a22b0000…0000`, so reading the last four bytes yields `00000000` and every
        // abort reason in the node would decode to zero.
        return Some(ChainEvent::TaskAborted {
            task_id: indexed(topics, 0)?,
            reason: data_word(data, 0)?.0[0..4].try_into().expect("4 bytes"),
        });
    }
    if *sig == *events::TASK_SEALED_TOPIC {
        return Some(ChainEvent::TaskSealed {
            task_id: indexed(topics, 0)?,
            ct_root: data_word(data, 0)?,
            shards: u32_of(data_word(data, 1)?),
            contributors: u32_of(data_word(data, 2)?),
        });
    }
    if *sig == *events::TASK_SETTLED_TOPIC {
        return Some(ChainEvent::TaskSettled {
            task_id: indexed(topics, 0)?,
            user_pool: u128_of(data_word(data, 0)?),
            node_pool: u128_of(data_word(data, 1)?),
            committee_pool: u128_of(data_word(data, 2)?),
        });
    }
    None
}

/// `PaymentVault` events.
///
/// | event             | indexed                        | data                              |
/// |-------------------|--------------------------------|-----------------------------------|
/// | `ChannelOpened`   | channelId, taskId, node        | streamer, maxCumulative, unlockAt |
/// | `SliceRedeemed`   | channelId, node                | cumulative, amount, sliceIndex    |
/// | `ChannelReclaimed`| channelId, node                | amount                            |
pub fn decode_vault_event(sig: &B256, topics: &[B256], data: &[u8]) -> Option<ChainEvent> {
    if *sig == *events::CHANNEL_OPENED_TOPIC {
        return Some(ChainEvent::ChannelOpened {
            channel_id: indexed(topics, 0)?,
            task_id: indexed(topics, 1)?,
            node: indexed_address(topics, 2)?,
            streamer: address_of(data_word(data, 0)?),
            max_cumulative: u128_of(data_word(data, 1)?),
            unlock_at: u64_of(data_word(data, 2)?),
        });
    }
    if *sig == *events::SLICE_REDEEMED_TOPIC {
        return Some(ChainEvent::SliceRedeemed {
            channel_id: indexed(topics, 0)?,
            node: indexed_address(topics, 1)?,
            cumulative: u128_of(data_word(data, 0)?),
            amount: u128_of(data_word(data, 1)?),
            slice_index: u64_of(data_word(data, 2)?),
        });
    }
    if *sig == *events::CHANNEL_RECLAIMED_TOPIC {
        return Some(ChainEvent::ChannelReclaimed {
            channel_id: indexed(topics, 0)?,
            node: indexed_address(topics, 1)?,
            amount: u128_of(data_word(data, 0)?),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The addresses of the deployment the logs below were captured from.
    const TASK_ADDR: &str = "0x8a791620dd6260079bf849dc5567adc3f2fdc318";
    const VAULT_ADDR: &str = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512";
    const NODE: &str = "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc";
    const ALICE: &str = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";
    const REPORTER: &str = "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f";

    fn addr(s: &str) -> Address {
        s.parse::<Address>().expect("fixture address")
    }

    fn word(s: &str) -> B256 {
        s.parse::<B256>().expect("fixture word")
    }

    #[test]
    fn epoch_opened_reads_indexed_and_data_from_the_right_places() {
        let t = vec![
            *events::EPOCH_OPENED_TOPIC,
            word("0x0000000000000000000000000000000000000000000000000000000000000007"),
            word("0x0000000000000000000000000000000000000000000000000000000000000002"),
        ];
        let mut data = [0u8; 64];
        data[0..32].fill(0xAA);
        data[32..64].fill(0xBB);

        assert_eq!(
            decode_task_event(&events::EPOCH_OPENED_TOPIC, &t, &data),
            Some(ChainEvent::EpochOpened {
                task_id: U256::from(7),
                epoch: 2,
                enc_weights_cid: B256::repeat_byte(0xAA),
                weights_digest: B256::repeat_byte(0xBB),
            })
        );
    }

    #[test]
    fn a_short_data_buffer_decodes_to_none_rather_than_reading_past_the_end() {
        let t = vec![*events::EPOCH_OPENED_TOPIC, B256::ZERO, B256::ZERO];
        assert!(decode_task_event(&events::EPOCH_OPENED_TOPIC, &t, &[0u8; 32]).is_none());
        assert!(decode_task_event(&events::EPOCH_OPENED_TOPIC, &t, &[0u8; 64]).is_some());
    }

    #[test]
    fn a_missing_topic_decodes_to_none() {
        let t = vec![*events::EPOCH_COMMITTED_TOPIC];
        assert!(decode_task_event(&events::EPOCH_COMMITTED_TOPIC, &t, &[0u8; 32]).is_none());
    }

    #[test]
    fn a_non_boolean_word_is_not_silently_accepted_as_true() {
        let t = vec![
            *events::EPOCH_VERIFIED_TOPIC,
            B256::ZERO,
            B256::ZERO,
            B256::ZERO,
        ];
        let mut odd = [0u8; 32];
        odd[31] = 2;
        assert!(decode_task_event(&events::EPOCH_VERIFIED_TOPIC, &t, &odd).is_none());
    }

    #[test]
    fn unknown_topic_decodes_to_none() {
        let odd = B256::repeat_byte(9);
        assert!(decode_task_event(&odd, &[odd], &[0u8; 128]).is_none());
        assert!(decode_vault_event(&odd, &[odd], &[0u8; 128]).is_none());
    }

    #[test]
    fn a_vault_topic_emitted_by_the_task_address_is_not_decoded() {
        // Same topic, wrong emitter: the task decoder would read the vault's data words as
        // task fields and produce a plausible amount.
        let vault_topics = vec![
            *events::CHANNEL_OPENED_TOPIC,
            B256::ZERO,
            B256::ZERO,
            B256::ZERO,
        ];
        assert!(decode_any(
            addr(TASK_ADDR),
            addr(VAULT_ADDR),
            addr(TASK_ADDR),
            &vault_topics,
            &[0u8; 96]
        )
        .is_none());
    }

    // --- real chain logs ----------------------------------------------------------------
    //
    // Captured with `eth_getLogs` from a Hardhat run that drove the full money path: two
    // epochs, a redeem, a reclaim after the unlock window, settlement, a dispute quorum, and
    // an abort. They are the only trustworthy statement of which arguments are `indexed` and
    // which are data, so each watched event is decoded from its real log here.
    struct RealLog {
        name: &'static str,
        address: &'static str,
        topics: &'static [&'static str],
        data: &'static str,
    }

    // One captured log per line, exactly as `eth_getLogs` returned it: a re-capture then shows up as
    // a one-line diff per event. `rustfmt::skip` is not decoration — the hex words are longer than
    // anything it can wrap, so its only alternative is to shred each log across a dozen lines.
    #[rustfmt::skip]
    const REAL_LOGS: &[RealLog] = &[
        RealLog { name: "ContributionSubmitted", address: TASK_ADDR, topics: &["0xc37fa11865d20db8c2f9f36ef55d1f99c41a0ee1f98fd66fcad5c3e82cae8ef3", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x0000000000000000000000000000000000000000000000000000000000000000"], data: "0x7cb28e2fbd63cc4d4a519f09950cf70541ff7d13878e887d59fb1341ac17890c00000000000000000000000000000000000000000000000000000000000003e8" },
        RealLog { name: "DisputeReported", address: TASK_ADDR, topics: &["0x56c6da7aeff81fba1958ad3eddabcec10d01fa5edbe133afd962121e89b9acf9", "0x0000000000000000000000000000000000000000000000000000000000000002", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x00000000000000000000000023618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f"], data: "0x9e8b8a6f48ae2afb4feccb8a3d14ad5fc0a2279f3cb83cc5c6f549468b6aaaff" },
        RealLog { name: "EpochCommitted", address: TASK_ADDR, topics: &["0xbe1c0401080fba30020b1609c22d6c3de654f750279eb2c12daac731b9c5f668", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000009965507d1a55bcc2695c58ba16fb37d819b0a4dc"], data: "0x01c8a3e3937be1c605ffbdfd93fa4c7b1a68ef7dd87913adf52d6c0739ee7f62" },
        RealLog { name: "EpochOpened", address: TASK_ADDR, topics: &["0x7e3cb4c8395e586b6b675ae99ac10bb09551b19d95aeae90a896aead64caab2b", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000000000000000000000000000000"], data: "0x7058f9c48824b4113784aea72c20faae780d67e13596f1adfa8d87ac2f68d021f4559db0122e9706e35b50592c904d11d671491d7d9443d1d19abc75b5f62225" },
        RealLog { name: "EpochRejected", address: TASK_ADDR, topics: &["0x8ef810f8e72a2aced85333b1f2a81efc7ee1e964b7b6e12eac2e49eb288900cc", "0x0000000000000000000000000000000000000000000000000000000000000002", "0x0000000000000000000000000000000000000000000000000000000000000000"], data: "0x0000000000000000000000000000000000000000000000000000000000000003" },
        RealLog { name: "EpochSettled", address: TASK_ADDR, topics: &["0x9c7e9f71dff59cfde2bb5e38de2a9baecc65bbaaa779209751a12c1c28355610", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000009965507d1a55bcc2695c58ba16fb37d819b0a4dc"], data: "0x00000000000000000000000000000000000000000000000000000000047868c0" },
        RealLog { name: "EpochVerified", address: TASK_ADDR, topics: &["0xde1a096b42a741da9abd8e171b97e821d67b222feddb8d4e6efdfd642df44091", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000009965507d1a55bcc2695c58ba16fb37d819b0a4dc"], data: "0x0000000000000000000000000000000000000000000000000000000000000001" },
        RealLog { name: "NodeRewardChannelOpened", address: TASK_ADDR, topics: &["0x2226c20f431901d82fc48febfeab68c3b8b46423aae620f73d8b0b3c2b407053", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000009965507d1a55bcc2695c58ba16fb37d819b0a4dc"], data: "0x000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000047868c0000000000000000000000000000000000000000000000000000000006ad641fd00000000000000000000000000000000000000000000000000000000047868c0" },
        RealLog { name: "TaskAborted", address: TASK_ADDR, topics: &["0xe445d9d031ef936fdcc51bb3f78ad934dc35d6a085ab35864de6329a6e9f65c8", "0x0000000000000000000000000000000000000000000000000000000000000003"], data: "0xb551a22b00000000000000000000000000000000000000000000000000000000" },
        RealLog { name: "TaskSealed", address: TASK_ADDR, topics: &["0x99bf7cc8880bbbcd95ba1c122c314cb230e1607837b7aed2ea1957185b28c41b", "0x0000000000000000000000000000000000000000000000000000000000000001"], data: "0xb719daf526966b94fd548fd4de7c9659c119d4b006beaf12759e5c94da10dd1400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002" },
        RealLog { name: "TaskSettled", address: TASK_ADDR, topics: &["0x64b9379e52477e67cef49489615cca11e9f6343f94879ddc0c0f50ba19a4be65", "0x0000000000000000000000000000000000000000000000000000000000000001"], data: "0x000000000000000000000000000000000000000000000000000000002faf08000000000000000000000000000000000000000000000000000000000008f0d1800000000000000000000000000000000000000000000000000000000002faf080" },
        RealLog { name: "ChannelOpened", address: VAULT_ADDR, topics: &["0x70d39e0205cc39a51528f1c53832da8ccc0820ec76bec1d321bfa6c864c829cf", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000009965507d1a55bcc2695c58ba16fb37d819b0a4dc"], data: "0x0000000000000000000000008a791620dd6260079bf849dc5567adc3f2fdc31800000000000000000000000000000000000000000000000000000000047868c0000000000000000000000000000000000000000000000000000000006ad641fd" },
        RealLog { name: "SliceRedeemed", address: VAULT_ADDR, topics: &["0x107845e530b551b1ff303785868633c9e6e01096d45d483f669269e4b5995a69", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000009965507d1a55bcc2695c58ba16fb37d819b0a4dc"], data: "0x00000000000000000000000000000000000000000000000000000000047868c000000000000000000000000000000000000000000000000000000000047868c00000000000000000000000000000000000000000000000000000000000000000" },
        RealLog { name: "ChannelReclaimed", address: VAULT_ADDR, topics: &["0x97c9fd82973dc049001bdce58b00498bb0ed44ee59212ca45dbe5f1e8201ba84", "0x0000000000000000000000000000000000000000000000000000000000000001", "0x0000000000000000000000009965507d1a55bcc2695c58ba16fb37d819b0a4dc"], data: "0x0000000000000000000000000000000000000000000000000000000000000000" },
    ];

    /// Decode a captured log through the same routing the watcher uses.
    fn real(name: &str) -> ChainEvent {
        let row = REAL_LOGS
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("no captured log for {name}"));
        let topics: Vec<B256> = row.topics.iter().map(|t| word(t)).collect();
        let data = hex::decode(row.data.strip_prefix("0x").unwrap_or(row.data))
            .expect("captured data is hex");
        decode_any(
            addr(TASK_ADDR),
            addr(VAULT_ADDR),
            addr(row.address),
            &topics,
            &data,
        )
        .unwrap_or_else(|| panic!("{name} did not decode from its real log"))
    }

    #[test]
    fn every_watched_event_decodes_from_its_real_log() {
        // The subscription list and the captured table must cover exactly the same events,
        // or a future event would enter the fold with no decoder at all.
        assert_eq!(
            REAL_LOGS.len(),
            events::TASK_EVENTS.len() + events::VAULT_EVENTS.len()
        );
        for row in REAL_LOGS {
            assert_eq!(real(row.name).kind(), row.name);
        }
    }

    #[test]
    fn real_contribution_submitted_splits_three_indexed_and_two_data_words() {
        assert_eq!(
            real("ContributionSubmitted"),
            ChainEvent::ContributionSubmitted {
                task_id: U256::from(1),
                contributor: addr(ALICE),
                leaf_index: 0,
                ciphertext_cid: word(
                    "0x7cb28e2fbd63cc4d4a519f09950cf70541ff7d13878e887d59fb1341ac17890c"
                ),
                rows: 1_000,
            }
        );
    }

    #[test]
    fn real_task_sealed_reports_shards_and_contributors_separately() {
        assert_eq!(
            real("TaskSealed"),
            ChainEvent::TaskSealed {
                task_id: U256::from(1),
                // Two leaves, so this is the second step of the chain
                // `transcript::ct_root_steps_match_the_chain` walks.
                ct_root: word("0xb719daf526966b94fd548fd4de7c9659c119d4b006beaf12759e5c94da10dd14"),
                shards: 2,
                contributors: 2,
            }
        );
    }

    #[test]
    fn real_epoch_committed_takes_the_node_from_the_topics() {
        let committed = "0x01c8a3e3937be1c605ffbdfd93fa4c7b1a68ef7dd87913adf52d6c0739ee7f62";
        assert_eq!(
            real("EpochCommitted"),
            ChainEvent::EpochCommitted {
                task_id: U256::from(1),
                epoch: 0,
                node: addr(NODE),
                trace_digest: word(committed),
            }
        );
    }

    #[test]
    fn real_epoch_verified_and_rejected_carry_their_own_payloads() {
        assert_eq!(
            real("EpochVerified"),
            ChainEvent::EpochVerified {
                task_id: U256::from(1),
                epoch: 0,
                node: addr(NODE),
                ok: true,
            }
        );
        assert_eq!(
            real("EpochRejected"),
            ChainEvent::EpochRejected {
                task_id: U256::from(2),
                epoch: 0,
                reporters: 3,
            }
        );
    }

    #[test]
    fn real_epoch_settled_amount_is_the_right_aligned_uint128() {
        assert_eq!(
            real("EpochSettled"),
            ChainEvent::EpochSettled {
                task_id: U256::from(1),
                epoch: 0,
                node: addr(NODE),
                amount: 75_000_000,
            }
        );
    }

    #[test]
    fn real_task_aborted_reads_the_left_aligned_bytes4() {
        // `bytes4` pads to the *right*: the captured word is `b551a22b` followed by 28 zero
        // bytes. Reading the tail would make every abort reason decode to `00000000`.
        assert_eq!(
            real("TaskAborted"),
            ChainEvent::TaskAborted {
                task_id: U256::from(3),
                reason: [0xb5, 0x51, 0xa2, 0x2b],
            }
        );
    }

    #[test]
    fn real_node_reward_channel_opened_carries_the_channel_id_the_node_must_redeem() {
        assert_eq!(
            real("NodeRewardChannelOpened"),
            ChainEvent::NodeRewardChannelOpened {
                task_id: U256::from(1),
                epoch: 0,
                node: addr(NODE),
                channel_id: U256::from(1),
                max_cumulative: 75_000_000,
                unlock_at: 0x6ad6_41fd,
                first_slice: 75_000_000,
            }
        );
    }

    #[test]
    fn real_task_settled_splits_the_three_pools() {
        assert_eq!(
            real("TaskSettled"),
            ChainEvent::TaskSettled {
                task_id: U256::from(1),
                user_pool: 800_000_000,
                node_pool: 150_000_000,
                committee_pool: 50_000_000,
            }
        );
    }

    #[test]
    fn real_channel_opened_takes_the_node_from_the_topics_not_the_data() {
        // The pre-existing decoder read `node` from data word 0 and required a fourth data
        // word; the real log has three indexed topics and three data words, so every channel
        // the node was owed decoded to `None`.
        assert_eq!(
            real("ChannelOpened"),
            ChainEvent::ChannelOpened {
                channel_id: U256::from(1),
                task_id: U256::from(1),
                node: addr(NODE),
                streamer: addr(TASK_ADDR),
                max_cumulative: 75_000_000,
                unlock_at: 0x6ad6_41fd,
            }
        );
    }

    #[test]
    fn real_slice_redeemed_reads_the_slice_index_from_the_third_data_word() {
        assert_eq!(
            real("SliceRedeemed"),
            ChainEvent::SliceRedeemed {
                channel_id: U256::from(1),
                node: addr(NODE),
                cumulative: 75_000_000,
                amount: 75_000_000,
                slice_index: 0,
            }
        );
    }

    #[test]
    fn real_channel_reclaimed_reports_the_refund_and_the_owner() {
        // The reclaim in the capture refunded nothing: the whole channel had been redeemed.
        assert_eq!(
            real("ChannelReclaimed"),
            ChainEvent::ChannelReclaimed {
                channel_id: U256::from(1),
                node: addr(NODE),
                amount: 0,
            }
        );
    }

    #[test]
    fn dispute_reported_digest_and_reporter_come_from_the_real_log() {
        assert_eq!(
            real("DisputeReported"),
            ChainEvent::DisputeReported {
                task_id: U256::from(2),
                epoch: 0,
                reporter: addr(REPORTER),
                digest: word("0x9e8b8a6f48ae2afb4feccb8a3d14ad5fc0a2279f3cb83cc5c6f549468b6aaaff"),
            }
        );
    }

    #[test]
    fn epoch_opened_weights_are_two_independent_words() {
        let enc_cid = "0x7058f9c48824b4113784aea72c20faae780d67e13596f1adfa8d87ac2f68d021";
        let digest = "0xf4559db0122e9706e35b50592c904d11d671491d7d9443d1d19abc75b5f62225";
        assert_eq!(
            real("EpochOpened"),
            ChainEvent::EpochOpened {
                task_id: U256::from(1),
                epoch: 0,
                enc_weights_cid: word(enc_cid),
                weights_digest: word(digest),
            }
        );
    }

    #[test]
    fn checkpoint_reports_zero_before_the_first_poll_resolves_a_backfill_start() {
        let cfg = Config::default();
        let state = Arc::new(NodeState::new());
        // No `chain.start_block`: the cursor is unresolved until `run()` sees a head.
        let w = Watcher::new(&cfg, state).expect("a default config builds a watcher");
        assert_eq!(w.cursor.load(Ordering::SeqCst), DERIVE_START);
        assert_eq!(w.checkpoint().last_scanned, 0);
    }

    #[test]
    fn an_explicit_start_block_is_used_verbatim() {
        let mut cfg = Config::default();
        cfg.chain.start_block = Some(4_242_424);
        let w = Watcher::new(&cfg, Arc::new(NodeState::new())).expect("builds");
        assert_eq!(w.cursor.load(Ordering::SeqCst), 4_242_424);
        assert_eq!(w.checkpoint().last_scanned, 4_242_424);
    }

    #[test]
    fn task_filter_keeps_only_the_watched_task_and_its_own_channels() {
        let mut cfg = Config::default();
        cfg.node.task_filter = Some(B256::from(U256::from(1)));
        let state = Arc::new(NodeState::new());
        let w = Watcher::new(&cfg, state.clone()).expect("builds");

        assert!(w.passes_filter(&real("EpochOpened")));
        assert!(!w.passes_filter(&ChainEvent::EpochOpened {
            task_id: U256::from(2),
            epoch: 0,
            enc_weights_cid: B256::ZERO,
            weights_digest: B256::ZERO,
        }));

        // A channel event names no task, so it is attributed through the fold: unknown
        // channel is dropped, a channel belonging to the watched task is kept.
        let orphan = ChainEvent::SliceRedeemed {
            channel_id: U256::from(77),
            node: addr(NODE),
            cumulative: 1,
            amount: 1,
            slice_index: 0,
        };
        assert!(!w.passes_filter(&orphan));
        state.apply(&real("ChannelOpened"));
        // Still dropped: `ChannelOpened` in the capture is for task 1, and the orphan names a
        // different channel, so the fold cannot attribute it.
        assert!(!w.passes_filter(&orphan));
        let ours = ChainEvent::SliceRedeemed {
            channel_id: U256::from(1),
            node: addr(NODE),
            cumulative: 1,
            amount: 1,
            slice_index: 0,
        };
        assert!(w.passes_filter(&ours));
    }
}
