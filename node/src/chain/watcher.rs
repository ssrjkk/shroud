//! Reorg-safe log watcher.
//!
//! The node's view of the chain is a fold over logs. Two properties make it correct rather
//! than merely working:
//!
//! 1. **Only finalised blocks are acted on.** An epoch commit costs a real STARK, so acting on
//!    a log that later disappears means doing the work twice. The watcher holds a cursor that
//!    trails the head by `finality.confirmations` blocks.
//!
//! 2. **A reorg invalidates the fold, so the fold restarts from the fork point.** Block hashes
//!    for the last `reorg_threshold + confirmations` blocks are kept in a ring. When one no
//!    longer matches the canonical chain, every derived state derived from it is discarded and
//!    the fold replays from that block. There is no attempt to "undo" individual events:
//!    getting that wrong is how nodes end up accepting a proof for an epoch that no longer
//!    exists.
//!
//! The watcher is the only place that talks to the chain for events, so the reorg policy is
//! auditable in one file.

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use alloy::{
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider},
    rpc::types::Log,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use super::bindings::events;
use crate::{
    config::{Config, FinalityConfig},
    error::{ConfigError, Error, Result},
    state::NodeState,
};

/// A decoded Shroud event, as the rest of the node sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainEvent {
    TaskSealed {
        task_id: U256,
        ct_root: B256,
        shards: u32,
        contributors: u32,
    },
    EpochOpened {
        task_id: U256,
        epoch: u32,
        enc_weights_cid: B256,
        weights_digest: B256,
    },
    EpochCommitted {
        task_id: U256,
        epoch: u32,
        node: Address,
        trace_digest: B256,
    },
    EpochSettled {
        task_id: U256,
        epoch: u32,
        node: Address,
        amount: u128,
    },
    DisputeReported {
        task_id: U256,
        epoch: u32,
        reporter: Address,
        digest: B256,
    },
    TaskAborted {
        task_id: U256,
        reason: [u8; 4],
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
}

impl ChainEvent {
    pub fn task_id(&self) -> Option<U256> {
        match self {
            ChainEvent::TaskSealed { task_id, .. }
            | ChainEvent::EpochOpened { task_id, .. }
            | ChainEvent::EpochCommitted { task_id, .. }
            | ChainEvent::EpochSettled { task_id, .. }
            | ChainEvent::DisputeReported { task_id, .. }
            | ChainEvent::TaskAborted { task_id, .. }
            | ChainEvent::ChannelOpened { task_id, .. } => Some(*task_id),
            ChainEvent::SliceRedeemed { .. } => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ChainEvent::TaskSealed { .. } => "TaskSealed",
            ChainEvent::EpochOpened { .. } => "EpochOpened",
            ChainEvent::EpochCommitted { .. } => "EpochCommitted",
            ChainEvent::EpochSettled { .. } => "EpochSettled",
            ChainEvent::DisputeReported { .. } => "DisputeReported",
            ChainEvent::TaskAborted { .. } => "TaskAborted",
            ChainEvent::ChannelOpened { .. } => "ChannelOpened",
            ChainEvent::SliceRedeemed { .. } => "SliceRedeemed",
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
    poll_interval: std::time::Duration,
    get_logs_window: u64,
    get_logs_chunk: u64,
    state: Arc<NodeState>,
    cursor: AtomicU64,
    /// `(number, hash)` for the blocks we have folded past, oldest first. Covers
    /// `reorg_threshold + confirmations` blocks and is the only reliable fork detector.
    anchors: tokio::sync::Mutex<VecDeque<(u64, B256)>>,
    /// Broadcast channel for decoded events. Capacity 1024 is deliberate backpressure: if a
    /// consumer falls behind this far the node is not keeping up with an epoch window and
    /// `RecvError::Lagged` tells it so instead of silently dropping a commit.
    tx: broadcast::Sender<ChainEvent>,
    pub rx: broadcast::Receiver<ChainEvent>,
}

impl Watcher {
    pub fn new(provider: DynProvider, cfg: &Config, state: Arc<NodeState>) -> Result<Self> {
        let (tx, rx) = broadcast::channel(1_024);
        if cfg.chain.get_logs_chunk > cfg.chain.get_logs_window {
            return Err(ConfigError::Invalid {
                field: "chain.get_logs_chunk",
                reason: format!(
                    "chunk ({}) must not exceed window ({})",
                    cfg.chain.get_logs_chunk, cfg.chain.get_logs_window
                ),
            }
            .into());
        }
        Ok(Self {
            provider,
            contract: cfg.contracts.cipher_task,
            vault: cfg.contracts.payment_vault,
            finality: cfg.finality.clone(),
            poll_interval: cfg.chain.poll_interval,
            get_logs_window: cfg.chain.get_logs_window,
            get_logs_chunk: cfg.chain.get_logs_chunk,
            state,
            cursor: AtomicU64::new(cfg.chain.start_block.unwrap_or(0)),
            anchors: tokio::sync::Mutex::new(VecDeque::new()),
            tx,
            rx,
        })
    }

    /// Restore a checkpoint, validating it against the canonical chain first.
    ///
    /// A checkpoint is only trusted if it was written for the same `chain_id` **and** the
    /// block it names still has the recorded hash. Otherwise the cursor resets to the
    /// configured backfill depth.
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

    /// The block the watcher is allowed to act up to, given the current head.
    pub async fn safe_head(&self) -> Result<u64> {
        let head = self.provider.get_block_number().await?;
        Ok(head.saturating_sub(self.finality.confirmations))
    }

    /// Run until `shutdown` resolves. Reorg-safe, idempotent, and safe to restart.
    pub async fn run(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        info!(
            contract = %self.contract,
            confirmations = self.finality.confirmations,
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
                        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                        _ = shutdown.changed() => return Ok(()),
                    }
                    continue;
                }
            };

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

            let to = safe.min(from.saturating_add(self.get_logs_window.max(1) - 1));
            if let Err(e) = self.scan(from, to).await {
                error!(from, to, error = %e, "watcher: scan failed; will retry the same window");
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                    _ = shutdown.changed() => return Ok(()),
                }
                continue;
            }

            self.cursor.store(to, Ordering::SeqCst);
            self.record_anchor(to).await;
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
    /// The watcher records `(number, hash)` for every block it has folded past, in a ring
    /// covering `reorg_threshold + confirmations` blocks. On each poll it re-reads those
    /// blocks: the first one whose hash is no longer canonical is the fork point, and the fold
    /// restarts from there. If a recorded block is missing entirely the chain was reset or
    /// swapped, which is handled identically — a full replay.
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
                    self.state.reset();
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
    async fn record_anchor(&self, number: u64) {
        let Ok(Some(block)) = self.provider.get_block_by_number(number.into()).await else {
            // Losing an anchor is not fatal: it only means this block will not be used as a
            // fork point. The checkpoint still pins `last_scanned` across restarts.
            debug!(block = number, "could not record a reorg anchor");
            return;
        };
        let keep = (self.finality.reorg_threshold + self.finality.confirmations + 1) as usize;
        let mut anchors = self.anchors.lock().await;
        anchors.push_back((number, block.header.hash));
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

    /// Fetch and apply one block window.
    async fn scan(&self, from: u64, to: u64) -> Result<()> {
        let mut cursor = from;
        let chunk = self.get_logs_chunk.max(1);
        while cursor <= to {
            let end = to.min(cursor + chunk - 1);
            let filter = self.filter().from_block(cursor).to_block(end);

            let logs = self
                .provider
                .get_logs(&filter)
                .await
                .map_err(|e| Error::Chain(format!("eth_getLogs {cursor}..={end}: {e}")))?;

            // Sort by (block, log_index): the fold must be deterministic regardless of the
            // order the RPC returns.
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
                        debug!(kind = ev.kind(), task = ?ev.task_id(), "applying event");
                        // `send` fails only when nobody is listening, which is fine: the
                        // state machine has already been updated by the consumer, and the
                        // watcher must not block on a slow or absent consumer.
                        let _ = self.tx.send(ev);
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
        // `selectors` (pre-computed topics), not `events` (signatures): the topics are already
        // derived from the signature strings in `bindings::events`, so asking the provider to
        // hash them again would be redundant and would silently mean something different if the
        // two lists ever drifted.
        //
        // Both addresses go into one `Vec` because `Filter::address` *replaces* the value on
        // each call; calling it twice leaves only the vault, and the node would silently stop
        // seeing task events.
        let addresses = vec![self.contract, self.vault];
        alloy::rpc::types::Filter::new()
            .address(addresses)
            .from_block(0)
            .event_signature(events::WATCH.clone())
    }

    /// Decode a log. `Ok(None)` means "not ours after all" (a topic we subscribe to that
    /// belongs to a different contract, e.g. a vault event seen through the task address).
    ///
    /// Both the indexed arguments (from `log.topics()`) and the data words are needed, and
    /// getting that split wrong is the classic way a log decoder silently reads zeros, so
    /// the two are kept as separate parameters all the way down.
    fn decode(&self, log: &Log) -> Result<Option<ChainEvent>> {
        let topics = log.topics();
        let Some(first) = topics.first() else {
            return Ok(None);
        };
        let data = &log.data().data[..];

        if log.address() == self.contract {
            if let Some(ev) = decode_task_event(first, topics, data) {
                return Ok(Some(ev));
            }
        }
        if log.address() == self.vault {
            if let Some(ev) = decode_vault_event(first, topics, data) {
                return Ok(Some(ev));
            }
        }
        Ok(None)
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

    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            last_scanned: self.cursor.load(Ordering::SeqCst),
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
    indexed_b256(topics, i).map(|b| Address::from_slice(&b.0[12..32]))
}

fn indexed_u32(topics: &[B256], i: usize) -> Option<u32> {
    indexed_b256(topics, i).map(|b| u32::from_be_bytes(b.0[28..32].try_into().expect("4 bytes")))
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

/// `CipherTask` events.
///
/// | event              | indexed                    | data                     |
/// |--------------------|----------------------------|--------------------------|
/// | `TaskSealed`       | taskId                     | ctRoot, shards, contributors |
/// | `EpochOpened`      | taskId, epoch              | encWeightsCid, weightsDigest |
/// | `EpochCommitted`   | taskId, epoch, node        | traceDigest              |
/// | `EpochSettled`     | taskId, epoch, node        | amount                   |
/// | `DisputeReported`  | taskId, epoch, reporter    | digest                   |
/// | `TaskAborted`      | taskId                     | reason (bytes4)          |
pub fn decode_task_event(sig: &B256, topics: &[B256], data: &[u8]) -> Option<ChainEvent> {
    if *sig == events::task_sealed() {
        return Some(ChainEvent::TaskSealed {
            task_id: indexed(topics, 0)?,
            ct_root: data_word(data, 0)?,
            shards: u32_of(data_word(data, 1)?),
            contributors: u32_of(data_word(data, 2)?),
        });
    }
    if *sig == events::epoch_opened() {
        return Some(ChainEvent::EpochOpened {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            enc_weights_cid: data_word(data, 0)?,
            weights_digest: data_word(data, 1)?,
        });
    }
    if *sig == events::epoch_committed() {
        return Some(ChainEvent::EpochCommitted {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            node: indexed_address(topics, 2)?,
            trace_digest: data_word(data, 0)?,
        });
    }
    if *sig == events::epoch_settled() {
        return Some(ChainEvent::EpochSettled {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            node: indexed_address(topics, 2)?,
            amount: u128_of(data_word(data, 0)?),
        });
    }
    if *sig == events::dispute_reported() {
        return Some(ChainEvent::DisputeReported {
            task_id: indexed(topics, 0)?,
            epoch: indexed_u32(topics, 1)?,
            reporter: indexed_address(topics, 2)?,
            digest: data_word(data, 0)?,
        });
    }
    if *sig == events::task_aborted() {
        return Some(ChainEvent::TaskAborted {
            task_id: indexed(topics, 0)?,
            reason: data_word(data, 0)?.0[28..32].try_into().expect("4 bytes"),
        });
    }
    None
}

/// `PaymentVault` events.
///
/// | event           | indexed             | data                                    |
/// |-----------------|---------------------|-----------------------------------------|
/// | `ChannelOpened` | channelId, taskId   | node, streamer, maxCumulative, unlockAt |
/// | `SliceRedeemed` | channelId           | node, cumulative, amount, sliceIndex    |
pub fn decode_vault_event(sig: &B256, topics: &[B256], data: &[u8]) -> Option<ChainEvent> {
    if *sig == events::channel_opened() {
        return Some(ChainEvent::ChannelOpened {
            channel_id: indexed(topics, 0)?,
            task_id: indexed(topics, 1)?,
            node: address_of(data_word(data, 0)?),
            streamer: address_of(data_word(data, 1)?),
            max_cumulative: u128_of(data_word(data, 2)?),
            unlock_at: u64_of(data_word(data, 3)?),
        });
    }
    if *sig == events::slice_redeemed() {
        return Some(ChainEvent::SliceRedeemed {
            channel_id: indexed(topics, 0)?,
            node: address_of(data_word(data, 0)?),
            cumulative: u128_of(data_word(data, 1)?),
            amount: u128_of(data_word(data, 2)?),
            slice_index: u64_of(data_word(data, 3)?),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topics(sig: B256, words: &[B256]) -> Vec<B256> {
        let mut v = vec![sig];
        v.extend_from_slice(words);
        v
    }

    #[test]
    fn epoch_opened_reads_indexed_and_data_from_the_right_places() {
        let t = topics(
            events::epoch_opened(),
            &[
                B256::from(U256::from(7).to_be_bytes::<32>()),
                B256::from(U256::from(2).to_be_bytes::<32>()),
            ],
        );
        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(&[0xAA; 32]);
        data[32..64].copy_from_slice(&[0xBB; 32]);

        let ev = decode_task_event(&events::epoch_opened(), &t, &data).expect("decodes");
        match ev {
            ChainEvent::EpochOpened {
                task_id,
                epoch,
                enc_weights_cid,
                weights_digest,
            } => {
                assert_eq!(task_id, U256::from(7));
                assert_eq!(epoch, 2);
                assert_eq!(enc_weights_cid, B256::from([0xAA; 32]));
                assert_eq!(weights_digest, B256::from([0xBB; 32]));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn epoch_committed_reads_the_node_from_topics_not_data() {
        let node = Address::from_slice(&[0x11; 20]);
        let mut node_word = [0u8; 32];
        node_word[12..32].copy_from_slice(node.as_slice());
        let t = topics(
            events::epoch_committed(),
            &[
                B256::from(U256::from(1).to_be_bytes::<32>()),
                B256::from(U256::from(0).to_be_bytes::<32>()),
                B256::from(node_word),
            ],
        );
        let mut data = [0u8; 32];
        data[..].copy_from_slice(&[0xCC; 32]);

        let ev = decode_task_event(&events::epoch_committed(), &t, &data).expect("decodes");
        match ev {
            ChainEvent::EpochCommitted {
                node: got,
                trace_digest,
                ..
            } => {
                assert_eq!(got, node);
                assert_eq!(trace_digest, B256::from([0xCC; 32]));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn a_short_data_buffer_decodes_to_none_rather_than_reading_past_the_end() {
        let t = topics(events::epoch_opened(), &[B256::ZERO, B256::ZERO]);
        assert!(decode_task_event(&events::epoch_opened(), &t, &[0u8; 32]).is_none());
        assert!(decode_task_event(&events::epoch_opened(), &t, &[0u8; 64]).is_some());
    }

    #[test]
    fn a_missing_topic_decodes_to_none() {
        // Only the signature, no indexed args at all.
        let t = vec![events::epoch_committed()];
        assert!(decode_task_event(&events::epoch_committed(), &t, &[0u8; 32]).is_none());
    }

    #[test]
    fn task_aborted_reads_a_bytes4_reason_from_the_low_word() {
        let t = topics(
            events::task_aborted(),
            &[B256::from(U256::from(9).to_be_bytes::<32>())],
        );
        let mut data = [0u8; 32];
        data[28..32].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let ev = decode_task_event(&events::task_aborted(), &t, &data).expect("decodes");
        assert_eq!(
            ev,
            ChainEvent::TaskAborted {
                task_id: U256::from(9),
                reason: [0xde, 0xad, 0xbe, 0xef]
            }
        );
    }

    #[test]
    fn channel_opened_splits_two_indexed_and_four_data_words() {
        let t = topics(
            events::channel_opened(),
            &[
                B256::from(U256::from(5).to_be_bytes::<32>()),
                B256::from(U256::from(3).to_be_bytes::<32>()),
            ],
        );
        let mut data = [0u8; 128];
        // Word 2 is the `uint128`, right-aligned in its 32-byte slot; word 3 is the `uint64`.
        data[80..96].copy_from_slice(&1_234u128.to_be_bytes());
        data[120..128].copy_from_slice(&7u64.to_be_bytes());

        let ev = decode_vault_event(&events::channel_opened(), &t, &data).expect("decodes");
        match ev {
            ChainEvent::ChannelOpened {
                channel_id,
                task_id,
                max_cumulative,
                unlock_at,
                ..
            } => {
                assert_eq!(channel_id, U256::from(5));
                assert_eq!(task_id, U256::from(3));
                assert_eq!(max_cumulative, 1_234);
                assert_eq!(unlock_at, 7);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn slice_redeemed_reads_slice_index_from_the_fourth_data_word() {
        // `SliceRedeemed` indexes only `channelId`; `sliceIndex` is the 4th data word.
        // Reading it from the topics would silently yield zero and every slice would be
        // numbered 0, which is exactly the kind of bug that only shows up in a dispute.
        let t = topics(
            events::slice_redeemed(),
            &[B256::from(U256::from(11).to_be_bytes::<32>())],
        );
        let mut data = [0u8; 128];
        data[120..128].copy_from_slice(&42u64.to_be_bytes());

        let ev = decode_vault_event(&events::slice_redeemed(), &t, &data).expect("decodes");
        match ev {
            ChainEvent::SliceRedeemed {
                channel_id,
                slice_index,
                amount,
                cumulative,
                ..
            } => {
                assert_eq!(channel_id, U256::from(11));
                assert_eq!(slice_index, 42);
                assert_eq!(cumulative, 0);
                assert_eq!(amount, 0);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn unknown_topic_decodes_to_none() {
        assert!(decode_task_event(
            &B256::from([9u8; 32]),
            &[B256::from([9u8; 32])],
            &[0u8; 128]
        )
        .is_none());
    }
}
