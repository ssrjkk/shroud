//! The inbound half of the peer mesh: what this node answers when a peer calls it.
//!
//! Three RPCs, and the rule on each is the same: a peer is an *untrusted* source of information
//! about data, so everything it hands over is checked against a length, a chain, or a capability
//! before it is believed — and nothing a peer says can make this node spend gas or read bytes it
//! does not have.
//!
//! * `gossip` — a long-lived stream. The first envelope must be a `Hello`; the handshake refuses a
//!   peer that never introduces itself, one on another chain, and one with a malformed node id.
//!   Shard announcements go into a bounded index whose only job is to let a later miss say *which
//!   peer claimed the object*.
//! * `fetch_shard` — a ranged read of the local content-addressed store, bounded by
//!   `shard.range_bytes` per call, `shard.max_ciphertext_bytes` per object, and
//!   `mesh.request_timeout` per read.
//! * `announce_epoch` — intent, nothing more. The chain assigns epochs; this only reports what our
//!   own fold already says about the announced epoch.
//!
//! # Why a peer's trace digest is logged and not stored
//!
//! The state fold ingests chain logs and nothing else, by design: if gossip could move state, a
//! peer could move this node's idea of what it is owed. A reported digest is therefore validated
//! and written to the log for the operator, and never folded in. A node that wants an opinion on an
//! epoch forms it by re-executing, not by believing an announcement.
//!
//! # Store layout
//!
//! The objects served here are `shard.cache_dir/<hex-of-ciphertextCid>`, one file per object. In
//! this build nothing *writes* that directory — the DA-layer puller is not implemented — so a node
//! serves what the operator put in the cache and answers `not_found` for the rest. That is a real
//! answer with a real consequence: the caller tries the named peer, then the DA layer.

use std::{
    collections::{HashMap, VecDeque},
    io::SeekFrom,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use alloy::primitives::{keccak256, B256, U256};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{mpsc, watch, Semaphore},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::{Certificate, Identity, Server, ServerTlsConfig},
    Request, Response, Status, Streaming,
};
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    error::{ConfigError, Error, MeshError, Result},
    mesh::{
        mesh_server,
        proto::{
            envelope::Body, Ack, Envelope, EpochAnnouncement, Hello, ShardAnnounce, ShardRequest,
            ShardResponse, TraceDigestAnnounce,
        },
        DecimalU256,
    },
    state::{EpochState, NodeState},
};

/// One item of a gossip stream, in the shape tonic's server-streaming bound requires.
type GossipItem = std::result::Result<Envelope, Status>;

/// Outgoing envelopes buffered per gossip stream.
///
/// Small on purpose: once the buffer is full the read loop blocks, which is backpressure on a peer
/// that cannot drain its own stream. Dropping announcements instead would quietly desynchronise the
/// two indexes.
const OUTBOUND_BUFFER: usize = 32;

/// `Hello.node_id` is the 20-byte operator address. Any other length is a peer that means something
/// else by the field, and a mesh where identities do not mean the same thing at both ends is worse
/// than a mesh that refuses to talk.
const NODE_ID_BYTES: usize = 20;

/// A trace digest is 32 bytes because it is a `bytes32` on chain, not a hash of convenience.
const DIGEST_BYTES: usize = 32;

/// The `EpochAnnouncement.intent` values the protocol defines.
const INTENTS: [&str; 3] = ["execute", "reexecute", "observe"];

/// The capability a peer must advertise for its trace digests to be worth this node's attention:
/// only a node that can re-execute an epoch can have derived one.
const CAPABILITY_REEXECUTION: &str = "stark-babybear";

/// A shard a peer said it holds.
#[derive(Debug, Clone)]
pub struct AnnouncedShard {
    pub task_id: U256,
    pub leaf_index: u32,
    pub ct_digest: B256,
    pub rows: u32,
    pub bytes: u32,
    pub announced_at: u64,
    /// Hex of the announcing peer's node id, so a later miss can name where to try next.
    pub peer: String,
}

/// Per-IP token bucket for inbound mesh work.
///
/// `fetch_shard` does disk I/O and gossip writes grow the shard index, so a peer flooding
/// either is a disk/CPU DoS on this node. The bucket is per peer IP: `burst` tokens of
/// headroom, refilled at `rps`. `take` is pure over an injected `now`, so the window math
/// is unit-testable without sleeping.
///
/// Memory is bounded like the shard index: at most `max_peers` buckets, idle-full buckets
/// swept, and the stalest bucket evicted when a new peer arrives at a full table — the
/// newcomer is throttled from a full burst like any new peer, never admitted unthrottled.
#[derive(Debug)]
pub struct InboundThrottle {
    rps: f64,
    burst: f64,
    buckets: HashMap<IpAddr, Bucket>,
    max_peers: usize,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl InboundThrottle {
    pub fn new(rps: u64, burst: u64) -> Self {
        // Zero here divides by zero in the retry computation; config validation rejects it,
        // and this is the backstop for direct construction.
        assert!(rps >= 1, "inbound rps must be >= 1");
        assert!(burst >= 1, "inbound burst must be >= 1");
        Self {
            rps: rps as f64,
            burst: burst as f64,
            buckets: HashMap::new(),
            max_peers: 10_000,
        }
    }

    /// Cap the peer table below the default (see `mesh.max_throttle_peers`). The bound
    /// is memory, not policy: past it the stalest bucket is evicted, never the accounting.
    pub fn with_max_peers(mut self, max_peers: usize) -> Self {
        assert!(max_peers >= 1, "throttle peer cap must be >= 1");
        self.max_peers = max_peers;
        self
    }

    /// Take one request token for `ip`. `Err(retry_after)` when over quota.
    ///
    /// Synchronous by design: under the service lock, check-and-record is atomic and no
    /// two concurrent requests from one peer can both see the last token.
    pub fn take(&mut self, ip: IpAddr, now: Instant) -> std::result::Result<(), Duration> {
        if !self.buckets.contains_key(&ip) {
            if self.buckets.len() >= self.max_peers {
                self.sweep(now);
                if self.buckets.len() >= self.max_peers {
                    // Still full of active peers: evict the stalest bucket to make room
                    // rather than admitting the newcomer unthrottled. Memory stays bounded
                    // and every peer — including an IP-rotating flooder cycling past
                    // `max_peers` — is throttled from a full burst like any new peer.
                    if let Some(victim) = self
                        .buckets
                        .iter()
                        .min_by_key(|(_, bucket)| bucket.updated)
                        .map(|(ip, _)| *ip)
                    {
                        self.buckets.remove(&victim);
                    }
                }
            }
            self.buckets.insert(
                ip,
                Bucket {
                    tokens: self.burst,
                    updated: now,
                },
            );
        }
        let bucket = match self.buckets.get_mut(&ip) {
            Some(b) => b,
            // Unreachable under `&mut self` (the insert above just ran), but a future
            // evict/sweep refactor must not turn into a per-packet panic on the mesh
            // hot path: fail closed with a retry instead.
            None => return Err(Duration::from_millis(100)),
        };
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - bucket.tokens) / self.rps))
        }
    }

    /// Drop buckets that are both full and idle past 60s. Returns evicted count.
    ///
    /// Refill is applied before the idleness check (without moving `updated`): a bucket
    /// that would be full if anyone asked is as good as full for eviction purposes, and
    /// idle age is still measured from the last real request, not from the sweep.
    pub fn sweep(&mut self, now: Instant) -> usize {
        let idle_for = Duration::from_secs(60);
        for bucket in self.buckets.values_mut() {
            let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
            if elapsed > 0.0 {
                bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
            }
        }
        let before = self.buckets.len();
        self.buckets.retain(|_, b| {
            !(b.tokens >= self.burst - f64::EPSILON
                && now.saturating_duration_since(b.updated) > idle_for)
        });
        before - self.buckets.len()
    }

    #[cfg(test)]
    fn peer_count(&self) -> usize {
        self.buckets.len()
    }
}

/// A bounded, peer-fed view of who holds what.
///
/// Bounded because a peer must not be able to grow this node's memory: `index_capacity` is a hard
/// cap and the oldest first announcement leaves it. Eviction is by first announcement rather than
/// least-recently-used — a re-announcement refreshes an entry's contents but does not extend its
/// life, which keeps the queue honest without an O(n) touch per message.
#[derive(Debug)]
pub struct ShardIndex {
    capacity: usize,
    order: VecDeque<B256>,
    entries: HashMap<B256, AnnouncedShard>,
}

impl ShardIndex {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    /// Record an announcement, returning the cid it displaced, if any.
    pub fn insert(&mut self, cid: B256, entry: AnnouncedShard) -> Option<B256> {
        if let Some(existing) = self.entries.get_mut(&cid) {
            *existing = entry;
            return None;
        }
        let evicted = if self.entries.len() >= self.capacity {
            self.order.pop_front()
        } else {
            None
        };
        if let Some(old) = evicted {
            self.entries.remove(&old);
        }
        self.order.push_back(cid);
        self.entries.insert(cid, entry);
        evicted
    }

    pub fn get(&self, cid: B256) -> Option<&AnnouncedShard> {
        self.entries.get(&cid)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The bytes this node will hand back for one `fetch_shard`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub start: u64,
    pub len: usize,
    /// Whether this chunk ends the object, which is what tells the caller to stop asking.
    pub complete: bool,
}

/// A validated peer: what the handshake learned, carried for the life of the stream.
struct Peer {
    label: String,
    capabilities: Vec<String>,
}

/// Everything a spawned gossip task needs, so the stream handler can hand it over as one `Arc`.
#[derive(Clone)]
struct Shared {
    chain_id: u64,
    cache_dir: PathBuf,
    max_object_bytes: u64,
    range_bytes: u64,
    request_timeout: Duration,
    state: Arc<NodeState>,
    index: Arc<Mutex<ShardIndex>>,
    inbound: Arc<Mutex<InboundThrottle>>,
    /// Global cap on in-flight mesh RPCs across ALL connections.
    ///
    /// M15 fix: `concurrency_limit_per_connection` alone does not stop a peer that opens
    /// many connections. Every handler (and every spawned gossip stream) holds one permit;
    /// when none is free the RPC is shed with `resource_exhausted` instead of spawning
    /// another task. Shed, never queue: queueing would let a hostile peer fill memory
    /// with pending streams while legitimate callers wait behind them.
    in_flight: Arc<Semaphore>,
}

/// The gRPC service.
pub struct MeshService {
    inner: Arc<Shared>,
}

impl MeshService {
    pub fn new(cfg: &Config, state: Arc<NodeState>) -> Self {
        Self {
            inner: Arc::new(Shared {
                chain_id: cfg.chain.chain_id,
                cache_dir: cfg.shard.cache_dir.clone(),
                max_object_bytes: cfg.shard.max_ciphertext_bytes,
                range_bytes: cfg.shard.range_bytes,
                request_timeout: cfg.mesh.request_timeout,
                state,
                index: Arc::new(Mutex::new(ShardIndex::new(cfg.mesh.index_capacity))),
                inbound: Arc::new(Mutex::new(
                    InboundThrottle::new(cfg.mesh.inbound_rps, cfg.mesh.inbound_burst)
                        .with_max_peers(cfg.mesh.max_throttle_peers),
                )),
                in_flight: Arc::new(Semaphore::new(cfg.mesh.max_global_streams.max(1))),
            }),
        }
    }

    /// Which peer last claimed to hold this object, if any.
    fn peer_holding(&self, cid: B256) -> Option<String> {
        self.inner
            .index
            .lock()
            .unwrap_or_else(poisoned)
            .get(cid)
            .map(|a| a.peer.clone())
    }
}

#[tonic::async_trait]
impl mesh_server::Mesh for MeshService {
    type GossipStream = ReceiverStream<GossipItem>;

    async fn gossip(
        &self,
        request: Request<Streaming<Envelope>>,
    ) -> std::result::Result<Response<Self::GossipStream>, Status> {
        // Global gate first: one permit per live gossip stream, held by the spawned task
        // for the stream's whole life. Shed when saturated — a gossip stream that waited
        // for a slot would hold its sender buffer open while the peer keeps writing.
        let permit = self
            .inner
            .in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("mesh saturated; retry later"))?;
        // Captured before `into_inner` consumes the request: the stream loop needs the peer
        // IP for throttling peer-fed writes, and there is no other place to get it.
        let peer_ip = request.remote_addr().map(|a| a.ip());
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(OUTBOUND_BUFFER);
        let shared = self.inner.clone();
        tokio::spawn(async move {
            let _permit = permit;
            run_gossip(&mut inbound, tx, shared, peer_ip).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn fetch_shard(
        &self,
        request: Request<ShardRequest>,
    ) -> std::result::Result<Response<ShardResponse>, Status> {
        // Global gate before any per-peer accounting or disk I/O: a range fetch is a
        // seek + read, and the permit is held until the chunk is served.
        let _permit = self
            .inner
            .in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("mesh saturated; retry later"))?;
        // Throttle before any disk I/O: a range fetch is a seek + read, and an uncapped peer
        // turns those into a disk DoS. Unknown peer address (unix socket) is admitted — the
        // throttle keys on IP, and refusing traffic we cannot attribute would break local use.
        if let Some(ip) = request.remote_addr().map(|a| a.ip()) {
            let retry = self
                .inner
                .inbound
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(ip, Instant::now());
            if let Err(retry) = retry {
                warn!(
                    ip = %ip,
                    retry_ms = retry.as_millis(),
                    "inbound mesh quota exceeded; shedding fetch_shard"
                );
                return Err(Status::resource_exhausted(format!(
                    "inbound quota exceeded; retry in {}ms",
                    retry.as_millis()
                )));
            }
        }
        let req = request.into_inner();
        let cid = to_b256(&req.ciphertext_cid)
            .ok_or_else(|| Status::invalid_argument("ciphertext_cid must be 32 bytes"))?;

        let path = self.inner.cache_dir.join(hex::encode(cid.as_slice()));
        let meta = tokio::fs::metadata(&path).await.map_err(|e| {
            // Naming a peer that claimed to hold this object is the difference between "try
            // elsewhere in the mesh" and "nothing in the mesh has it", and the caller acts
            // differently in the two cases.
            match self.peer_holding(cid) {
                Some(peer) => Status::not_found(format!(
                    "{cid:#x} is not in this node's store; last announced by {peer}"
                )),
                None => Status::not_found(format!("{cid:#x} is not in this node's store ({e})")),
            }
        })?;

        let range = plan_range(
            meta.len(),
            req.offset,
            req.length,
            self.inner.range_bytes,
            self.inner.max_object_bytes,
        )?;
        let chunk = read_range(&path, range.start, range.len, self.inner.request_timeout).await?;

        // `expected_sha256` is the digest of the *whole* object, so it is only checkable when the
        // whole object is in hand. A caller taking a range checks `chunk_digest` below, and the
        // concatenation itself.
        if range.complete && !req.expected_sha256.is_empty() {
            let got = Sha256::digest(&chunk);
            if got[..] != req.expected_sha256[..] {
                // Refusing is the only safe answer: the local copy is corrupt, and serving it would
                // hand the caller bytes that cannot reach the digest it asked for.
                warn!(
                    cid = format!("{cid:#x}"),
                    "the local copy does not match the object digest the caller expects"
                );
                return Err(Status::failed_precondition(
                    "local copy fails the object digest check",
                ));
            }
        }

        debug!(
            cid = format!("{cid:#x}"),
            start = range.start,
            len = range.len,
            complete = range.complete,
            "served a shard range"
        );
        // The caller hashes each chunk it receives, so a peer that returns a different byte at the
        // same offset is caught on the first range rather than in the middle of an epoch.
        let chunk_digest = keccak256(&chunk).as_slice().to_vec();
        Ok(Response::new(ShardResponse {
            chunk,
            next_offset: range.start + range.len as u64,
            complete: range.complete,
            chunk_digest,
            // Empty by design: the status code is the machine-readable answer, and an error a
            // caller can only branch on by string comparison is one it will branch wrong.
            error: String::new(),
        }))
    }

    async fn announce_epoch(
        &self,
        request: Request<EpochAnnouncement>,
    ) -> std::result::Result<Response<Ack>, Status> {
        // Cheap handler, but still gated: uniformity means one number (`max_global_streams`)
        // bounds every task this server can be holding, with no per-RPC asterisks.
        let _permit = self
            .inner
            .in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("mesh saturated; retry later"))?;
        let a = request.into_inner();
        let task_id = parse_id(&a.task_id).ok_or_else(|| {
            Status::invalid_argument(format!("task_id {:?} is not a decimal uint256", a.task_id))
        })?;
        if !INTENTS.contains(&a.intent.as_str()) {
            return Ok(Response::new(Ack {
                ok: false,
                reason: format!("unknown intent {:?}; expected {INTENTS:?}", a.intent),
            }));
        }

        // An answer about our own fold, and nothing else. The chain's `nodeRegistered` and commit
        // views decide who executes; announcing here moves neither.
        let answer = epoch_answer(
            a.epoch,
            self.inner
                .state
                .task(task_id)
                .as_ref()
                .and_then(|t| t.epoch(a.epoch)),
        );
        Ok(Response::new(answer))
    }
}

/// What this node's fold says about an epoch a peer just announced.
///
/// `ok` is "your announcement describes work that still exists here", not a verdict on the peer:
/// `None` means our watcher has not reached that epoch, which is an answer about *this* node's
/// height and not about the chain. The four cases a peer can act on are settled, rejected by the
/// dispute quorum, in progress, and unknown.
fn epoch_answer(epoch: u32, seen: Option<&EpochState>) -> Ack {
    match seen {
        None => Ack {
            ok: true,
            reason: "this node has no record of that epoch; its watcher may be behind".to_string(),
        },
        Some(e) if e.settled => Ack {
            ok: false,
            reason: format!("epoch {epoch} is already settled here"),
        },
        Some(e) if e.rejected => Ack {
            ok: false,
            reason: format!("epoch {epoch} reached the dispute quorum; nobody is paid for it"),
        },
        Some(e) => Ack {
            ok: true,
            reason: format!(
                "{} node(s) have committed to epoch {epoch}",
                e.commits.len()
            ),
        },
    }
}

/// The gossip read loop, in its own task so the outbound stream can be returned immediately.
async fn run_gossip(
    inbound: &mut Streaming<Envelope>,
    out: mpsc::Sender<GossipItem>,
    shared: Arc<Shared>,
    peer_ip: Option<IpAddr>,
) {
    let Some(peer) = handshake(inbound, &out, &shared).await else {
        return;
    };

    loop {
        let env = match inbound.message().await {
            Ok(Some(env)) => env,
            Ok(None) => {
                debug!(peer = %peer.label, "gossip stream ended");
                return;
            }
            Err(e) => {
                debug!(peer = %peer.label, error = %e, "gossip stream failed");
                return;
            }
        };

        // Peer-fed writes (index growth, log volume) share the inbound quota with
        // fetch_shard, and only those writes consume it: throttling cheap control frames
        // (Ping/Hello/Ack) would let a Ping flood starve legitimate announcements.
        // Over quota the message is nacked, not applied: the stream stays alive and an
        // honest peer backs off, while a flooding peer only burns its own quota.
        let is_write = matches!(
            &env.body,
            Some(Body::ShardAnnounce(_)) | Some(Body::TraceDigest(_))
        );
        if is_write {
            let over_quota = peer_ip
                .map(|ip| {
                    shared
                        .inbound
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .take(ip, Instant::now())
                        .is_err()
                })
                .unwrap_or(false);
            if over_quota {
                warn!("inbound mesh quota exceeded; shedding a peer-fed write");
                if !ack(&out, env.nonce, false, "inbound quota exceeded".to_string()).await {
                    return;
                }
                continue;
            }
        }

        let rejection = match env.body {
            Some(Body::ShardAnnounce(announce)) => record_announce(&shared, &peer.label, announce),
            Some(Body::TraceDigest(trace)) => {
                let reason = validate_trace(&peer.capabilities, &trace);
                if reason.is_none() {
                    debug!(
                        peer = %peer.label,
                        task = %trace.task_id,
                        epoch = trace.epoch,
                        "a peer reported a trace digest"
                    );
                }
                reason
            }
            Some(Body::Ping(_)) => None,
            Some(Body::Hello(hello)) => match validate_hello(&hello, shared.chain_id) {
                // A second Hello re-introduces the peer. If it now claims a different chain than
                // the one this stream was accepted on, the index no longer knows which chain its
                // announcements refer to, so the stream ends.
                Ok(_) => None,
                Err(reason) => {
                    let _ = ack(&out, env.nonce, false, reason).await;
                    return;
                }
            },
            Some(Body::Ack(reply)) => {
                if !reply.ok {
                    debug!(peer = %peer.label, reason = %reply.reason, "a peer rejected our message");
                }
                None
            }
            None => Some("empty envelope body".to_string()),
        };

        if let Some(reason) = rejection {
            if !ack(&out, env.nonce, false, reason).await {
                return;
            }
        }
    }
}

/// Read and validate the `Hello`, then return the peer.
async fn handshake(
    inbound: &mut Streaming<Envelope>,
    out: &mpsc::Sender<GossipItem>,
    shared: &Shared,
) -> Option<Peer> {
    let env = match inbound.message().await {
        Ok(Some(env)) => env,
        Ok(None) => return None,
        Err(e) => {
            debug!(error = %e, "gossip stream failed before the handshake");
            return None;
        }
    };

    let hello = match env.body {
        Some(Body::Hello(hello)) => hello,
        _ => {
            let reason = "the first envelope must be a Hello".to_string();
            let _ = ack(out, env.nonce, false, reason).await;
            return None;
        }
    };

    let label = match validate_hello(&hello, shared.chain_id) {
        Ok(label) => label,
        Err(reason) => {
            let _ = ack(out, env.nonce, false, reason).await;
            return None;
        }
    };

    info!(
        peer = %label,
        version = %hello.version,
        capabilities = ?hello.capabilities,
        "peer handshaked"
    );
    Some(Peer {
        label,
        capabilities: hello.capabilities,
    })
}

/// The handshake rules, as a pure function so they are testable without a stream.
///
/// `Ok` is the peer's label: the hex node id used in logs and in index entries.
fn validate_hello(hello: &Hello, our_chain_id: u64) -> std::result::Result<String, String> {
    if hello.node_id.len() != NODE_ID_BYTES {
        return Err(format!(
            "node_id must be {NODE_ID_BYTES} bytes, got {}",
            hello.node_id.len()
        ));
    }
    // M7: bls/signing keys were ignored, so anyone could claim any node_id.
    // Shape-check when present (empty = legacy peer, still accepted). Full
    // signature binding needs a protocol change; this kills trivial spoofs and
    // keeps mesh data hints-only (never drives FileDispute — that comes from
    // chain logs in state.rs, not from gossip).
    if !hello.bls_pubkey.is_empty() && hello.bls_pubkey.len() != DIGEST_BYTES {
        return Err(format!(
            "bls_pubkey must be {DIGEST_BYTES} bytes when present, got {}",
            hello.bls_pubkey.len()
        ));
    }
    if !hello.signing_pubkey.is_empty()
        && hello.signing_pubkey.len() != 33
        && hello.signing_pubkey.len() != 65
    {
        return Err(format!(
            "signing_pubkey must be 33 or 65 bytes when present, got {}",
            hello.signing_pubkey.len()
        ));
    }
    let claimed = match hello.chain_id.parse::<DecimalU256>() {
        Ok(id) => id.0,
        Err(e) => return Err(format!("chain_id is not a decimal uint256: {e}")),
    };
    if claimed != U256::from(our_chain_id) {
        return Err(format!(
            "chain id mismatch: we are {our_chain_id}, peer claims {claimed}"
        ));
    }
    Ok(hex::encode(&hello.node_id))
}

/// Index one shard announcement. `Some` is the reason to send back to the peer.
fn record_announce(shared: &Shared, peer: &str, a: ShardAnnounce) -> Option<String> {
    let task_id = match parse_id(&a.task_id) {
        Some(id) => id,
        None => return Some(format!("task_id {:?} is not a decimal uint256", a.task_id)),
    };
    let cid = match to_b256(&a.ciphertext_cid) {
        Some(cid) => cid,
        None => {
            return Some(format!(
                "ciphertext_cid must be {DIGEST_BYTES} bytes, got {}",
                a.ciphertext_cid.len()
            ))
        }
    };
    let ct_digest = match to_b256(&a.ct_digest) {
        Some(digest) => digest,
        None => {
            return Some(format!(
                "ct_digest must be {DIGEST_BYTES} bytes, got {}",
                a.ct_digest.len()
            ))
        }
    };
    // This node could never serve the announced object: anything past
    // `max_object_bytes` fails our own fetch caps, so indexing it only poisons
    // `peer_holding` hints and invites range pulls we will refuse.
    if u64::from(a.bytes) > shared.max_object_bytes {
        return Some(format!(
            "bytes {} exceeds this node's max_object_bytes {}",
            a.bytes, shared.max_object_bytes
        ));
    }

    let entry = AnnouncedShard {
        task_id,
        leaf_index: a.leaf_index,
        ct_digest,
        rows: a.rows,
        bytes: a.bytes,
        announced_at: a.announced_at,
        peer: peer.to_string(),
    };
    let mut index = shared.index.lock().unwrap_or_else(poisoned);
    if index.insert(cid, entry).is_some() {
        // Steady state once the cap is reached, so it stays out of the operator's log: the memory
        // is bounded, which is all the cap was ever for.
        debug!(
            cid = format!("{cid:#x}"),
            "shard index full; dropped the oldest announcement"
        );
    }
    None
}

/// Check a peer's trace digest. `Some` is the reason to send back.
fn validate_trace(capabilities: &[String], trace: &TraceDigestAnnounce) -> Option<String> {
    if !capabilities.iter().any(|c| c == CAPABILITY_REEXECUTION) {
        let expected = format!("only a {CAPABILITY_REEXECUTION} node can derive a trace digest");
        return Some(expected);
    }
    if parse_id(&trace.task_id).is_none() {
        return Some(format!(
            "task_id {:?} is not a decimal uint256",
            trace.task_id
        ));
    }
    if trace.trace_digest.len() != DIGEST_BYTES {
        let got = trace.trace_digest.len();
        return Some(format!(
            "trace_digest must be {DIGEST_BYTES} bytes, got {got}"
        ));
    }
    None
}

/// Parse a decimal `uint256` id field.
fn parse_id(src: &str) -> Option<U256> {
    src.parse::<DecimalU256>().ok().map(|v| v.0)
}

/// A `bytes` field that must be exactly a `bytes32`.
fn to_b256(src: &[u8]) -> Option<B256> {
    <[u8; 32]>::try_from(src).ok().map(B256::from)
}

/// The range a peer asked for, bounded by what this node is willing to read.
///
/// Each bound is a refusal rather than a clamp, except the tail of the object: a peer asking for
/// more than `range_bytes` has misconfigured *itself*, and quietly serving it less than it asked
/// for would make its own digest check fail with no explanation.
fn plan_range(
    size: u64,
    offset: u64,
    length: u64,
    range_bytes: u64,
    max_object_bytes: u64,
) -> std::result::Result<Range, Status> {
    if size > max_object_bytes {
        return Err(Status::failed_precondition(format!(
            "the local object is {size} bytes, over max_ciphertext_bytes = {max_object_bytes}"
        )));
    }
    if offset >= size {
        return Err(Status::out_of_range(format!(
            "offset {offset} is past the end of a {size} byte object"
        )));
    }
    let remaining = size - offset;
    let wanted = if length == 0 {
        remaining.min(range_bytes)
    } else if length > range_bytes {
        return Err(Status::invalid_argument(format!(
            "length {length} exceeds shard.range_bytes = {range_bytes}"
        )));
    } else {
        length
    };
    let len = usize::try_from(wanted.min(remaining))
        .map_err(|_| Status::invalid_argument("the requested range is too large"))?;
    Ok(Range {
        start: offset,
        len,
        complete: offset + len as u64 >= size,
    })
}

/// Read `len` bytes at `offset`, under the configured request deadline.
async fn read_range(
    path: &Path,
    offset: u64,
    len: usize,
    timeout: Duration,
) -> std::result::Result<Vec<u8>, Status> {
    let path = path.to_path_buf();
    let read = async move {
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(|e| Status::internal(format!("could not open the local object: {e}")))?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| Status::internal(format!("could not seek the local object: {e}")))?;
        // `read_exact`, not `read`: a file that shrank under us must fail here rather than return a
        // short chunk the caller would hash as if it were the range it asked for.
        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)
            .await
            .map_err(|e| Status::aborted(format!("the object changed while being read: {e}")))?;
        Ok(buf)
    };
    tokio::time::timeout(timeout, read)
        .await
        .map_err(|_| Status::deadline_exceeded("reading the local object timed out"))?
}

/// Send one `Ack` on the stream; `false` means the peer stopped reading.
async fn ack(out: &mpsc::Sender<GossipItem>, nonce: u64, ok: bool, reason: String) -> bool {
    let env = Envelope {
        nonce,
        body: Some(Body::Ack(Ack { ok, reason })),
    };
    out.send(Ok(env)).await.is_ok()
}

/// A poisoned lock means a gossip task panicked while inserting, which cannot leave the index
/// inconsistent (an entry is either replaced or not), so the panic is reported and the mesh keeps
/// serving rather than taking the node down with it.
fn poisoned(e: PoisonError<MutexGuard<'_, ShardIndex>>) -> MutexGuard<'_, ShardIndex> {
    e.into_inner()
}

/// Serve the mesh until `shutdown` fires.
///
/// The outbound half is not implemented in this build: this node accepts connections, and peers
/// that want its shards dial it. `mesh.peers` and `mesh.announce_interval` therefore change nothing
/// yet, which is said out loud at start-up rather than left as a silent no-op.
pub async fn serve(
    cfg: Config,
    state: Arc<NodeState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !cfg.mesh.peers.is_empty() {
        warn!(
            peers = cfg.mesh.peers.len(),
            "this build does not dial peers: mesh.peers and mesh.announce_interval are not \
             honoured, so the node only serves inbound gossip and range fetches"
        );
    }

    let service = mesh_server::MeshServer::new(MeshService::new(&cfg, state));

    let mut builder = Server::builder();
    // `Config::validate` rejects a partial triple, so this is either all three paths or none.
    if let (Some(cert), Some(key), Some(ca)) = (
        cfg.mesh.mtls_cert.as_ref(),
        cfg.mesh.mtls_key.as_ref(),
        cfg.mesh.ca_cert.as_ref(),
    ) {
        let tls = ServerTlsConfig::new()
            .identity(read_identity(cert, key)?)
            .client_ca_root(read_certificate(ca)?);
        builder = builder
            .tls_config(tls)
            .map_err(|e| listen_error(&cfg, &e))?;
        info!(addr = %cfg.mesh.listen, "peer mesh listening with mTLS");
    } else {
        warn!(
            addr = %cfg.mesh.listen,
            "the mesh is serving without TLS: set mesh.mtls_cert, mesh.mtls_key and mesh.ca_cert"
        );
    }

    let signal = async move {
        loop {
            if *shutdown.borrow_and_update() {
                return;
            }
            if shutdown.changed().await.is_err() {
                return;
            }
        }
    };

    builder = builder
        // M15 fix: the per-connection cap alone does not stop a peer that opens many
        // connections, so the handlers shed past `max_global_streams` in-flight RPCs
        // (see `Shared::in_flight`). The h2-level cap stays as the inner bound: each
        // gossip stream spawns a task plus a channel, so uncapped streams per connection
        // are task/memory exhaustion by handshake. Both caps live in config, not code.
        .concurrency_limit_per_connection(cfg.mesh.max_streams_per_connection);

    builder
        .add_service(service)
        .serve_with_shutdown(cfg.mesh.listen, signal)
        .await
        .map_err(|e| listen_error(&cfg, &e))?;
    Ok(())
}

fn listen_error(cfg: &Config, reason: &dyn std::fmt::Display) -> Error {
    Error::Mesh(MeshError::Server {
        addr: cfg.mesh.listen.to_string(),
        reason: reason.to_string(),
    })
}

fn read_identity(cert: &Path, key: &Path) -> Result<Identity> {
    let cert = std::fs::read(cert).map_err(|e| ConfigError::Invalid {
        field: "mesh.mtls_cert",
        reason: format!("{e}"),
    })?;
    let key = std::fs::read(key).map_err(|e| ConfigError::Invalid {
        field: "mesh.mtls_key",
        reason: format!("{e}"),
    })?;
    Ok(Identity::from_pem(cert, key))
}

fn read_certificate(ca: &Path) -> Result<Certificate> {
    let pem = std::fs::read(ca).map_err(|e| ConfigError::Invalid {
        field: "mesh.ca_cert",
        reason: format!("{e}"),
    })?;
    Ok(Certificate::from_pem(pem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::mesh_server::Mesh;

    fn cid(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    fn announce() -> ShardAnnounce {
        ShardAnnounce {
            task_id: "7".to_string(),
            leaf_index: 0,
            ciphertext_cid: cid(1).to_vec(),
            ct_digest: cid(2).to_vec(),
            rows: 128,
            bytes: 4096,
            announced_at: 1,
        }
    }

    fn hello(node_id: Vec<u8>, chain_id: &str) -> Hello {
        Hello {
            node_id,
            version: crate::VERSION.to_string(),
            capabilities: vec!["range-fetch".to_string()],
            chain_id: chain_id.to_string(),
            bls_pubkey: Vec::new(),
            signing_pubkey: Vec::new(),
        }
    }

    fn shared(capacity: usize) -> Shared {
        Shared {
            chain_id: 31_338,
            cache_dir: PathBuf::from("."),
            max_object_bytes: 8 << 30,
            range_bytes: 4 << 20,
            request_timeout: Duration::from_secs(1),
            state: Arc::new(NodeState::new()),
            index: Arc::new(Mutex::new(ShardIndex::new(capacity))),
            inbound: Arc::new(Mutex::new(InboundThrottle::new(100, 200))),
            in_flight: Arc::new(Semaphore::new(1024)),
        }
    }

    fn service(cfg: &Config) -> MeshService {
        MeshService::new(cfg, Arc::new(NodeState::new()))
    }

    fn request(offset: u64, length: u64, cid: B256, sha: Vec<u8>) -> Request<ShardRequest> {
        Request::new(ShardRequest {
            ciphertext_cid: cid.to_vec(),
            offset,
            length,
            expected_sha256: sha,
        })
    }

    const PEER: &str = "aa";

    #[test]
    fn a_hello_from_another_chain_is_refused() {
        let hello = hello(vec![0x11; 20], "999");
        let err = validate_hello(&hello, 31_338).expect_err("must refuse");
        assert!(err.contains("chain id mismatch"), "{err}");
    }

    #[test]
    fn a_non_decimal_chain_id_is_refused_rather_than_defaulted() {
        let hello = hello(vec![0x11; 20], "0x7aa6");
        let err = validate_hello(&hello, 31_338).expect_err("must refuse");
        assert!(err.contains("decimal"), "{err}");
    }

    #[test]
    fn a_node_id_of_the_wrong_length_is_refused() {
        for len in [0usize, 19, 21, 32] {
            let hello = hello(vec![0u8; len], "31338");
            let err = validate_hello(&hello, 31_338).expect_err("must refuse");
            assert!(err.contains("node_id must be 20 bytes"), "{err}");
        }
    }

    #[test]
    fn a_matching_hello_is_labelled_by_its_node_id() {
        let hello = hello(vec![0xab; 20], "31338");
        assert_eq!(
            validate_hello(&hello, 31_338).expect("accepts"),
            "ab".repeat(20)
        );
    }

    #[test]
    fn the_inbound_bucket_holds_burst_then_refills_at_the_rate() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let mut t = InboundThrottle::new(10, 3);
        let t0 = Instant::now();
        assert!(t.take(ip, t0).is_ok());
        assert!(t.take(ip, t0).is_ok());
        assert!(t.take(ip, t0).is_ok());
        // Burst spent: the fourth request in the same instant is over quota, with a
        // retry hint rather than a bare refusal.
        let retry = t.take(ip, t0).expect_err("burst is spent");
        assert!(retry > Duration::ZERO && retry <= Duration::from_millis(100));
        // Half a second later at 10 rps, five tokens are back: one request passes.
        let later = t0 + Duration::from_millis(500);
        assert!(t.take(ip, later).is_ok());
        // A different peer is unaffected by the first one's burst.
        let other: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(t.take(other, later).is_ok());
    }

    #[test]
    fn idle_buckets_are_swept_but_active_ones_survive() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let mut t = InboundThrottle::new(10, 3);
        let t0 = Instant::now();
        assert!(t.take(ip, t0).is_ok());
        // Recently used: survives the sweep even though it would refill to full.
        assert_eq!(t.sweep(t0 + Duration::from_secs(30)), 0);
        assert_eq!(t.peer_count(), 1);
        // Idle past the horizon: refilled to full by the sweep itself, then collected.
        // No per-peer leak from a slow trickle of distinct addresses.
        assert_eq!(t.sweep(t0 + Duration::from_secs(3600)), 1);
        assert_eq!(t.peer_count(), 0);
    }

    #[test]
    fn a_full_table_evicts_a_victim_instead_of_admitting_unthrottled() {
        // Fill every bucket with an active peer, then rotate in a newcomer: it must get
        // a real (burst-limited) bucket — never an unthrottled free pass — while the
        // table stays bounded. Otherwise cycling IPs past `max_peers` disables the
        // throttle exactly when it is needed.
        let mut t = InboundThrottle::new(10, 3);
        let t0 = Instant::now();
        for n in 0..10_000u32 {
            let ip: IpAddr = format!("10.0.{}.{}", n / 256, n % 256).parse().unwrap();
            assert!(t.take(ip, t0).is_ok());
        }
        assert_eq!(t.peer_count(), 10_000);
        let newcomer: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(t.take(newcomer, t0).is_ok());
        assert!(t.take(newcomer, t0).is_ok());
        assert!(t.take(newcomer, t0).is_ok());
        t.take(newcomer, t0)
            .expect_err("newcomer is throttled after its burst");
        assert!(t.peer_count() <= 10_000);
    }

    #[test]
    fn the_configured_peer_cap_bounds_the_table() {
        // Same eviction contract as the full-size table, at a scale a unit test can
        // assert precisely: the fourth peer displaces one of the first three, the table
        // never exceeds its cap, and the newcomer is burst-limited from the start.
        let mut t = InboundThrottle::new(10, 3).with_max_peers(3);
        let t0 = Instant::now();
        for n in 1..=3u8 {
            let ip: IpAddr = format!("10.9.0.{n}").parse().unwrap();
            assert!(t.take(ip, t0).is_ok());
        }
        assert_eq!(t.peer_count(), 3);
        let newcomer: IpAddr = "192.0.2.9".parse().unwrap();
        assert!(t.take(newcomer, t0).is_ok());
        assert_eq!(t.peer_count(), 3);
        assert!(t.take(newcomer, t0).is_ok());
        assert!(t.take(newcomer, t0).is_ok());
        t.take(newcomer, t0)
            .expect_err("newcomer is throttled after its burst");
    }

    #[test]
    fn an_announcement_with_a_short_cid_never_enters_the_index() {
        let shared = shared(16);
        let mut a = announce();
        a.ciphertext_cid = vec![0u8; 31];
        assert!(record_announce(&shared, PEER, a).is_some());
        assert!(shared.index.lock().unwrap_or_else(poisoned).is_empty());
    }

    #[test]
    fn an_announcement_bigger_than_our_cap_is_refused() {
        // We could never serve it (our own fetch caps would refuse), so indexing it
        // would only poison `peer_holding` hints with an unanswerable peer.
        let shared = Shared {
            chain_id: 31_338,
            cache_dir: PathBuf::from("."),
            max_object_bytes: 1024,
            range_bytes: 4 << 20,
            request_timeout: Duration::from_secs(1),
            state: Arc::new(NodeState::new()),
            index: Arc::new(Mutex::new(ShardIndex::new(16))),
            inbound: Arc::new(Mutex::new(InboundThrottle::new(100, 200))),
            in_flight: Arc::new(Semaphore::new(1024)),
        };
        let mut a = announce();
        a.bytes = 2048;
        let err = record_announce(&shared, PEER, a).expect("must refuse");
        assert!(err.contains("max_object_bytes"), "{err}");
        assert!(shared.index.lock().unwrap_or_else(poisoned).is_empty());
        // At exactly the cap it is serviceable: boundary is inclusive.
        let mut b = announce();
        b.bytes = 1024;
        assert!(record_announce(&shared, PEER, b).is_none());
        assert_eq!(shared.index.lock().unwrap_or_else(poisoned).len(), 1);
    }

    #[test]
    fn an_announcement_is_foundable_by_cid() {
        let shared = shared(16);
        assert!(record_announce(&shared, PEER, announce()).is_none());
        // The guard has to outlive the lookup: binding the two together would drop the lock at
        // the end of the statement and leave `got` pointing into a released mutex.
        let index = shared.index.lock().unwrap_or_else(poisoned);
        let got = index.get(cid(1)).expect("indexed");
        assert_eq!(got.task_id, U256::from(7));
        assert_eq!(got.ct_digest, cid(2));
        assert_eq!(got.peer, PEER);
    }

    #[test]
    fn the_index_is_hard_bounded_by_the_configured_capacity() {
        let shared = shared(3);
        for byte in 1..=5u8 {
            let mut a = announce();
            a.ciphertext_cid = cid(byte).to_vec();
            record_announce(&shared, PEER, a);
        }
        let index = shared.index.lock().unwrap_or_else(poisoned);
        assert_eq!(index.len(), 3);
        assert!(index.get(cid(1)).is_none(), "the oldest leaves first");
        assert!(index.get(cid(2)).is_none());
        assert!(index.get(cid(5)).is_some());
    }

    #[test]
    fn re_announcing_refreshes_an_entry_without_growing_the_index() {
        let mut index = ShardIndex::new(2);
        let mut entry = AnnouncedShard {
            task_id: U256::from(7),
            leaf_index: 0,
            ct_digest: cid(2),
            rows: 1,
            bytes: 1,
            announced_at: 1,
            peer: PEER.to_string(),
        };
        index.insert(cid(9), entry.clone());
        entry.rows = 2;
        assert!(index.insert(cid(9), entry).is_none());
        assert_eq!(index.len(), 1);
        assert_eq!(index.get(cid(9)).expect("present").rows, 2);
    }

    #[test]
    fn a_trace_digest_from_a_node_that_cannot_re_execute_is_not_believed() {
        let trace = TraceDigestAnnounce {
            task_id: "7".to_string(),
            epoch: 1,
            trace_digest: cid(3).to_vec(),
            observed_at: 1,
            proof: Vec::new(),
        };
        let err = validate_trace(&["range-fetch".to_string()], &trace)
            .expect("no re-execution capability");
        assert!(err.contains(CAPABILITY_REEXECUTION), "{err}");
        let caps = vec![CAPABILITY_REEXECUTION.to_string()];
        assert!(validate_trace(&caps, &trace).is_none());
    }

    #[test]
    fn a_misshapen_trace_digest_is_refused() {
        let caps = vec![CAPABILITY_REEXECUTION.to_string()];
        let trace = TraceDigestAnnounce {
            task_id: "7".to_string(),
            epoch: 1,
            trace_digest: cid(3)[..31].to_vec(),
            observed_at: 1,
            proof: Vec::new(),
        };
        let err = validate_trace(&caps, &trace).expect("short digest");
        assert!(err.contains("trace_digest must be 32 bytes"), "{err}");
    }

    #[test]
    fn a_range_larger_than_the_configured_chunk_is_refused() {
        let err = plan_range(1_000_000, 0, 5 << 20, 4 << 20, 8 << 30).expect_err("over cap");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn an_offset_past_the_end_is_out_of_range_rather_than_an_empty_chunk() {
        let err = plan_range(100, 100, 10, 4 << 20, 8 << 30).expect_err("past the end");
        assert_eq!(err.code(), tonic::Code::OutOfRange);
    }

    #[test]
    fn an_oversized_local_object_is_refused_before_anything_is_read() {
        let err = plan_range(1 << 30, 0, 10, 4 << 20, 1 << 20).expect_err("over the cap");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn a_zero_length_means_up_to_one_chunk() {
        let range = plan_range(10 << 20, 0, 0, 4 << 20, 8 << 30).expect("plans");
        assert_eq!(
            range,
            Range {
                start: 0,
                len: 4 << 20,
                complete: false
            }
        );
    }

    #[test]
    fn the_last_chunk_of_an_object_reports_complete() {
        let range = plan_range(10, 8, 100, 4 << 20, 8 << 30).expect("clamps");
        assert_eq!(
            range,
            Range {
                start: 8,
                len: 2,
                complete: true
            }
        );
    }

    #[test]
    fn a_cid_of_the_wrong_width_is_not_a_content_address() {
        assert!(to_b256(&[0u8; 31]).is_none());
        assert!(to_b256(&[0u8; 33]).is_none());
        assert_eq!(to_b256(&[7u8; 32]), Some(B256::repeat_byte(7)));
    }

    #[tokio::test]
    async fn reads_a_range_out_of_a_real_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("object");
        let body: Vec<u8> = (0u8..64).collect();
        tokio::fs::write(&path, &body).await.expect("write");

        let chunk = read_range(&path, 16, 8, Duration::from_secs(5))
            .await
            .expect("reads");
        assert_eq!(chunk, body[16..24]);

        // A range that runs off the end fails rather than returning a short chunk.
        let err = read_range(&path, 60, 8, Duration::from_secs(5))
            .await
            .expect_err("short read");
        assert_eq!(err.code(), tonic::Code::Aborted);
    }

    #[tokio::test]
    async fn a_whole_object_that_fails_the_digest_check_is_not_served() {
        let dir = tempfile::tempdir().expect("tempdir");
        let name = hex::encode(cid(3));
        tokio::fs::write(&dir.path().join(name), b"ciphertext")
            .await
            .expect("write");

        let mut cfg = Config::default();
        cfg.shard.cache_dir = dir.path().to_path_buf();
        let err = service(&cfg)
            .fetch_shard(request(0, 0, cid(3), vec![0u8; 32]))
            .await
            .expect_err("the local copy is corrupt");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn an_unknown_cid_names_the_peer_that_last_announced_it() {
        let mut cfg = Config::default();
        cfg.shard.cache_dir = PathBuf::from("/nonexistent-shroud-store");
        let service = service(&cfg);

        // Nothing announced yet: a plain miss, with no peer to blame.
        let miss = service
            .fetch_shard(request(0, 16, cid(4), Vec::new()))
            .await
            .expect_err("not in the store");
        assert_eq!(miss.code(), tonic::Code::NotFound);
        assert!(!miss.message().contains("last announced"), "{miss}");

        record_announce(&service.inner, PEER, announce());
        let hint = service
            .fetch_shard(request(0, 16, cid(1), Vec::new()))
            .await
            .expect_err("still not in the store");
        assert!(
            hint.message().contains(PEER),
            "the message names the peer: {hint}"
        );
    }

    #[tokio::test]
    async fn an_epoch_this_node_has_not_seen_is_answered_without_claiming_authority() {
        let ack = service(&Config::default())
            .announce_epoch(Request::new(EpochAnnouncement {
                task_id: "12345".to_string(),
                epoch: 0,
                intent: "execute".to_string(),
                announced_at: 1,
            }))
            .await
            .expect("answers")
            .into_inner();
        assert!(ack.ok);
        assert!(ack.reason.contains("no record"), "{}", ack.reason);
    }

    #[test]
    fn a_settled_or_rejected_epoch_is_reported_as_finished_work() {
        let settled = EpochState {
            settled: true,
            ..Default::default()
        };
        let ack = epoch_answer(4, Some(&settled));
        assert!(!ack.ok, "nobody has to race for a finished epoch");
        assert!(ack.reason.contains("settled"), "{}", ack.reason);

        let rejected = EpochState {
            rejected: true,
            ..Default::default()
        };
        let ack = epoch_answer(4, Some(&rejected));
        assert!(!ack.ok);
        assert!(ack.reason.contains("quorum"), "{}", ack.reason);
    }

    #[test]
    fn an_unseen_epoch_is_answered_as_a_question_about_this_node() {
        let ack = epoch_answer(9, None);
        assert!(ack.ok, "an unknown epoch is not the peer's error");
        assert!(ack.reason.contains("watcher"), "{}", ack.reason);

        let in_progress = EpochState::default();
        let ack = epoch_answer(9, Some(&in_progress));
        assert!(ack.ok);
        assert!(ack.reason.starts_with("0 node(s)"), "{}", ack.reason);
    }

    #[tokio::test]
    async fn an_unknown_intent_is_rejected_because_it_is_protocol_skew() {
        let ack = service(&Config::default())
            .announce_epoch(Request::new(EpochAnnouncement {
                task_id: "1".to_string(),
                epoch: 0,
                intent: "EXECUTE".to_string(),
                announced_at: 1,
            }))
            .await
            .expect("answers")
            .into_inner();
        assert!(!ack.ok);
    }

    #[tokio::test]
    async fn a_malformed_task_id_is_an_argument_error_not_a_silent_no_op() {
        let err = service(&Config::default())
            .announce_epoch(Request::new(EpochAnnouncement {
                task_id: "0x1".to_string(),
                epoch: 0,
                intent: "observe".to_string(),
                announced_at: 1,
            }))
            .await
            .expect_err("rejects");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
