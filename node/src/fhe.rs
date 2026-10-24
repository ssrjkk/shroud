//! Epoch execution: turning sealed shards and previous weights into new weights.
//!
//! This module is the compute leg the rest of the node was built around. It has two backends
//! behind one trait:
//!
//! * [`ReferenceCpuEngine`] — deterministic fixed-point SGD over `shroud/noop/v1` shards
//!   (the `NoopEncryptor` development path, where the DA payload carries `f64` rows in the
//!   clear). Always compiled in, byte-for-byte deterministic across runs, machines and nodes.
//! * `TfheBackend` (feature `prover` only) — the same epoch structure over real `tfhe-rs`
//!   `FheUint32` ciphertexts under the network server key. See its own docs for the two
//!   genuine constraints of that path (u32 wrapping arithmetic and PBS randomness breaking
//!   cross-node digest equality).
//!
//! # What `trace_digest` is
//!
//! The 32-byte commitment `commitEpoch` stores and disputes compare. It is a `keccak256` over
//! a documented byte layout (see [`trace_digest`]) binding the task, the epoch, the dataset
//! root, the previous weights, every consumed shard in leaf order, the hyperparameters and
//! the resulting weights. Two nodes that ran the same backend over the same inputs produce
//! the same digest; any difference in any input changes it. The chain never interprets it —
//! it only stores it — so agreement between re-executors is what makes a dispute decidable.
//!
//! # What `proof` is
//!
//! `commitEpoch` takes a 32-byte *proof reference*, never a proof: a real STARK does not fit
//! in 32 bytes. [`proof_reference`] derives that reference as `0x53544152 ("STAR") ||
//! keccak256("SHROUD/PROOF-REF/v1" || trace_digest)[0..28]`. The `STAR` prefix is what the
//! devnet `MockStarkVerifier` checks, so this reference verifies on mock-verifier chains and
//! binds the exact trace it attests to. On a chain with a production verifier it will not
//! verify — that is correct behaviour, not a bug: a trace digest without a proving system
//! behind it must not be committable there. The zkVM proving backend (Phase 3) replaces this
//! derivation, not the digest layout.

use std::sync::Arc;

use alloy::primitives::{Address, B256, U256};

use crate::config::FheConfig;
use crate::error::{Error, FheError, Result};

/// Envelope magics, re-exported from the portable core so there is exactly one
/// definition of each: `shroud/noop/v1` development shards, `shroud/weights/v1`
/// files, and the `tfhe-rs` envelopes (feature `prover` only).
pub use shroud_core::shard::{NOOP_SHARD_MAGIC, TFHE_SHARD_MAGIC};
pub use shroud_core::weights::WEIGHTS_MAGIC;
/// Envelope magic of `tfhe-rs` weight vectors (feature `prover` only).
pub const TFHE_WEIGHTS_MAGIC: &[u8] = b"shroud/tfhe-weights/v1\0";
/// Domain tag of the trace digest preimage (see [`trace_digest`]).
pub use shroud_core::transcript::TRACE_MAGIC;
/// Domain tag of the proof-reference derivation, and the `"STAR"` prefix every
/// proof reference carries (see [`proof_reference`]).
pub use shroud_core::transcript::{PROOF_REF_MAGIC, PROOF_REF_PREFIX};
/// Upper bound for the mean quantised loss of a sane epoch, in true (unscaled) units.
/// Past this the update is not learning but exploding, and committing its digest would put
/// a garbage claim on chain that a re-executor must then dispute.
const DIVERGENCE_LOSS_CAP: f64 = 1e12;

/// A weight vector, re-exported from the portable core (single definition — see
/// `shroud_core::weights`). Lanes are `i32` two's complement stored in `u32`
/// words; `lanes.len()` always equals `features`; the last lane is the bias.
pub use shroud_core::weights::Weights;

/// Decoded development shard and its decoder, re-exported from the portable core
/// (single definition — see `shroud_core::shard`).
pub use shroud_core::shard::{decode_noop_shard, ShardRows};

/// Everything an epoch execution needs, gathered by the worker before the engine runs.
///
/// Shards arrive in contract leaf order (`leaf_index` ascending): the digest binds the order,
/// so two nodes that consumed the same dataset in different orders must disagree — and do.
/// `bytes` are the exact DA payloads the chain pinned (the worker verifies
/// `keccak256(bytes) == ct_digest` before the engine runs); each backend decodes the
/// envelope it understands.
pub struct EpochInputs {
    pub task_id: U256,
    pub epoch: u32,
    pub chain_id: u64,
    pub cipher_task: Address,
    pub ct_root: B256,
    pub prev_weights_digest: B256,
    pub features: u32,
    pub scale: u32,
    pub lr_q16: u32,
    pub l2_q16: u32,
    pub minibatch: usize,
    pub seed: u64,
    /// Previous weights in the clear. `Some` on backends that observe them (reference);
    /// `None` where the node never decrypts (tfhe) — those use `prev_weights_bytes`.
    pub prev_weights: Option<Weights>,
    /// Previous weight file bytes (tfhe envelope on ciphertext backends). The worker
    /// refuses a zero `last_weights_cid` before the engine runs, so these are always
    /// present; there is no genesis path, because inventing weights would fork the digest.
    pub prev_weights_bytes: Vec<u8>,
    pub shards: Vec<ShardInput>,
}

/// One shard ready for the engine: identity for the digest, bytes for the math.
pub struct ShardInput {
    pub leaf_index: u32,
    pub cid: B256,
    pub ct_digest: B256,
    pub bytes: Vec<u8>,
}

/// What an execution produces: the artefacts the worker publishes.
pub struct EpochOutput {
    pub weights: Weights,
    /// `weightsDigest` for `commitEpoch` (digest of the lane words, or of the weight file
    /// for ciphertext backends — see each engine's docs).
    pub weights_digest: B256,
    /// `traceDigest` for `commitEpoch` (the execution commitment disputes compare).
    pub trace_digest: B256,
    /// Encoded weight file for the content-addressed store (`encWeightsCid` pins these).
    pub weights_bytes: Vec<u8>,
    /// Encoded metrics file for the store (`metricsCid` pins these).
    pub metrics_bytes: Vec<u8>,
    /// Mean quantised squared error of the epoch, for the metrics file.
    pub loss_mean_q: Option<i128>,
    pub rows: u64,
}

/// An epoch execution engine. Synchronous and `Send + Sync`: the worker runs it on a
/// blocking thread so a 40-second epoch never stalls finalisation and redemption.
pub trait FheEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute_epoch(&self, inputs: &EpochInputs) -> Result<EpochOutput>;
    /// Re-derive only the commitment (used by the dispute path to form an opinion).
    fn digest_epoch(&self, inputs: &EpochInputs) -> Result<B256> {
        Ok(self.execute_epoch(inputs)?.trace_digest)
    }
}

/// The trace commitment. Layout, in order:
///
/// ```text
/// "SHROUD/TRACE/v1\0" | task_id u256-BE | epoch u32-BE | chain_id u64-BE | cipher_task 20B
/// | ct_root | prev_weights_digest
/// | features u32-BE | scale u32-BE | lr_q16 u32-BE | l2_q16 u32-BE | minibatch u64-BE | seed u64-BE
/// | n_rows u64-BE | loss_mean_q i128-BE two's complement (0 when the backend cannot observe loss)
/// | per leaf ascending: leaf_index u32-BE | cid | ct_digest
/// | next_weights_digest
/// ```
///
/// `keccak256` of the concatenation. Every value that can change the result is in the
/// preimage — including the hyperparameters, so nodes that disagree on configuration
/// disagree on the digest instead of accusing each other. `ct_digest` (already verified
/// by the worker to equal `keccak256` of the shard bytes) stands in for the bytes: the
/// digest commits to the exact payload the chain pinned without re-hashing megabytes.
/// Byte-array conversions for the portable core (chain types stay at the boundary).
fn b2a(b: &B256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(b.as_slice());
    out
}

fn a2a(a: &Address) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(a.as_slice());
    out
}

pub fn trace_digest(
    inputs: &EpochInputs,
    n_rows: u64,
    loss_mean_q: Option<i128>,
    next_weights_digest: B256,
) -> B256 {
    let mut leaves: Vec<&ShardInput> = inputs.shards.iter().collect();
    leaves.sort_by_key(|s| s.leaf_index);
    let core_leaves: Vec<shroud_core::transcript::TraceLeaf> = leaves
        .iter()
        .map(|s| shroud_core::transcript::TraceLeaf {
            leaf_index: s.leaf_index,
            cid: b2a(&s.cid),
            ct_digest: b2a(&s.ct_digest),
        })
        .collect();
    B256::from(shroud_core::transcript::trace_digest(
        inputs.task_id.to_be_bytes::<32>(),
        inputs.epoch,
        inputs.chain_id,
        a2a(&inputs.cipher_task),
        b2a(&inputs.ct_root),
        b2a(&inputs.prev_weights_digest),
        inputs.features,
        inputs.scale,
        inputs.lr_q16,
        inputs.l2_q16,
        inputs.minibatch as u64,
        inputs.seed,
        n_rows,
        loss_mean_q,
        &core_leaves,
        b2a(&next_weights_digest),
    ))
}

/// The 32-byte `proof` reference for `commitEpoch`.
///
/// `0x53544152 ("STAR") || keccak256("SHROUD/PROOF-REF/v1" || trace_digest)[0..28]`.
/// The prefix satisfies the mock verifier's magic check on devnet/test chains; the hash
/// binds the exact trace, so the reference is useless for any other epoch. See the module
/// docs for why this is a reference and what replaces it on production verifiers.
pub fn proof_reference(trace_digest: B256) -> B256 {
    B256::from(shroud_core::transcript::proof_reference(b2a(&trace_digest)))
}

/// Deterministic fixed-point SGD for linear regression over quantised rows.
///
/// Row convention: the first `features - 1` lanes are inputs, the last lane is the label
/// (`labelBits` on chain describes its width). The weight vector has `features` lanes, the
/// last being the bias — the weight on the constant 1.0 input, quantised as `S`, so its
/// gradient accumulator lives in the same S² domain as every other lane and the shared
/// update rule applies to it unchanged. All arithmetic is checked `i128`; anything that does not fit is an
/// error, never a wrap: two nodes must compute the same digest, and wrapping would make
/// that depend on build details.
///
/// Update per minibatch of `m` rows, with `S = scale`, `Q = 2^16`:
/// `w -= (lr_q16 * Σ(err * x)) / (Q * S * m)`, then L2 once per epoch:
/// `w -= (l2_q16 * w) / Q`. Division truncates toward zero — deterministic on every
/// platform, which is the only property the dispute protocol needs from it.
///
/// The engine never touches the network or the chain: inputs in, artefacts out. Shard
/// fetching, DA publishing and `commitEpoch` are the worker's job.
pub struct ReferenceCpuEngine {
    scale: u32,
    lr_q16: u32,
    l2_q16: u32,
    minibatch: usize,
}

impl ReferenceCpuEngine {
    pub fn new(scale: u32, lr_q16: u32, l2_q16: u32, minibatch: usize) -> Self {
        Self {
            scale,
            lr_q16,
            l2_q16,
            minibatch,
        }
    }

    fn decoded(&self, inputs: &EpochInputs) -> shroud_core::Result<Vec<ShardRows>> {
        let mut leaves: Vec<&ShardInput> = inputs.shards.iter().collect();
        leaves.sort_by_key(|s| s.leaf_index);
        leaves
            .iter()
            .map(|s| decode_noop_shard(&s.bytes, inputs.features, self.scale))
            .collect()
    }
}

impl FheEngine for ReferenceCpuEngine {
    fn name(&self) -> &'static str {
        "reference-cpu"
    }

    fn execute_epoch(&self, inputs: &EpochInputs) -> Result<EpochOutput> {
        let f = inputs.features as usize;
        if f < 2 {
            return Err(Error::Fhe(FheError::ShapeMismatch {
                got_rows: 0,
                got_cols: f,
                want_rows: 0,
                want_cols: 2,
            }));
        }
        let prev_len = inputs.prev_weights.as_ref().map_or(0, |w| w.lanes.len());
        if prev_len != f {
            return Err(Error::Fhe(FheError::ShapeMismatch {
                got_rows: 0,
                got_cols: prev_len,
                want_rows: 0,
                want_cols: f,
            }));
        }
        if self.scale == 0 || self.minibatch == 0 {
            return Err(Error::Fhe(FheError::Backend(
                "reference engine: scale and minibatch must be non-zero".into(),
            )));
        }
        let decoded = self.decoded(inputs)?;
        let w: Vec<i64> = inputs
            .prev_weights
            .as_ref()
            .ok_or_else(|| {
                Error::Fhe(FheError::Backend(
                    "reference engine: prev_weights input is missing".into(),
                ))
            })?
            .signed();
        // The numeric heart lives in the portable core (`shroud_core::sgd`); the
        // `From<CoreError>` mapping keeps every stage label and message identical,
        // so disputes and logs see exactly the errors this function raised before.
        let views: Vec<shroud_core::sgd::ShardView<'_>> = decoded
            .iter()
            .map(|shard| shroud_core::sgd::ShardView {
                rows: shard.rows,
                values: &shard.values,
            })
            .collect();
        let sgd = shroud_core::sgd::run_epoch(
            &shroud_core::sgd::SgdParams {
                scale: self.scale,
                lr_q16: self.lr_q16,
                l2_q16: self.l2_q16,
                minibatch: self.minibatch,
            },
            f,
            &w,
            &views,
        )?;
        let (w, loss_mean, n_rows) = (sgd.weights, sgd.loss_mean_q, sgd.n_rows);
        let loss_true = loss_mean as f64 / f64::from(self.scale).powi(2);
        if loss_true > DIVERGENCE_LOSS_CAP {
            return Err(Error::Fhe(FheError::Diverged {
                epoch: inputs.epoch,
                loss: loss_true,
            }));
        }

        let mut lanes = Vec::with_capacity(f);
        for v in w {
            let word = i32::try_from(v)
                .map_err(|_| Error::Fhe(FheError::LaneOverflow(v.unsigned_abs())))?;
            lanes.push(word as u32);
        }
        let weights = Weights {
            features: inputs.features,
            lanes,
        };
        let weights_digest = B256::from(weights.digest());
        let weights_bytes = weights.encode();
        let metrics_bytes = metrics_bytes(
            "reference-cpu",
            inputs.epoch,
            n_rows,
            inputs.features,
            self.scale,
            Some(loss_mean),
        );
        let digest = trace_digest(inputs, n_rows, Some(loss_mean), weights_digest);
        Ok(EpochOutput {
            weights,
            weights_digest,
            trace_digest: digest,
            weights_bytes,
            metrics_bytes,
            loss_mean_q: Some(loss_mean),
            rows: n_rows,
        })
    }
}

/// Metrics file body (JSON): what the worker publishes under `metricsCid`.
fn metrics_bytes(
    engine: &str,
    epoch: u32,
    rows: u64,
    features: u32,
    scale: u32,
    loss_mean_q: Option<i128>,
) -> Vec<u8> {
    serde_json::json!({
        "v": 1,
        "engine": engine,
        "epoch": epoch,
        "rows": rows,
        "features": features,
        "scale": scale,
        "loss_mean_q": loss_mean_q.map(|l| l.to_string()),
    })
    .to_string()
    .into_bytes()
}

/// Fixed-point shift of the public learning-rate step (`STEP = round(lr·2^32/(S·m))`).
///
/// Compiled where it is used: the `prover` backend, and the tests that pin the
/// derivation. A build with neither has no use for it, and an unused item is a
/// warning, not a hint.
#[cfg(any(feature = "prover", test))]
const STEP_SHIFT: u32 = 32;

/// Shift-based public learning-rate derivation, computed once in the clear.
///
/// The update is `w -= (grad_acc * STEP) >> 32` with
/// `STEP = round(lr_q16 * 2^32 / (2^16 * S * m))`. `STEP` must fit in a u32 lane;
/// hyperparameters that do not fit are a configuration error, reported before any gas
/// is spent.
///
/// Deliberately outside the `prover`-gated backend: this is plain arithmetic, and keeping it
/// here means it is compiled and tested in every build rather than only in the ones that
/// pull in the FHE stack.
#[cfg(any(feature = "prover", test))]
fn derive_step(lr_q16: u32, scale: u32, minibatch: usize) -> Result<u32> {
    let denom = (1u128 << 16) * u128::from(scale) * (minibatch as u128);
    if denom == 0 {
        return Err(Error::Fhe(FheError::Backend(
            "tfhe backend: scale and minibatch must be non-zero".into(),
        )));
    }
    let step = ((u128::from(lr_q16) << STEP_SHIFT) + denom / 2) / denom;
    u32::try_from(step).map_err(|_| {
        Error::Fhe(FheError::Backend(format!(
            "tfhe backend: learning-rate step {step} exceeds the u32 lane; \
             lower fhe.lr_q16 or raise the quantisation scale"
        )))
    })
}

/// Shift-based L2 shrinkage step, computed once in the clear.
///
/// The shrinkage is `w -= (w * L2) >> 32` with `L2 = round(l2_q16 * 2^32 / 2^16)`,
/// i.e. `w -= l2_q16 * w / 2^16` - the same rule the reference engine applies
/// (`node/crates/shroud-core/src/sgd.rs`).
///
/// Deliberately not `derive_step`: the scale and the minibatch belong to the *gradient*
/// step (`w -= lr_q16 * Σ(err·x) / (2^16 · S · m)`), not to the shrinkage. Dividing by
/// the scale as well would make the tfhe backend's regularisation `S` times weaker
/// than the reference engine's - at the default scale of 10 000, no regularisation at
/// all, while the operator asked for `fhe.l2_q16`.
#[cfg(any(feature = "prover", test))]
fn derive_l2(l2_q16: u32) -> Result<u32> {
    let denom = 1u128 << 16;
    let step = ((u128::from(l2_q16) << STEP_SHIFT) + denom / 2) / denom;
    u32::try_from(step).map_err(|_| {
        Error::Fhe(FheError::Backend(format!(
            "tfhe backend: L2 step {step} exceeds the u32 lane; lower fhe.l2_q16"
        )))
    })
}

/// The row count an envelope's header must carry.
///
/// The decoder reads `features` and `rows` and then expects `rows * features` frames,
/// while an envelope holds one frame per lane. So the row count is `lanes / features`:
/// the weights are one row of `features` lanes. Writing the *lane* count here instead
/// leaves the decoder looking for `features` times too many frames, and every epoch
/// then fails with "truncated ciphertext length".
#[cfg(any(feature = "prover", test))]
fn envelope_rows(lanes: usize, features: u32) -> u32 {
    let per_row = features.max(1) as usize;
    (lanes / per_row) as u32
}

/// Frame opaque payloads into an envelope: the magic, the `features`/`rows` header the
/// decoder reads back, then each frame length-prefixed.
///
/// Deliberately free of any `tfhe` type: the framing is where the weights envelope and
/// its decoder used to disagree, and keeping it here means the agreement is compiled and
/// tested in every build rather than only in the ones that pull in the FHE stack.
#[cfg(any(feature = "prover", test))]
fn encode_frames(magic: &[u8], features: u32, rows: u32, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(magic);
    out.extend_from_slice(&features.to_le_bytes());
    out.extend_from_slice(&rows.to_le_bytes());
    for frame in frames {
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}

#[cfg(feature = "prover")]
mod tfhe_backend {
    //! Homomorphic epoch execution over real `tfhe-rs` ciphertexts.
    //!
    //! Same epoch structure as the reference engine, but the shards carry
    //! `shroud/tfhe/v1` envelopes of `FheUint32` ciphertexts encrypted under the network
    //! key, and every operation is a server-key homomorphic op. The node never holds the
    //! client key and never decrypts: digests bind the serialised ciphertexts.
    //!
    //! Envelope convention (buyer tooling must produce it; there is no producer in this
    //! repo yet): `shroud/tfhe/v1\0` + features u32-LE + rows u32-LE, then per lane a
    //! u32-LE length followed by that many `safe_serialize` bytes of one `FheUint32`.
    //! Values are quantised integers at `fhe.scale`, which MUST be a power of two on this
    //! path: the update scales by public shifts, and a non-power-of-two scale has no exact
    //! shift. Weights use `shroud/tfhe-weights/v1\0` with the same framing.
    //!
    //! Two genuine constraints, stated plainly because they shape deployments:
    //!
    //! * **u32 wrapping arithmetic.** `FheUint32` wraps mod 2^32. Keep quantised magnitudes
    //!   small (the reference engine range-checks; this one cannot) and run the same
    //!   backend on every node of a task.
    //! * **PBS randomness breaks cross-node byte equality.** Two honest nodes executing the
    //!   same inputs produce different ciphertext bytes, hence different digests. The quorum
    //!   dispute protocol needs byte-deterministic re-execution, so this backend is for
    //!   single-executor tasks today; multi-node deterministic FHE (deterministic parameter
    //!   sets, `TfheConcrete`-style) is tracked future work, not a property of this code.

    use std::path::PathBuf;
    use std::sync::Mutex;

    use alloy::primitives::keccak256;
    use tfhe::prelude::*;
    use tfhe::safe_serialization::safe_deserialize;
    use tfhe::{CompressedServerKey, FheUint32, ServerKey};

    use super::{
        derive_l2, derive_step, encode_frames, envelope_rows, EpochInputs, EpochOutput, Weights,
        STEP_SHIFT, TFHE_SHARD_MAGIC, TFHE_WEIGHTS_MAGIC,
    };
    use crate::error::{Error, FheError, Result, ShardError};

    /// Maximum serialised object this backend will deserialise (server keys are GB-scale).
    const DESERIALIZE_LIMIT: u64 = 8 << 30;

    struct CachedKey {
        mtime: std::time::SystemTime,
        key: ServerKey,
    }

    /// `slot = f(slot)` for ciphertext lanes: the old value moves into the closure,
    /// so indexed updates never borrow against themselves.
    fn update_ct(slot: &mut FheUint32, f: impl FnOnce(FheUint32) -> FheUint32) {
        let old = std::mem::replace(slot, FheUint32::encrypt_trivial(0u32));
        *slot = f(old);
    }

    pub struct TfheBackend {
        server_key_path: Option<PathBuf>,
        cache: Mutex<Option<CachedKey>>,
    }

    impl TfheBackend {
        pub fn new(server_key_path: Option<PathBuf>) -> Self {
            Self {
                server_key_path,
                cache: Mutex::new(None),
            }
        }

        /// Load (and cache) the decompressed server key, or refuse without key material.
        ///
        /// The file holds a `safe_serialize`d `CompressedServerKey` provisioned out of band
        /// by the key ceremony. Without it the node cannot compute on network ciphertexts,
        /// and inventing a key would produce digests nobody reproduces — so this is an
        /// error, not a fallback.
        fn server_key(&self) -> Result<ServerKey> {
            let path = self
                .server_key_path
                .as_ref()
                .ok_or(Error::Fhe(FheError::NoKeyShare))?;
            let bad = |e: std::io::Error| {
                Error::Fhe(FheError::Backend(format!(
                    "tfhe backend: cannot read {}: {e}",
                    path.display()
                )))
            };
            // `bad` is used twice below, so it cannot be moved into `map_err`:
            // the borrow is load-bearing, and clippy's suggestion does not apply.
            #[allow(clippy::needless_borrows_for_generic_args)]
            let mtime = std::fs::metadata(path)
                .map_err(&bad)?
                .modified()
                .map_err(&bad)?;
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            let hit = match cache.as_ref() {
                Some(cached) if cached.mtime == mtime => Some(cached.key.clone()),
                _ => None,
            };
            if let Some(key) = hit {
                return Ok(key);
            }
            let bytes = std::fs::read(path).map_err(bad)?;
            let compressed: CompressedServerKey =
                safe_deserialize(bytes.as_slice(), DESERIALIZE_LIMIT).map_err(|e| {
                    Error::Fhe(FheError::Backend(format!(
                        "tfhe backend: {} is not a compressed server key: {e}",
                        path.display()
                    )))
                })?;
            let key = compressed.decompress();
            cache.replace(CachedKey {
                mtime,
                key: key.clone(),
            });
            Ok(key)
        }

        /// Decode one framed envelope (`shroud/tfhe/v1` or `shroud/tfhe-weights/v1`).
        fn decode_envelope(
            bytes: &[u8],
            magic: &[u8],
            what: &str,
            expected_features: u32,
        ) -> Result<Vec<FheUint32>> {
            let malformed = |offset: usize, reason: String| {
                Error::ShardStore(ShardError::Malformed { offset, reason })
            };
            if bytes.len() < magic.len() + 8 {
                return Err(malformed(0, format!("{what} is shorter than the header")));
            }
            if &bytes[..magic.len()] != magic {
                return Err(malformed(0, format!("bad {what} magic")));
            }
            let r32 = |o: usize| -> Result<u32, Error> {
                let bytes4: [u8; 4] = bytes
                    .get(o..o + 4)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .ok_or_else(|| malformed(o, format!("{what} truncated at offset {o}")))?;
                Ok(u32::from_le_bytes(bytes4))
            };
            let features = r32(magic.len())?;
            let rows = r32(magic.len() + 4)?;
            if features != expected_features {
                return Err(Error::Fhe(FheError::ShapeMismatch {
                    got_rows: rows as usize,
                    got_cols: features as usize,
                    want_rows: rows as usize,
                    want_cols: expected_features as usize,
                }));
            }
            let mut pos = magic.len() + 8;
            let total = (rows as usize)
                .checked_mul(features as usize)
                .ok_or_else(|| malformed(pos, "lane count overflows the address space".into()))?;
            // Grown frame by frame, never pre-allocated from the header claim: a
            // hostile rows×features would otherwise turn into a giant allocation
            // before the first length check runs.
            let mut out = Vec::new();
            for _ in 0..total {
                if pos + 4 > bytes.len() {
                    return Err(malformed(pos, "truncated ciphertext length".into()));
                }
                let len = r32(pos)? as usize;
                pos += 4;
                if pos + len > bytes.len() {
                    return Err(malformed(pos, "truncated ciphertext bytes".into()));
                }
                let ct: FheUint32 = safe_deserialize(&bytes[pos..pos + len], DESERIALIZE_LIMIT)
                    .map_err(|e| malformed(pos, format!("ciphertext fails to deserialise: {e}")))?;
                pos += len;
                out.push(ct);
            }
            if pos != bytes.len() {
                return Err(malformed(
                    pos,
                    "trailing bytes after the last ciphertext".into(),
                ));
            }
            let _ = rows;
            Ok(out)
        }

        /// Frame ciphertexts into an envelope for the content-addressed store.
        ///
        /// The header is `features` then `rows`, exactly what `decode_envelope` reads back, and
        /// the frames that follow are `rows * features` of them. The weights are one row of
        /// `features` lanes, so the row count is `envelope_rows`.
        fn encode_envelope(magic: &[u8], features: u32, lanes: &[FheUint32]) -> Result<Vec<u8>> {
            let mut frames = Vec::with_capacity(lanes.len());
            for ct in lanes {
                let mut frame = Vec::new();
                tfhe::safe_serialization::safe_serialize(ct, &mut frame, DESERIALIZE_LIMIT)
                    .map_err(|e| {
                        Error::Fhe(FheError::Backend(format!(
                            "tfhe backend: ciphertext fails to serialise: {e}"
                        )))
                    })?;
                frames.push(frame);
            }
            Ok(encode_frames(
                magic,
                features,
                envelope_rows(lanes.len(), features),
                &frames,
            ))
        }
    }

    impl super::FheEngine for TfheBackend {
        fn name(&self) -> &'static str {
            "tfhe-u32"
        }

        fn execute_epoch(&self, inputs: &EpochInputs) -> Result<EpochOutput> {
            let f = inputs.features as usize;
            if f < 2 {
                return Err(Error::Fhe(FheError::ShapeMismatch {
                    got_rows: 0,
                    got_cols: f,
                    want_rows: 0,
                    want_cols: 2,
                }));
            }
            if !inputs.scale.is_power_of_two() {
                return Err(Error::Fhe(FheError::Backend(format!(
                    "tfhe backend: fhe.scale ({}) must be a power of two: \
                     the update scales by public shifts",
                    inputs.scale
                ))));
            }
            let log_scale = inputs.scale.trailing_zeros();
            let key = self.server_key()?;
            tfhe::set_server_key(key);
            let step = derive_step(inputs.lr_q16, inputs.scale, inputs.minibatch)?;
            let step_ct = FheUint32::encrypt_trivial(step);
            // Quantised unit input for the bias lane (see the reference engine: the bias
            // gradient lives in the S² domain like every other lane).
            let unit_ct = FheUint32::encrypt_trivial(inputs.scale);
            let l2_ct = if inputs.l2_q16 == 0 {
                None
            } else {
                Some(FheUint32::encrypt_trivial(derive_l2(inputs.l2_q16)?))
            };

            // Previous encrypted weights are required: there is no genesis path, because
            // inventing weights would fork the digest. The worker refuses a zero
            // `last_weights_cid` before the engine runs.
            let prev = Self::decode_envelope(
                &inputs.prev_weights_bytes,
                TFHE_WEIGHTS_MAGIC,
                "tfhe weights",
                inputs.features,
            )?;
            if prev.len() != f {
                return Err(Error::Fhe(FheError::ShapeMismatch {
                    got_rows: 0,
                    got_cols: prev.len(),
                    want_rows: 0,
                    want_cols: f,
                }));
            }
            let mut w = prev;

            let mut leaves: Vec<&super::ShardInput> = inputs.shards.iter().collect();
            leaves.sort_by_key(|s| s.leaf_index);
            let mut n_rows: u64 = 0;
            // Gradient accumulators over one minibatch, then applied and cleared.
            // Built lane by lane: `FheUint32` is not assumed `Clone`.
            let mut grad: Vec<FheUint32> =
                (0..f).map(|_| FheUint32::encrypt_trivial(0u32)).collect();
            let mut in_batch: u64 = 0;
            for leaf in leaves {
                let lanes = Self::decode_envelope(
                    &leaf.bytes,
                    TFHE_SHARD_MAGIC,
                    "tfhe shard",
                    inputs.features,
                )?;
                if lanes.len() % f != 0 {
                    return Err(Error::Fhe(FheError::ShapeMismatch {
                        got_rows: lanes.len(),
                        got_cols: 1,
                        want_rows: lanes.len() / f * f,
                        want_cols: f,
                    }));
                }
                for r in 0..lanes.len() / f {
                    let base = r * f;
                    // predict = Σ w·x >> log2(S) + bias (reference form, as in the
                    // upstream shift tests: `&ct >> clear`).
                    let mut dot = FheUint32::encrypt_trivial(0u32);
                    for j in 0..f - 1 {
                        let prod = &w[j] * &lanes[base + j];
                        dot = &dot + &prod;
                    }
                    let shifted = &dot >> log_scale;
                    let pred = &shifted + &w[f - 1];
                    let err = &pred - &lanes[base + f - 1];
                    for j in 0..f - 1 {
                        let g = &err * &lanes[base + j];
                        update_ct(&mut grad[j], |acc| &acc + &g);
                    }
                    let gb = &err * &unit_ct;
                    update_ct(&mut grad[f - 1], |acc| &acc + &gb);
                    in_batch += 1;
                    n_rows += 1;
                    if in_batch as usize >= inputs.minibatch {
                        for j in 0..f {
                            let scaled = &grad[j] * &step_ct;
                            let delta = &scaled >> STEP_SHIFT;
                            update_ct(&mut w[j], |w| &w - &delta);
                            grad[j] = FheUint32::encrypt_trivial(0u32);
                        }
                        in_batch = 0;
                    }
                }
            }
            if n_rows == 0 {
                return Err(Error::Fhe(FheError::ShapeMismatch {
                    got_rows: 0,
                    got_cols: f,
                    want_rows: 1,
                    want_cols: f,
                }));
            }
            if in_batch > 0 {
                // M2: tail uses its actual size. Reference `apply_update` divides by
                // `in_batch`; reusing `step_ct` (derived for full `minibatch`) made every
                // incomplete last batch diverge reference<->tfhe.
                let tail_step = derive_step(inputs.lr_q16, inputs.scale, in_batch as usize)?;
                let tail_ct = FheUint32::encrypt_trivial(tail_step);
                for j in 0..f {
                    let scaled = &grad[j] * &tail_ct;
                    let delta = &scaled >> STEP_SHIFT;
                    update_ct(&mut w[j], |w| &w - &delta);
                }
            }
            if let Some(l2) = l2_ct {
                for lane in w.iter_mut() {
                    let scaled = &*lane * &l2;
                    let shrink = &scaled >> STEP_SHIFT;
                    update_ct(lane, |w| &w - &shrink);
                }
            }

            // One row of `features` lanes: the decoder reads `rows` and then expects
            // `rows * features` frames.
            let weights_bytes = Self::encode_envelope(TFHE_WEIGHTS_MAGIC, inputs.features, &w)?;
            // Ciphertext bytes are randomised by PBS: the digest pins this run's outputs.
            // See the module docs for why cross-node byte equality does not hold here.
            let weights_digest = keccak256(&weights_bytes);
            let metrics_bytes = super::metrics_bytes(
                "tfhe-u32",
                inputs.epoch,
                n_rows,
                inputs.features,
                inputs.scale,
                None,
            );
            let digest = super::trace_digest(inputs, n_rows, None, weights_digest);
            Ok(EpochOutput {
                weights: Weights {
                    features: inputs.features,
                    lanes: Vec::new(),
                },
                weights_digest,
                trace_digest: digest,
                weights_bytes,
                metrics_bytes,
                loss_mean_q: None,
                rows: n_rows,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::{TFHE_SHARD_MAGIC, TFHE_WEIGHTS_MAGIC};
        use crate::error::{Error, FheError};

        #[test]
        fn key_loading_refuses_without_material() {
            let backend = super::TfheBackend::new(None);
            assert!(matches!(
                backend.server_key(),
                Err(Error::Fhe(FheError::NoKeyShare))
            ));
        }

        #[test]
        fn envelopes_reject_garbage() {
            assert!(
                super::TfheBackend::decode_envelope(&[1, 2, 3], TFHE_SHARD_MAGIC, "x", 2).is_err()
            );
            let mut bad = Vec::from(TFHE_SHARD_MAGIC);
            bad.extend_from_slice(&[3u32.to_le_bytes(), 1u32.to_le_bytes()].concat());
            assert!(super::TfheBackend::decode_envelope(&bad, TFHE_SHARD_MAGIC, "x", 2).is_err());
        }

        #[test]
        fn hostile_lane_counts_are_errors_never_panics() {
            // u32::MAX rows: the claimed total is gigabytes of frames the payload does
            // not contain. Decoding must fail fast on truncation — never pre-allocate
            // from the header claim and never loop past the bytes.
            let mut bad = Vec::from(TFHE_SHARD_MAGIC);
            bad.extend_from_slice(&2u32.to_le_bytes());
            bad.extend_from_slice(&u32::MAX.to_le_bytes());
            assert!(super::TfheBackend::decode_envelope(&bad, TFHE_SHARD_MAGIC, "x", 2).is_err());
        }

        #[test]
        fn the_decoder_reads_exactly_rows_times_features_frames() {
            // The other half of the same contract, from the decoder's side: with
            // `features = 2` and `rows = 1` it must look for two frames. If it looked for
            // a different number it would stop at the end of the buffer and report a
            // truncation - which is the failure mode the weights envelope had.
            let mut env = Vec::from(TFHE_WEIGHTS_MAGIC);
            env.extend_from_slice(&2u32.to_le_bytes()); // features
            env.extend_from_slice(&1u32.to_le_bytes()); // rows
            for _ in 0..2 {
                env.extend_from_slice(&4u32.to_le_bytes());
                env.extend_from_slice(&[0u8; 4]);
            }
            // `FheUint32` is not `Debug`, so the error is unwrapped by hand rather than
            // through `expect_err`.
            let err = match super::TfheBackend::decode_envelope(&env, TFHE_WEIGHTS_MAGIC, "x", 2) {
                Ok(_) => panic!("a frame of zeroes is not a ciphertext"),
                Err(e) => e,
            };
            let reason = match err {
                Error::ShardStore(crate::error::ShardError::Malformed { reason, .. }) => reason,
                other => panic!("expected a malformed envelope, got {other:?}"),
            };
            assert!(
                reason.contains("fails to deserialise"),
                "the decoder must read both frames and fail on their content, got: {reason}"
            );
        }
    }
}

/// Pick the engine `fhe.backend` names. Infallible construction: a backend that cannot run
/// (missing key, missing feature) fails at execution time with a loud error, never at
/// startup — the node must stay up as a watchdog and payment agent even when it cannot
/// compute.
pub fn select_engine(fhe: &FheConfig) -> Arc<dyn FheEngine> {
    use crate::config::FheBackend;
    match fhe.backend {
        FheBackend::Reference => Arc::new(ReferenceCpuEngine::new(
            fhe.scale,
            fhe.lr_q16,
            fhe.l2_q16,
            fhe.minibatch,
        )),
        #[cfg(feature = "prover")]
        FheBackend::TfheShortInteger | FheBackend::TfheConcrete => {
            Arc::new(tfhe_backend::TfheBackend::new(fhe.server_key_path.clone()))
        }
        #[cfg(not(feature = "prover"))]
        FheBackend::TfheShortInteger | FheBackend::TfheConcrete => Arc::new(ProverMissingEngine),
        FheBackend::Accelerator => Arc::new(UnsupportedEngine {
            what: "accelerator (cuFHE/HPU) backend",
        }),
    }
}

/// Backend selected but not compiled in: refuse loudly at execution time.
#[cfg(not(feature = "prover"))]
struct ProverMissingEngine;

#[cfg(not(feature = "prover"))]
impl FheEngine for ProverMissingEngine {
    fn name(&self) -> &'static str {
        "prover-missing"
    }

    fn execute_epoch(&self, _inputs: &EpochInputs) -> Result<EpochOutput> {
        Err(Error::Fhe(FheError::Backend(
            "fhe.backend names a tfhe backend but this binary was built without the \
             `prover` feature; rebuild with --features prover or set fhe.backend = \"reference\""
                .into(),
        )))
    }
}

/// Backend with no implementation behind it: refuse loudly, never silently substitute.
struct UnsupportedEngine {
    what: &'static str,
}

impl FheEngine for UnsupportedEngine {
    fn name(&self) -> &'static str {
        "unsupported"
    }

    fn execute_epoch(&self, _inputs: &EpochInputs) -> Result<EpochOutput> {
        Err(Error::Fhe(FheError::Backend(format!(
            "the {} has no implementation in this build",
            self.what
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Explicit (not via the glob above): the top level no longer imports these —
    // every value-use lives in tests, so they live here. Mirrors tfhe_backend.
    use alloy::primitives::keccak256;
    use shroud_core::fixed::quantize;

    #[test]
    fn step_derivation_is_exact_for_sane_hyperparameters() {
        // lr=1, S=2^14, m=8: STEP = round(2^16·2^32/(2^16·2^14·8)) = 2^48/2^33 = 32768.
        assert_eq!(derive_step(65_536, 16_384, 8).unwrap(), 32_768);
    }

    #[test]
    fn step_derivation_rejects_unrepresentable_rates() {
        assert!(derive_step(u32::MAX, 1, 1).is_err());
        assert!(derive_step(65_536, 0, 8).is_err());
    }

    #[test]
    fn the_weights_envelope_header_matches_the_frames_it_carries() {
        // The bug this guards: the encoder wrote the *lane* count where the decoder reads
        // a *row* count, and then wrote one frame per lane while the decoder expected
        // `rows * features` of them. Every tfhe epoch therefore failed to load its own
        // previous weights ("truncated ciphertext length"): the backend could never start,
        // never commit and never dispute.
        //
        // The weights are one row of `features` lanes, so the header must say one row -
        // and the frame count the decoder will expect has to be the frame count that is
        // actually there.
        let features = 3u32;
        let frames = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let rows = envelope_rows(frames.len(), features);
        assert_eq!(rows, 1, "three lanes of three features are one row");

        let bytes = encode_frames(TFHE_WEIGHTS_MAGIC, features, rows, &frames);
        let at = TFHE_WEIGHTS_MAGIC.len();
        let read_features = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let read_rows = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
        assert_eq!(read_features, features);
        assert_eq!(read_rows, rows);
        assert_eq!(
            read_rows as usize * features as usize,
            frames.len(),
            "the decoder reads `rows` and then expects `rows * features` frames"
        );
    }

    #[test]
    fn the_l2_step_is_the_reference_engines_rule() {
        // The reference engine shrinks by `l2_q16 * w / 2^16` (see
        // `shroud-core/src/sgd.rs`). The tfhe backend must shrink by the same amount, so
        // the step is `l2_q16 * 2^32 / 2^16` and carries neither the quantisation scale
        // nor the minibatch: those belong to the gradient step. Deriving it from
        // `derive_step` divided by the scale as well, which made the regularisation
        // 10 000 times weaker than configured at the default scale.
        // The step is `l2_q16 * 2^16`, and it has to fit the u32 lane: `l2_q16 = 2^16`
        // would need 2^32 and is refused rather than wrapped.
        assert_eq!(derive_l2(65).unwrap(), 65 << 16);
        assert!(derive_l2(65_536).is_err());
        // The reference rule for a concrete lane: `w -= l2_q16 * w / 2^16`.
        let l2_q16 = 65u32;
        let w = 1_000_000i64;
        let reference = (l2_q16 as i64 * w) / 65_536;
        let step = derive_l2(l2_q16).unwrap() as i64;
        let tfhe = (w * step) >> 32;
        assert_eq!(
            tfhe, reference,
            "both backends must shrink by the same amount"
        );
    }

    /// Build a `shroud/noop/v1` payload exactly like the SDK's `NoopEncryptor`.
    fn noop_bytes(features: u32, rows: &[f64]) -> Vec<u8> {
        let n = (rows.len() / features as usize) as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(NOOP_SHARD_MAGIC);
        buf.extend_from_slice(format!("{features}\0{n}\0").as_bytes());
        for v in rows {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        buf
    }

    fn shard_input(bytes: Vec<u8>) -> ShardInput {
        let digest = keccak256(&bytes);
        ShardInput {
            leaf_index: 0,
            cid: B256::repeat_byte(0xdd),
            ct_digest: digest,
            bytes,
        }
    }

    fn inputs_for(rows: &[f64], prev: Weights) -> EpochInputs {
        EpochInputs {
            task_id: U256::from(7),
            epoch: 0,
            chain_id: 31_337,
            cipher_task: Address::repeat_byte(0xcc),
            ct_root: B256::repeat_byte(0xaa),
            prev_weights_digest: B256::repeat_byte(0xbb),
            features: 2,
            scale: 10_000,
            lr_q16: 65_536,
            l2_q16: 0,
            minibatch: 8,
            seed: 42,
            prev_weights: Some(prev),
            prev_weights_bytes: Vec::new(),
            shards: vec![shard_input(noop_bytes(2, rows))],
        }
    }

    #[test]
    fn noop_shard_decoding_matches_the_sdk_layout() {
        let bytes = noop_bytes(2, &[1.5, 2.25, 0.0, 4.0]);
        let shard = decode_noop_shard(&bytes, 2, 10_000).expect("decodes");
        assert_eq!(shard.features, 2);
        assert_eq!(shard.rows, 2);
        assert_eq!(shard.values, vec![15_000u64, 22_500, 0, 40_000]);
    }

    #[test]
    fn noop_shard_rejects_foreign_magic_and_tells_which() {
        let mut tfhe_like = Vec::new();
        tfhe_like.extend_from_slice(TFHE_SHARD_MAGIC);
        tfhe_like.extend_from_slice(&[0u8; 16]);
        let err = decode_noop_shard(&tfhe_like, 2, 10_000)
            .map_err(Error::from)
            .expect_err("must refuse");
        assert!(matches!(err, Error::Fhe(FheError::Backend(_))), "{err:?}");
    }

    #[test]
    fn noop_shard_rejects_garbage_and_truncation() {
        assert!(decode_noop_shard(&[1, 2, 3], 2, 10_000).is_err());
        let mut bytes = noop_bytes(2, &[1.0, 2.0]);
        bytes.pop();
        assert!(decode_noop_shard(&bytes, 2, 10_000).is_err());
        bytes = noop_bytes(3, &[1.0, 2.0, 3.0]);
        assert!(matches!(
            decode_noop_shard(&bytes, 2, 10_000).map_err(Error::from),
            Err(Error::Fhe(FheError::ShapeMismatch { .. }))
        ));
    }

    #[test]
    fn quantize_rejects_what_tfhe_cannot_hold() {
        assert_eq!(quantize(1.5, 10_000, 0).unwrap(), 15_000);
        assert!(quantize(-1.0, 10_000, 0).is_err());
        assert!(quantize(f64::NAN, 10_000, 0).is_err());
        assert!(quantize(f64::INFINITY, 10_000, 0).is_err());
        assert!(quantize(1e20, 10_000, 0).is_err());
    }

    #[test]
    fn one_gradient_step_is_exact() {
        // Hand-computed: S=10000, lr=1, l2=0, w=[0,0], row x=2.0 y=3.0.
        // pred = 0, err = -30000. Δcoef = -6e8/1e4 = -60000 → 60000;
        // Δbias = -30000/1e4 = -3 → 30000.
        let engine = ReferenceCpuEngine::new(10_000, 65_536, 0, 8);
        let prev = Weights::zeros(2).unwrap();
        let out = engine
            .execute_epoch(&inputs_for(&[2.0, 3.0], prev))
            .expect("executes");
        assert_eq!(out.weights.lanes, vec![60_000u32, 30_000u32]);
        assert_eq!(out.rows, 1);
        assert_eq!(out.loss_mean_q, Some(900_000_000));
    }

    #[test]
    fn execution_is_deterministic_and_sensitive() {
        let engine = ReferenceCpuEngine::new(10_000, 65_536, 65, 8);
        let prev = Weights::zeros(2).unwrap();
        let a = engine
            .execute_epoch(&inputs_for(&[2.0, 3.0, 1.0, 1.0], prev.clone()))
            .expect("executes");
        let b = engine
            .execute_epoch(&inputs_for(&[2.0, 3.0, 1.0, 1.0], prev.clone()))
            .expect("executes");
        assert_eq!(a.trace_digest, b.trace_digest);
        assert_eq!(a.weights_digest, b.weights_digest);
        let c = engine
            .execute_epoch(&inputs_for(&[2.0, 3.0, 1.0, 2.0], prev))
            .expect("executes");
        assert_ne!(a.trace_digest, c.trace_digest);
        assert_ne!(a.weights_digest, c.weights_digest);
    }

    #[test]
    fn second_epoch_feeds_on_the_first() {
        let engine = ReferenceCpuEngine::new(10_000, 65_536, 0, 8);
        let first = engine
            .execute_epoch(&inputs_for(&[2.0, 3.0], Weights::zeros(2).unwrap()))
            .expect("first epoch");
        let round_tripped = Weights::decode(&first.weights_bytes, 2).expect("weights file decodes");
        assert_eq!(round_tripped, first.weights);
        assert_eq!(first.weights_digest, B256::from(round_tripped.digest()));
        let mut second_inputs = inputs_for(&[2.0, 3.0], round_tripped);
        second_inputs.epoch = 1;
        second_inputs.prev_weights_digest = first.weights_digest;
        let second = engine.execute_epoch(&second_inputs).expect("second epoch");
        assert_ne!(second.weights.lanes, first.weights.lanes);
        assert_ne!(second.trace_digest, first.trace_digest);
    }

    #[test]
    fn empty_and_degenerate_inputs_are_refused() {
        let engine = ReferenceCpuEngine::new(10_000, 65_536, 0, 8);
        let mut no_shards = inputs_for(&[2.0, 3.0], Weights::zeros(2).unwrap());
        no_shards.shards.clear();
        assert!(engine.execute_epoch(&no_shards).is_err());
        let mut no_weights = inputs_for(&[2.0, 3.0], Weights::zeros(2).unwrap());
        no_weights.prev_weights = None;
        assert!(engine.execute_epoch(&no_weights).is_err());
        assert!(Weights::zeros(1).is_err());
    }

    #[test]
    fn divergence_is_an_error_not_a_commit() {
        let engine = ReferenceCpuEngine::new(10_000, 65_536, 0, 8);
        // A label astronomically far from a zero prediction: the loss explodes.
        let out = engine.execute_epoch(&inputs_for(&[1.0, 1e9], Weights::zeros(2).unwrap()));
        assert!(matches!(out, Err(Error::Fhe(FheError::Diverged { .. }))));
    }

    #[test]
    fn hostile_headers_are_errors_never_panics() {
        // rows × features overflows the address space: without checked arithmetic this panics
        // in debug builds (and wraps in release). Either way it must come back as Err.
        // The header is decimal ASCII, NUL-separated: "features\0rows\0". Written with \x00
        // rather than \0 on purpose — "\04294967295" is the octal escape 0o42 (a quote), not
        // a NUL followed by "42", and the wrong byte makes the decoder fail one step earlier
        // than the overflow this test is about.
        let mut bytes = Vec::from(NOOP_SHARD_MAGIC);
        bytes.extend_from_slice(b"4294967295\x0042994967295\x00");
        assert!(decode_noop_shard(&bytes, 4294967295, 10_000).is_err());
        // Same shape, wrong features: a shape error, still not a panic.
        assert!(decode_noop_shard(&bytes, 2, 10_000).is_err());
    }

    #[test]
    fn proof_reference_carries_the_star_prefix_and_binds_the_trace() {
        let t = B256::repeat_byte(0x42);
        let proof = proof_reference(t);
        assert_eq!(&proof.as_slice()[..4], &PROOF_REF_PREFIX);
        assert_ne!(proof_reference(B256::repeat_byte(0x43)), proof);
        assert_ne!(proof, B256::ZERO);
    }

    #[test]
    fn weights_files_round_trip_and_reject_mismatch() {
        let w = Weights {
            features: 3,
            lanes: vec![1, 2, 0xffff_ffff],
        };
        let bytes = w.encode();
        assert_eq!(Weights::decode(&bytes, 3).unwrap(), w);
        assert!(Weights::decode(&bytes, 2).is_err());
        let mut cut = bytes.clone();
        cut.pop();
        assert!(Weights::decode(&cut, 3).is_err());
    }

    #[test]
    fn engine_selection_follows_the_config() {
        use crate::config::{Config, FheBackend};
        let mut cfg = Config::default();
        cfg.fhe.backend = FheBackend::Reference;
        assert_eq!(select_engine(&cfg.fhe).name(), "reference-cpu");
        cfg.fhe.backend = FheBackend::Accelerator;
        assert!(select_engine(&cfg.fhe)
            .execute_epoch(&inputs_for(&[2.0, 3.0], Weights::zeros(2).unwrap()))
            .is_err());
    }

    /// The site lab (`web/`) must compute the same digests as this engine.
    ///
    /// `web/tests/vectors.json` pins golden pipeline outputs; this test and the
    /// site's `node web/tests/equiv.mjs` check both pin the same file, so drift
    /// on either side fails its own CI job. See the vectors file header for how
    /// the goldens were cross-validated (ethers keccak256, built `@shroud/sdk`,
    /// this exact layout).
    #[test]
    fn site_vectors_pin_the_digest_layout() {
        use std::str::FromStr;

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct VectorFile {
            pipelines: Vec<Pipeline>,
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Pipeline {
            name: String,
            features: u32,
            rows: Vec<Vec<f64>>,
            scale: u32,
            lr_q16: u32,
            l2_q16: u32,
            minibatch: usize,
            seed: u64,
            expect: Expect,
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Expect {
            bytes: usize,
            commit: String,
            /// The on-chain pin: `keccak256(payload)`.
            ct_digest: String,
            /// The transport address the contributor submitted (`sha256(payload)`).
            transport_cid: String,
            /// The chain's `ctRoot` after this contribution:
            /// `keccak256(_EMPTY_ROOT || u32be(leafIndex) || ciphertextCid)`.
            ct_root: String,
            lanes: Vec<i32>,
            loss_mean_q: String,
            n_rows: u64,
            weights_digest: String,
            trace_digest: String,
            proof_ref: String,
        }

        let raw = include_str!("../../web/tests/vectors.json");
        let vectors: VectorFile = serde_json::from_str(raw).expect("vectors.json parses");
        assert!(!vectors.pipelines.is_empty(), "no golden pipelines pinned");

        for p in &vectors.pipelines {
            let flat: Vec<f64> = p.rows.iter().flatten().copied().collect();
            // Shard bytes exactly like the SDK's `NoopEncryptor`, then the on-chain pin
            // (`keccak256` of the payload) and the row commitment.
            let bytes = noop_bytes(p.features, &flat);
            assert_eq!(bytes.len(), p.expect.bytes, "{}: shard length", p.name);
            assert_eq!(
                format!("{:#x}", keccak256(&bytes)),
                p.expect.ct_digest,
                "{}: shard ctDigest (the on-chain pin)",
                p.name
            );
            let mut preimage = b"shroud/noop-row/v1\0".to_vec();
            for v in &flat {
                preimage.extend_from_slice(&v.to_le_bytes());
            }
            assert_eq!(
                format!("{:#x}", keccak256(&preimage)),
                p.expect.commit,
                "{}: row commitment",
                p.name
            );

            // Full epoch through the real engine, same pins as the golden.
            let inputs = EpochInputs {
                task_id: U256::from_be_slice(keccak256(b"demo-task-1").as_slice()),
                epoch: 0,
                chain_id: 31_337,
                cipher_task: Address::from_str("0x5FbDB2315678afecb367f032d93F642f64180aa3")
                    .expect("cipher task parses"),
                ct_root: B256::from_str(&p.expect.ct_root).expect("ct root parses"),
                prev_weights_digest: B256::ZERO,
                features: p.features,
                scale: p.scale,
                lr_q16: p.lr_q16,
                l2_q16: p.l2_q16,
                minibatch: p.minibatch,
                seed: p.seed,
                prev_weights: Some(Weights::zeros(p.features).expect("genesis zeros")),
                prev_weights_bytes: Vec::new(),
                shards: vec![ShardInput {
                    leaf_index: 0,
                    // The leaf the node builds from the chain's contribution record: the
                    // transport address the contributor submitted, and the on-chain pin.
                    cid: B256::from_str(&p.expect.transport_cid).expect("transport cid parses"),
                    ct_digest: B256::from_str(&p.expect.ct_digest).expect("ct digest parses"),
                    bytes,
                }],
            };
            let engine = ReferenceCpuEngine::new(p.scale, p.lr_q16, p.l2_q16, p.minibatch);
            let out = engine
                .execute_epoch(&inputs)
                .expect("golden epoch executes");
            let lanes: Vec<i32> = out.weights.lanes.iter().map(|w| *w as i32).collect();
            assert_eq!(lanes, p.expect.lanes, "{}: lanes", p.name);
            assert_eq!(
                out.loss_mean_q,
                Some(p.expect.loss_mean_q.parse::<i128>().expect("loss parses")),
                "{}: loss",
                p.name
            );
            assert_eq!(out.rows, p.expect.n_rows, "{}: rows", p.name);
            assert_eq!(
                format!("{:#x}", out.weights_digest),
                p.expect.weights_digest,
                "{}: weights digest",
                p.name
            );
            assert_eq!(
                format!("{:#x}", out.trace_digest),
                p.expect.trace_digest,
                "{}: trace digest",
                p.name
            );
            assert_eq!(
                format!("{:#x}", proof_reference(out.trace_digest)),
                p.expect.proof_ref,
                "{}: proof reference",
                p.name
            );
        }
    }

    /// Regenerate `web/tests/vectors.json` from this engine (`DUMP_VECTORS=1`).
    ///
    /// The goldens are computed, not hand-written: this replays the exact construction
    /// in `site_vectors_pin_the_digest_layout` (same shard bytes, same `EpochInputs`
    /// shape, `ct_root` pinned to the freshly computed CID exactly like the pin test)
    /// and writes the `expect` blocks back. Key order and indentation are normalized
    /// by the serializer, so review value changes and ignore layout on first use.
    /// Without `DUMP_VECTORS=1` this test does nothing.
    #[test]
    fn dump_site_vectors_when_requested() {
        if std::env::var("DUMP_VECTORS").as_deref() != Ok("1") {
            return;
        }
        use std::str::FromStr;

        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../web/tests/vectors.json");
        let raw = std::fs::read_to_string(&path).expect("web/tests/vectors.json must exist");
        let mut doc: serde_json::Value = serde_json::from_str(&raw).expect("vectors.json parses");
        let pipelines = doc
            .get_mut("pipelines")
            .and_then(|p| p.as_array_mut())
            .expect("pipelines array");
        for p in pipelines.iter_mut() {
            let name = p
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("?")
                .to_string();
            let features = p
                .get("features")
                .and_then(|f| f.as_u64())
                .expect("features") as u32;
            let rows: Vec<Vec<f64>> =
                serde_json::from_value(p.get("rows").cloned().expect("rows")).expect("rows decode");
            let scale = p.get("scale").and_then(|s| s.as_u64()).expect("scale") as u32;
            let lr_q16 = p.get("lr_q16").and_then(|l| l.as_u64()).expect("lr_q16") as u32;
            let l2_q16 = p.get("l2_q16").and_then(|l| l.as_u64()).expect("l2_q16") as u32;
            let minibatch = p
                .get("minibatch")
                .and_then(|m| m.as_u64())
                .expect("minibatch") as usize;
            let seed = p.get("seed").and_then(|s| s.as_u64()).expect("seed");
            let flat: Vec<f64> = rows.iter().flatten().copied().collect();
            let bytes = noop_bytes(features, &flat);
            let cid = keccak256(&bytes);
            let mut preimage = b"shroud/noop-row/v1\0".to_vec();
            for v in &flat {
                preimage.extend_from_slice(&v.to_le_bytes());
            }
            let commit = keccak256(&preimage);
            let inputs = EpochInputs {
                task_id: U256::from_be_slice(keccak256(b"demo-task-1").as_slice()),
                epoch: 0,
                chain_id: 31_337,
                cipher_task: Address::from_str("0x5FbDB2315678afecb367f032d93F642f64180aa3")
                    .expect("cipher task parses"),
                ct_root: cid,
                prev_weights_digest: B256::ZERO,
                features,
                scale,
                lr_q16,
                l2_q16,
                minibatch,
                seed,
                prev_weights: Some(Weights::zeros(features).expect("genesis zeros")),
                prev_weights_bytes: Vec::new(),
                shards: vec![ShardInput {
                    leaf_index: 0,
                    cid,
                    ct_digest: commit,
                    bytes: bytes.clone(),
                }],
            };
            let engine = ReferenceCpuEngine::new(scale, lr_q16, l2_q16, minibatch);
            let out = engine
                .execute_epoch(&inputs)
                .expect("golden epoch executes");
            let lanes: Vec<i32> = out.weights.lanes.iter().map(|w| *w as i32).collect();
            let loss = out.loss_mean_q.expect("epoch reports loss").to_string();
            let expect = p.get_mut("expect").expect("expect block");
            expect["bytes"] = serde_json::json!(bytes.len());
            expect["commit"] = serde_json::json!(format!("{commit:#x}"));
            expect["cid"] = serde_json::json!(format!("{cid:#x}"));
            expect["lanes"] = serde_json::json!(lanes);
            expect["lossMeanQ"] = serde_json::json!(loss);
            expect["nRows"] = serde_json::json!(out.rows);
            expect["weightsDigest"] = serde_json::json!(format!("{:#x}", out.weights_digest));
            expect["traceDigest"] = serde_json::json!(format!("{:#x}", out.trace_digest));
            expect["proofRef"] =
                serde_json::json!(format!("{:#x}", proof_reference(out.trace_digest)));
            eprintln!("dumped golden pipeline {name}");
        }
        let formatted = serde_json::to_string_pretty(&doc).expect("serialize vectors") + "\n";
        std::fs::write(&path, formatted).expect("write web/tests/vectors.json");
    }
}
