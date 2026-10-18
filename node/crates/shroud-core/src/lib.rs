//! Shroud's portable compute core.
//!
//! Everything in here is a pure function of its arguments: no network, no chain
//! reads, no clock, no randomness, no filesystem. That is the whole point — the
//! same code must run in three places and agree byte-for-byte:
//!
//! * the operator node (`node/src/fhe.rs`, `node/src/chain/transcript.rs`), which
//!   wraps these primitives with chain types and error mapping;
//! * a zkVM guest (SP1 / RISC Zero), which cannot link tokio, alloy or reqwest;
//! * a wasm32 browser build of the lab, which cannot do any of that either.
//!
//! Determinism contract: integer division truncates toward zero, float use is
//! limited to input quantisation and the divergence check (both live here so the
//! rounding is pinned in one place), and every accumulator is checked `i128` —
//! anything that does not fit is an error, never a wrap, because two provers must
//! compute the same digest and wrapping would make that depend on build details.
//!
//! The ONLY external dependency is `sha3` for Keccak-256. In particular there is
//! no `alloy` (addresses/hashes are plain `[u8; N]` here), no `serde`, no async.

pub mod error;
pub mod fixed;
pub mod hash;
pub mod sgd;
pub mod shard;
pub mod transcript;
pub mod weights;

/// Re-exported at the crate root: the one type every consumer matches on.
pub use error::{CoreError, Result};
