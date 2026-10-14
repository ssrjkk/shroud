//! Shroud compute node.
//!
//! The node watches a `CipherTask` contract, keeps a derived view of it, and writes the
//! transactions its own view says are callable. It is written as a library plus a thin binary so
//! the whole decision path can be exercised in tests without a chain and without a network.
//!
//! # Module map
//!
//! | module | responsibility |
//! |--------|----------------|
//! | [`config`] | layered configuration (defaults -> file -> env -> flags) and its validation |
//! | [`error`] | one error enum, tagged by pipeline stage |
//! | [`state`] | the fold over chain events; derived, rebuildable, never authoritative |
//! | [`worker`] | the work loop: gates each nudge against a fresh chain read, then spends the gas |
//! | [`fhe`] | epoch execution engines (reference fixed-point, tfhe-rs) and digest layouts |
//! | [`da`] | content-addressed shard/weights store, local first with remote backends |
//! | [`chain::watcher`] | log ingestion, the finality cursor, and reorg detection |
//! | [`chain::client`] | point reads and transactions |
//! | [`chain::bindings`] | hand-checked Solidity ABI and event topics |
//! | [`chain::slice`] | the 96-byte ERC-1271 `redeem` blob encoding |
//! | [`chain::transcript`] | the `ctRoot` chain and the proof transcript, byte for byte |
//! | `mesh::server` | the peer mesh: gossip handshake, shard index, ranged shard reads (feature `grpc-server`) |
//!
//! # The one invariant worth stating up front
//!
//! Everything in [`state`] is a cache of what the chain already says. The contracts are the only
//! authority for what a node is owed, what it has committed, and what it may claim. If the local
//! view and the chain disagree, the chain wins and the node re-syncs. A bug in this crate must
//! never be able to make a node claim a payment or a proof it did not earn.
//!
//! # What this crate does not contain
//!
//! A zkVM STARK prover: `commitEpoch` carries a 32-byte *proof reference* (see
//! [`fhe::proof_reference`]), which verifies on mock-verifier chains and binds the trace
//! without proving it. Full proving is Phase 3. Everything else on the write path is real:
//! registration, epoch execution and re-execution, dispute filing, finalization,
//! settlement, redemption, reclamation and claiming all move money and status on chain.

pub mod chain;
pub mod config;
pub mod da;
pub mod error;
pub mod fhe;
pub mod mesh;
pub mod state;
pub mod worker;

pub use config::Config;
pub use error::{Error, Result};
pub use state::{NodeState, TaskStatus, Work};

/// Node build version, reported in `Hello` so peers can refuse an incompatible one.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
