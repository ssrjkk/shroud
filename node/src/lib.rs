//! Shroud compute node.
//!
//! The node watches a `CipherTask` contract, executes FHE epochs against encrypted shards, and
//! posts a ZK proof of compute. It is written as a library plus a thin binary so the epoch
//! pipeline can be exercised in tests without a chain and without a network.
//!
//! # Module map
//!
//! | module | responsibility |
//! |--------|----------------|
//! | [`config`] | layered configuration (defaults -> file -> env -> flags) and its validation |
//! | [`error`] | one error enum, tagged by pipeline stage |
//! | [`state`] | the fold over chain events; derived, rebuildable, never authoritative |
//! | [`chain::watcher`] | log ingestion, the finality cursor, and reorg detection |
//! | [`chain::client`] | point reads and transactions |
//! | [`chain::bindings`] | hand-checked Solidity ABI and event topics |
//!
//! # The one invariant worth stating up front
//!
//! Everything in [`state`] is a cache of what the chain already says. The contracts are the only
//! authority for what a node is owed, what it has committed, and what it may claim. If the local
//! view and the chain disagree, the chain wins and the node re-syncs. A bug in this crate must
//! never be able to make a node claim a payment or a proof it did not earn.

pub mod chain;
pub mod config;
pub mod error;
pub mod mesh;
pub mod state;

pub use config::Config;
pub use error::{Error, Result};
pub use state::{NodeState, TaskStatus, Work};

/// Node build version, reported in `Hello` so peers can refuse an incompatible one.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol capability tags advertised in `Hello`. A peer that lacks `stark-babybear` must not be
/// asked to re-execute, and one without `tfhe-u32` must not be assigned an epoch.
pub mod capability {
    pub const TFHE_U32: &str = "tfhe-u32";
    pub const STARK_BABYBEAR: &str = "stark-babybear";
    pub const GPU: &str = "gpu";
    pub const RANGE_FETCH: &str = "range-fetch";
}
