//! Chain access.
//!
//! Split in two so the reorg policy has exactly one home:
//!
//! * [`watcher`] — reads logs, owns the cursor and the fork detection. Read-only.
//! * [`client`] — writes transactions and does point reads. Knows nothing about reorgs.
//!
//! Nothing else in the node may construct a provider. That is a rule, not a convention: the
//! node's correctness argument depends on there being a single, auditable place where logs
//! enter the process.

pub mod bindings;
pub mod client;
pub mod watcher;

pub use client::OrchestratorClient;
pub use watcher::{ChainEvent, Checkpoint, Watcher};
