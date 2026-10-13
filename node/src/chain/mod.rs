//! Chain access.
//!
//! | module | responsibility |
//! |--------|----------------|
//! | [`watcher`] | log ingestion, the finality cursor, reorg detection; the only fold driver |
//! | [`client`] | transactions and point reads; knows nothing about reorgs |
//! | [`bindings`] | the Solidity ABI and event topics the node depends on |
//! | [`slice`] | the 96-byte ERC-1271 `redeem` blob encoding |
//! | [`transcript`] | the `ctRoot` chain and proof-of-compute public input, byte for byte |
//!
//! Nothing constructs a provider outside this module. That is a rule, not a convention: the
//! node's correctness argument depends on there being a single, auditable place where logs
//! enter the process. [`read_provider`] is the read-only half; [`OrchestratorClient`] owns the
//! only key-bearing provider in the node.

pub mod bindings;
pub mod client;
pub mod slice;
pub mod transcript;
pub mod watcher;

use alloy::providers::{DynProvider, ProviderBuilder};

use crate::{
    config::Config,
    error::{ConfigError, Result},
};

pub use client::OrchestratorClient;
pub use watcher::{ChainEvent, Checkpoint, Watcher};

/// Parse `chain.rpc_url`. Shared so both providers report the same field name on a typo.
pub(crate) fn parse_rpc_url(src: &str) -> std::result::Result<url::Url, ConfigError> {
    src.parse::<url::Url>().map_err(|e| ConfigError::Invalid {
        field: "chain.rpc_url",
        reason: format!("{e}"),
    })
}

/// A keyless provider, for log reads.
pub(crate) fn read_provider(cfg: &Config) -> Result<DynProvider> {
    Ok(ProviderBuilder::new()
        .connect_http(parse_rpc_url(&cfg.chain.rpc_url)?)
        .erased())
}
