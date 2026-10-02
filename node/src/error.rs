//! Error types for the Shroud compute node.
//!
//! One enum, because every fallible operation in an epoch must be attributable to a stage
//! when it fails: a node that cannot say *which* step of a 41-second FHE epoch broke is
//! operationally useless.

use thiserror::Error;

/// Top-level error type.
#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration: {0}")]
    Config(#[from] ConfigError),

    #[error("chain rpc: {0}")]
    Chain(String),

    #[error("alloy: {0}")]
    Alloy(String),

    #[error("contract call {method} reverted: {reason}")]
    ContractCall {
        method: &'static str,
        reason: String,
    },

    #[error("fhe engine: {0}")]
    Fhe(#[from] FheError),

    #[error("stark proving: {0}")]
    Stark(#[from] StarkError),

    #[error("shard store: {0}")]
    ShardStore(#[from] ShardError),

    #[error("peer mesh: {0}")]
    Mesh(#[from] MeshError),

    #[error("payment: {0}")]
    Payment(#[from] PaymentError),

    #[error("identity: {0}")]
    Identity(#[from] IdentityError),

    #[error("epoch {epoch} of task {task_id:#x}: {source}")]
    Epoch {
        task_id: alloy::primitives::B256,
        epoch: u32,
        #[source]
        source: Box<Error>,
    },

    #[error("the network public key on chain ({on_chain:#x}) does not match the local params ({local:#x}); refusing to start")]
    KeyPinMismatch {
        on_chain: alloy::primitives::B256,
        local: alloy::primitives::B256,
    },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required field `{0}`")]
    Missing(&'static str),
    #[error("`{field}` is invalid: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("could not load config: {0}")]
    Load(String),
}

#[derive(Debug, Error)]
pub enum FheError {
    #[error("noise budget exhausted at ciphertext {index} ({remaining} safe bits left); a rekey or a fresh epoch state is required")]
    NoiseBudgetExhausted { index: usize, remaining: u32 },

    #[error("shape mismatch: weight matrix is {got_rows}x{got_cols}, dataset is {want_rows}x{want_cols}")]
    ShapeMismatch {
        got_rows: usize,
        got_cols: usize,
        want_rows: usize,
        want_cols: usize,
    },

    #[error("no key material: the node has no share of the network secret key and cannot decrypt buyer weights")]
    NoKeyShare,

    #[error("tfhe backend failure: {0}")]
    Backend(String),

    #[error("value out of range for a u32 lane: {0}")]
    LaneOverflow(u64),

    #[error("gradient diverged: |loss| = {loss} exceeds the divergence cap after {epoch} epochs")]
    Diverged { epoch: u32, loss: f64 },
}

#[derive(Debug, Error)]
pub enum StarkError {
    #[error("trace does not match the public inputs: {0}")]
    PublicInputMismatch(String),

    #[error("trace length {got} is not a power of two >= {min}")]
    TraceLength { got: usize, min: usize },

    #[error("merkle path for shard leaf {leaf_index} does not reach ctRoot {expected:#x} (got {got:#x})")]
    BadMerklePath {
        leaf_index: u32,
        expected: alloy::primitives::B256,
        got: alloy::primitives::B256,
    },

    #[error("shards consumed out of order: expected leaf {expected}, saw {got}")]
    ShardOutOfOrder { expected: u32, got: u32 },

    #[error("proving took {secs}s, over the {limit}s budget for this epoch")]
    ProveTimeout { secs: u64, limit: u64 },

    #[error("proof is {len} bytes, over the {max} byte calldata limit; use segmented proving")]
    ProofTooLarge { len: usize, max: usize },

    #[error("winterfell: {0}")]
    Backend(String),
}

#[derive(Debug, Error)]
pub enum ShardError {
    #[error("digest mismatch: expected {expected:#x}, computed {got:#x} after {len} bytes")]
    DigestMismatch {
        expected: alloy::primitives::B256,
        got: alloy::primitives::B256,
        len: u64,
    },

    #[error("object {cid:#x} is {size} bytes, over the {max} byte pull budget")]
    TooLarge {
        cid: alloy::primitives::B256,
        size: u64,
        max: u64,
    },

    #[error("range {offset}..{end} is outside object of {size} bytes")]
    RangeOutOfBounds { offset: u64, end: u64, size: u64 },

    #[error("transport AEAD authentication failed for {cid:#x}")]
    AeadFailed { cid: alloy::primitives::B256 },

    #[error("ciphertext parse failed at byte {offset}: {reason}")]
    Malformed { offset: usize, reason: String },

    #[error("shard {cid:#x} for task {task_id:#x} was never announced by any peer and is not in the DA layer")]
    Unavailable {
        task_id: alloy::primitives::B256,
        cid: alloy::primitives::B256,
    },
}

#[derive(Debug, Error)]
pub enum MeshError {
    #[error("peer {peer} is unreachable: {source}")]
    Unreachable {
        peer: String,
        #[source]
        source: tonic::transport::Error,
    },

    #[error("peer {peer} rejected {request}: {reason}")]
    Rejected {
        peer: String,
        request: &'static str,
        reason: String,
    },

    #[error("no peer holds {cid:#x} after querying {queried} nodes")]
    NotFound {
        cid: alloy::primitives::B256,
        queried: usize,
    },

    #[error("peer {peer} spoke an incompatible protocol: {reason}")]
    Incompatible { peer: String, reason: String },

    #[error("gossip: {0}")]
    Gossip(String),
}

#[derive(Debug, Error)]
pub enum PaymentError {
    #[error("no reward channel for task {task_id:#x} epoch {epoch}")]
    NoChannel {
        task_id: alloy::primitives::B256,
        epoch: u32,
    },

    #[error("operator key {address} has no funds to pay the gas for {purpose}")]
    NoGas {
        address: alloy::primitives::Address,
        purpose: &'static str,
    },

    #[error("slice {index} was already redeemed (consumed = {consumed})")]
    SliceReplayed { index: u64, consumed: u64 },

    #[error("refusing to claim {claim} from channel {channel_id:#x} for task {task_id:#x}: the channel only authorises {authorised}")]
    OverAuthorised {
        task_id: alloy::primitives::B256,
        channel_id: alloy::primitives::U256,
        claim: u128,
        authorised: u128,
    },

    #[error("on-chain redeem reverted: {reason}")]
    Reverted { reason: String },
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("this node is not registered for task {task_id:#x}")]
    NotRegistered { task_id: alloy::primitives::B256 },

    #[error("BLS public key does not match the node id derived from the operator address")]
    KeyMismatch,

    #[error("the operator address in the config does not match the signing key")]
    OperatorMismatch {
        configured: alloy::primitives::Address,
        derived: alloy::primitives::Address,
    },
}

impl From<alloy::providers::RpcError<alloy::transports::TransportErrorKind>> for Error {
    fn from(e: alloy::providers::RpcError<alloy::transports::TransportErrorKind>) -> Self {
        Error::Alloy(e.to_string())
    }
}

impl From<alloy::contract::Error> for Error {
    fn from(e: alloy::contract::Error) -> Self {
        Error::Alloy(e.to_string())
    }
}

impl From<alloy::transport::TransportErrorKind> for Error {
    fn from(e: alloy::transport::TransportErrorKind) -> Self {
        Error::Alloy(e.to_string())
    }
}
