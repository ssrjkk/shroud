//! Node configuration.
//!
//! Resolution order (later wins): built-in defaults -> `shroud.toml` -> environment
//! variables. Every value is also settable with a `--flag`, so a container image can run as a
//! sequencer-attached worker, a dispute re-executor, or a prover by changing flags alone.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use alloy::primitives::{Address, B256};
use clap::Parser;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, Result};

/// Compute node.
#[derive(Debug, Parser, Clone)]
#[command(name = "shroud-node", version, about, long_about = None)]
pub struct Cli {
    /// Path to the TOML config. Env vars (`CM_` prefix) override whatever it contains.
    #[arg(long, env = "CM_CONFIG", default_value = "shroud.toml")]
    pub config: PathBuf,

    /// Override the chain RPC endpoint.
    #[arg(long, env = "CM_RPC_URL")]
    pub rpc_url: Option<String>,

    /// Also subscribe to the websocket endpoint for low-latency log delivery.
    #[arg(long, env = "CM_WS_URL")]
    pub ws_url: Option<String>,

    /// Chain id the RPC must serve (checked at startup). Without this flag the
    /// `CM_CHAIN_ID` variable silently had no effect: figment lowercases it to a
    /// top-level `chain_id` key that `Config` ignores, so only TOML `chain.chain_id`
    /// or this flag moves it. The compose devnet sets it, and now it lands.
    #[arg(long, env = "CM_CHAIN_ID")]
    pub chain_id: Option<u64>,

    /// Operator EOA that signs payment slices and pays gas.
    #[arg(long, env = "CM_OPERATOR_KEY")]
    pub operator_key: Option<String>,

    /// The node's BLS public key (32 bytes of hex), which is what `registerNode` stores.
    ///
    /// The secret half never reaches this process: in production it lives in the KMS that signs
    /// committee share updates, and a compute node only ever needs to *present* the public key.
    /// Configuring a private key here would be a way to leak it.
    #[arg(long, env = "CM_BLS_PUB_KEY")]
    pub bls_pub_key: Option<String>,

    /// Address of the CipherTask orchestrator.
    #[arg(long, env = "CM_TASK_ADDRESS")]
    pub task_address: Option<Address>,

    /// Address of the PaymentVault.
    #[arg(long, env = "CM_VAULT_ADDRESS")]
    pub vault_address: Option<Address>,

    /// First block of the log backfill. Overrides `chain.backfill_blocks`.
    #[arg(long, env = "CM_START_BLOCK")]
    pub start_block: Option<u64>,

    /// gRPC listen address for the peer mesh.
    #[arg(long, env = "CM_MESH_LISTEN", default_value = "0.0.0.0:7331")]
    pub mesh_listen: SocketAddr,

    /// Comma-separated seed peers.
    #[arg(long, env = "CM_MESH_PEERS", value_delimiter = ',')]
    pub mesh_peers: Vec<String>,

    /// Only watch this task (useful for a dedicated worker fleet).
    #[arg(long, env = "CM_TASK_FILTER")]
    pub task_filter: Option<B256>,

    /// Run as a dispute re-executor: never submit commits, only re-derive digests.
    #[arg(long, env = "CM_DISPUTE_ONLY", default_value_t = false)]
    pub dispute_only: bool,

    /// Log filter, e.g. `info,shroud_node::fhe=debug`.
    #[arg(long, env = "CM_LOG", default_value = "info")]
    pub log: String,

    /// Emit logs as JSON.
    #[arg(long, env = "CM_LOG_JSON", default_value_t = false)]
    pub log_json: bool,
}

/// Fully-resolved runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub chain: ChainConfig,
    pub contracts: ContractsConfig,
    pub node: NodeConfig,
    pub fhe: FheConfig,
    pub stark: StarkConfig,
    pub shard: ShardConfig,
    pub mesh: MeshConfig,
    pub payment: PaymentConfig,
    pub finality: FinalityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub rpc_url: String,
    pub ws_url: Option<String>,
    /// Start block for the initial log backfill. `None` = "look back this many blocks".
    pub start_block: Option<u64>,
    /// How far back to backfill when `start_block` is unset.
    pub backfill_blocks: u64,
    /// Re-poll interval for the finality cursor.
    pub poll_interval: Duration,
    /// Max in-flight `eth_getLogs` windows.
    pub get_logs_window: u64,
    pub get_logs_chunk: u64,
    /// Treat the chain as L2 and use `eth_getBlockByNumber` for L1-inclusion checks.
    pub is_l2: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractsConfig {
    pub cipher_task: Address,
    pub payment_vault: Address,
    pub network_params: Address,
    /// Off-chain STARK verifier service used to pre-check proofs before paying gas for them.
    pub stark_verifier_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub operator_key: String,
    /// `bytes32` handed to `registerNode`, hex-encoded. `None` means the node will refuse to
    /// register for a task, and so can neither commit nor dispute on it.
    pub bls_pub_key: Option<String>,
    /// Skip an epoch if the remaining window is shorter than this.
    pub min_epoch_window: Duration,
    pub data_dir: PathBuf,
    /// Refuse to start unless the on-chain `fhePublicKeyHash` matches the local params.
    pub enforce_key_pin: bool,
    /// Refuse to execute an epoch whose seed weights are not a decodable
    /// `shroud/weights/v1` file, instead of falling back to genesis zeros.
    ///
    /// Off by default: the fallback is a deliberate consensus choice (every node running
    /// this code agrees on zeros and binds the chain pin in the trace, so a node that
    /// understands the buyer's convention can still dispute). Turn it on when the
    /// deployment's buyers always publish SDK-encoded seed files and silent convention
    /// drift must be loud instead of executable.
    pub strict_weights: bool,
    /// Only watch this task. `None` watches everything. Set from `--task-filter`.
    pub task_filter: Option<B256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheConfig {
    pub backend: FheBackend,
    /// `NetworkParams.current.fhePublicKeyHash`, which the contract defines as
    /// `keccak256(abi.encode(s_pub))`.
    ///
    /// Required whenever `node.enforce_key_pin` is set: a pin with nothing to compare against
    /// would be a switch that looks protective and does nothing, which is worse than not having
    /// it, because it would be audited as if it worked.
    pub public_key_hash: Option<B256>,
    /// File holding the `safe_serialize`d `CompressedServerKey` the tfhe backends compute
    /// under. Provisioned out of band by the key ceremony; `None` means the node has no key
    /// material and its tfhe executions fail with `NoKeyShare` (the node keeps watching,
    /// disputing nothing it cannot recompute, and collecting its other duties).
    pub server_key_path: Option<PathBuf>,
    /// u32 message width. Bleve batches 8 lanes per ciphertext.
    pub lanes_per_ciphertext: usize,
    pub scale: u32,
    /// Fixed-point learning rate, Q16.16.
    pub lr_q16: u32,
    /// L2 regularisation, Q16.16.
    pub l2_q16: u32,
    pub minibatch: usize,
    pub max_noise_deficit: u32,
    /// Deterministic seed for shuffling minibatches. Must be a public input.
    pub seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FheBackend {
    /// Deterministic fixed-point SGD over development (`shroud/noop/v1`) shards.
    /// Byte-for-byte reproducible across nodes, which is what the dispute quorum needs.
    /// Refuses any shard it cannot decode — including real encrypted shards — loudly.
    Reference,
    /// `tfhe-rs` short-integer keys. The production CPU path (feature `prover`).
    TfheShortInteger,
    /// `tfhe-rs` Concrete, fully deterministic. Used by tests and by the re-executor so
    /// that a dispute digest is reproducible across builds.
    TfheConcrete,
    /// GPU/CPU cuFHE or HPU. Same semantics, different throughput.
    Accelerator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkConfig {
    /// Max bytes of STARK posted on chain. Over this, use segmented proving.
    pub max_proof_bytes: usize,
    /// Minibatch/shard granularity of a trace segment.
    pub segment_shards: u32,
    /// Winterfell security level in bits: 128 or 192.
    pub security_bits: u32,
    /// Skip proving and only produce the trace digest (re-executor mode).
    pub digest_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConfig {
    /// Content-addressed store root. `file://`, `s3://`, `gs://` or `https://`.
    pub da_endpoint: String,
    /// Per-task ciphertext byte cap, so a task cannot exhaust local disk.
    pub max_ciphertext_bytes: u64,
    /// Bytes pulled per range request.
    pub range_bytes: u64,
    pub cache_dir: PathBuf,
    /// Drop cached objects older than this.
    pub cache_ttl: Duration,
    /// Derive the per-shard AEAD transport key instead of trusting the DA transport.
    ///
    /// NOT IMPLEMENTED: no code in this crate reads this flag, so `true` used to mean
    /// "protected" while nothing was protected. It now fails closed in `validate()`:
    /// transport confidentiality comes from mesh mTLS (`mesh.mtls_*`) and DA-endpoint
    /// TLS, never from this key. Default `false`.
    pub aead_transport: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub listen: SocketAddr,
    pub peers: Vec<String>,
    /// How often to re-announce our own shards.
    pub announce_interval: Duration,
    /// gRPC request deadline.
    pub request_timeout: Duration,
    /// Max shard announcements kept in the local index.
    pub index_capacity: usize,
    /// Inbound mesh requests served per second, per peer IP. `fetch_shard` does disk I/O
    /// and gossip writes grow the shard index, so neither may be unbounded per peer.
    pub inbound_rps: u64,
    /// Burst above the rate a peer may spend at once.
    pub inbound_burst: u64,
    /// Max concurrent streams per h2 connection. Each gossip stream spawns a task plus a
    /// channel, so uncapped streams are task/memory exhaustion by handshake.
    pub max_streams_per_connection: usize,
    pub mtls_cert: Option<PathBuf>,
    pub mtls_key: Option<PathBuf>,
    pub ca_cert: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentConfig {
    /// Redeem the authorised slice as soon as a channel is opened.
    pub auto_redeem: bool,
    /// Gas limit for the redeem transaction.
    pub redeem_gas_limit: u64,
    /// Wait this long after `EpochSettled` before redeeming, to survive short RPC outages.
    pub redeem_delay: Duration,
    /// Max USDC (6 dp) a single node will claim from one task.
    ///
    /// `u64` rather than `u128`: figment implements no `deserialize_u128`, so a `u128` key is
    /// unreadable from a file, the environment, or the defaults layer.
    pub max_claim_per_task: u64,
    /// Refuse to bid for a task whose budget exceeds this, to bound exposure.
    pub max_budget_per_task: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityConfig {
    /// Number of confirmations required before acting on a log.
    pub confirmations: u64,
    /// Reorg depth that triggers a full state rebuild from the last checkpoint.
    pub reorg_threshold: u64,
    /// Persist the watcher cursor every N blocks so a rebuild is bounded.
    pub checkpoint_interval: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain: ChainConfig {
                // `hardhat node` always serves 31337 (the plugin asserts it), so the devnet
                // default matches the chain an operator actually gets from `docker compose up`.
                chain_id: 31_337,
                rpc_url: "http://127.0.0.1:8545".into(),
                ws_url: None,
                start_block: None,
                backfill_blocks: 2_000,
                poll_interval: Duration::from_secs(4),
                get_logs_window: 2_000,
                get_logs_chunk: 500,
                is_l2: true,
            },
            contracts: ContractsConfig {
                cipher_task: Address::ZERO,
                payment_vault: Address::ZERO,
                network_params: Address::ZERO,
                stark_verifier_url: None,
            },
            node: NodeConfig {
                operator_key: String::new(),
                bls_pub_key: None,
                min_epoch_window: Duration::from_secs(300),
                data_dir: PathBuf::from("./data"),
                // Off by default: turning it on without `fhe.public_key_hash` +
                // `contracts.network_params` makes the node refuse to start (see `validate`),
                // and the devnet config sets neither. The SDK-side pin check stays the alert
                // that is on out of the box; this is the opt-in node-side twin.
                enforce_key_pin: false,
                strict_weights: false,
                task_filter: None,
            },
            fhe: FheConfig {
                // Reference first: it runs without key material on development shards, so a
                // fresh node closes the whole loop (register → execute → commit → finalize →
                // settle → redeem) out of the box. Encrypted shards need a tfhe backend plus
                // `fhe.server_key_path`, and the reference engine refuses those loudly rather
                // than training on bytes it cannot read.
                backend: FheBackend::Reference,
                public_key_hash: None,
                server_key_path: None,
                lanes_per_ciphertext: 8,
                scale: 10_000,
                lr_q16: 65_536, // 1.0
                l2_q16: 65,     // 0.001
                minibatch: 8,
                max_noise_deficit: 8,
                seed: 0x4369_7068_6572_4d65, // "CipherMe"
            },
            stark: StarkConfig {
                max_proof_bytes: 48_576,
                segment_shards: 256,
                security_bits: 128,
                digest_only: false,
            },
            shard: ShardConfig {
                da_endpoint: "file://./data/da".into(),
                max_ciphertext_bytes: 8 << 30,
                range_bytes: 4 << 20,
                cache_dir: PathBuf::from("./data/cache"),
                cache_ttl: Duration::from_secs(7 * 86_400),
                aead_transport: false,
            },
            mesh: MeshConfig {
                listen: "0.0.0.0:7331"
                    .parse()
                    .expect("valid default socket address"),
                peers: Vec::new(),
                announce_interval: Duration::from_secs(30),
                request_timeout: Duration::from_secs(20),
                index_capacity: 65_536,
                inbound_rps: 100,
                inbound_burst: 200,
                max_streams_per_connection: 100,
                mtls_cert: None,
                mtls_key: None,
                ca_cert: None,
            },
            payment: PaymentConfig {
                auto_redeem: true,
                redeem_gas_limit: 220_000,
                redeem_delay: Duration::from_secs(20),
                max_claim_per_task: 5_000_000_000,
                max_budget_per_task: 100_000_000_000,
            },
            finality: FinalityConfig {
                confirmations: 2,
                reorg_threshold: 3,
                checkpoint_interval: 100,
            },
        }
    }
}

impl Config {
    /// Merge defaults, the TOML file, the environment and the CLI flags.
    ///
    /// Precedence, lowest to highest: built-in defaults -> `shroud.toml` -> `CM_*`
    /// environment -> `--flags`. The CLI is applied last and *only* for flags the user
    /// actually passed, so a `CM_CHAIN__RPC_URL` set in the environment is not clobbered by a
    /// clap default value. (`Option<T>` fields are "not passed"; the non-optional fields with
    /// `default_value_t` would always look passed, so they are read through
    /// `ArgMatches::value_source` instead — see `cli_overrides`.)
    pub fn load(cli: &Cli) -> Result<Self> {
        let figment = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(&cli.config))
            .merge(Env::prefixed("CM_").split("__"))
            .merge(cli_overrides(cli));

        let cfg: Config = figment
            .extract()
            .map_err(|e| ConfigError::Load(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contracts.cipher_task == Address::ZERO {
            return Err(ConfigError::Missing("contracts.cipher_task").into());
        }
        if self.contracts.payment_vault == Address::ZERO {
            return Err(ConfigError::Missing("contracts.payment_vault").into());
        }
        if self.node.operator_key.is_empty() {
            return Err(ConfigError::Missing("node.operator_key").into());
        }
        if self.fhe.lanes_per_ciphertext == 0 || !self.fhe.lanes_per_ciphertext.is_power_of_two() {
            return Err(ConfigError::Invalid {
                field: "fhe.lanes_per_ciphertext",
                reason: format!(
                    "{} must be a power of two for Bleve batching",
                    self.fhe.lanes_per_ciphertext
                ),
            }
            .into());
        }
        if self.fhe.scale == 0 {
            return Err(ConfigError::Invalid {
                field: "fhe.scale",
                reason: "must be > 0".into(),
            }
            .into());
        }
        if self.fhe.minibatch == 0 {
            return Err(ConfigError::Invalid {
                field: "fhe.minibatch",
                reason: "must be > 0".into(),
            }
            .into());
        }
        if self.fhe.lr_q16 == 0 {
            return Err(ConfigError::Invalid {
                field: "fhe.lr_q16",
                reason: "must be > 0".into(),
            }
            .into());
        }
        if !matches!(self.stark.security_bits, 128 | 192) {
            return Err(ConfigError::Invalid {
                field: "stark.security_bits",
                reason: "only 128 and 192 are supported by winterfell".into(),
            }
            .into());
        }
        if self.stark.segment_shards == 0 || !self.stark.segment_shards.is_power_of_two() {
            return Err(ConfigError::Invalid {
                field: "stark.segment_shards",
                reason: format!("{} must be a power of two", self.stark.segment_shards),
            }
            .into());
        }
        if self.finality.confirmations == 0 {
            return Err(ConfigError::Invalid {
                field: "finality.confirmations",
                reason: "acting on unconfirmed logs is unsafe on a reorg-able L2".into(),
            }
            .into());
        }
        // The three numbers below are divisors, subtrahends and `step_by` arguments in the
        // watcher's scan loop. A zero is not a slow configuration: it is an arithmetic panic (or
        // a wrapped range that never terminates) ten minutes after start-up, so it is a
        // configuration error and belongs here.
        if self.finality.checkpoint_interval == 0 {
            return Err(ConfigError::Invalid {
                field: "finality.checkpoint_interval",
                reason: "must be >= 1; the cursor is written every N blocks".into(),
            }
            .into());
        }
        if self.chain.get_logs_window == 0 {
            return Err(ConfigError::Invalid {
                field: "chain.get_logs_window",
                reason: "must be >= 1 blocks".into(),
            }
            .into());
        }
        if self.chain.get_logs_chunk == 0 {
            return Err(ConfigError::Invalid {
                field: "chain.get_logs_chunk",
                reason: "must be >= 1 blocks".into(),
            }
            .into());
        }
        if self.chain.get_logs_chunk > self.chain.get_logs_window {
            return Err(ConfigError::Invalid {
                field: "chain.get_logs_chunk",
                reason: format!(
                    "{} must not exceed chain.get_logs_window ({})",
                    self.chain.get_logs_chunk, self.chain.get_logs_window
                ),
            }
            .into());
        }
        // A pin that cannot be compared is not a pin. Rejecting it here is the difference between
        // "the operator forgot a field" and "the node ran an epoch under a superseded key".
        if self.node.enforce_key_pin && self.fhe.public_key_hash.is_none() {
            return Err(ConfigError::Missing("fhe.public_key_hash").into());
        }
        if self.node.enforce_key_pin && self.contracts.network_params == Address::ZERO {
            return Err(ConfigError::Missing("contracts.network_params").into());
        }
        // Parse the key at load rather than at the first `registerNode`: a typo in the one value
        // the contract stores as this node's identity should stop the node, not cost gas later.
        if let Some(src) = &self.node.bls_pub_key {
            if parse_bls_pub_key(src).is_none() {
                return Err(ConfigError::Invalid {
                    field: "node.bls_pub_key",
                    reason: "expected 32 bytes of hex, with or without `0x`".into(),
                }
                .into());
            }
        }
        // A peer-facing range of zero would make `fetch_shard` answer with empty chunks forever:
        // the caller's `next_offset` never moves, so it retries until its own deadline. Same class
        // of bug as the divisors above, but it surfaces as a mesh that looks alive and serves
        // nothing.
        if self.shard.range_bytes == 0 {
            return Err(ConfigError::Invalid {
                field: "shard.range_bytes",
                reason: "must be >= 1; it is the chunk size peers are served".into(),
            }
            .into());
        }
        if self.mesh.index_capacity == 0 {
            return Err(ConfigError::Invalid {
                field: "mesh.index_capacity",
                reason: "must be >= 1; at zero the node cannot remember any peer's shard".into(),
            }
            .into());
        }
        if self.mesh.inbound_rps == 0 {
            return Err(ConfigError::Invalid {
                field: "mesh.inbound_rps",
                reason: "must be >= 1; at zero the node serves no peer".into(),
            }
            .into());
        }
        if self.mesh.inbound_burst == 0 {
            return Err(ConfigError::Invalid {
                field: "mesh.inbound_burst",
                reason: "must be >= 1; at zero even one request is over quota".into(),
            }
            .into());
        }
        if self.mesh.max_streams_per_connection == 0 {
            return Err(ConfigError::Invalid {
                field: "mesh.max_streams_per_connection",
                reason: "must be >= 1; at zero no peer can open a stream".into(),
            }
            .into());
        }
        if self.mesh.request_timeout.is_zero() {
            return Err(ConfigError::Invalid {
                field: "mesh.request_timeout",
                reason: "must be > 0; it bounds how long one range read may hold a peer".into(),
            }
            .into());
        }
        // `shard.aead_transport` was accepted and never read: `true` meant "protected"
        // while nothing was protected. Fail closed until a real AEAD transport exists —
        // use mesh mTLS and DA-endpoint TLS instead.
        if self.shard.aead_transport {
            return Err(ConfigError::Invalid {
                field: "shard.aead_transport",
                reason: "not implemented; set false and rely on mesh mTLS + DA TLS".into(),
            }
            .into());
        }
        // Two of three mTLS paths is not a configuration, it is a mistake, and the mistake would
        // show up as a mesh that accepts every caller. Either all three or none.
        let have_cert = self.mesh.mtls_cert.is_some();
        let have_key = self.mesh.mtls_key.is_some();
        let have_ca = self.mesh.ca_cert.is_some();
        if (have_cert || have_key || have_ca) && !(have_cert && have_key && have_ca) {
            return Err(ConfigError::Invalid {
                field: "mesh.mtls_cert",
                reason: "the three mesh TLS paths must be set together".into(),
            }
            .into());
        }
        Ok(())
    }
}

/// Parse the configured BLS public key: 32 bytes of hex, `0x` prefix optional.
///
/// Deliberately lenient about the prefix and strict about everything else, because this value is
/// what `registerNode` records as the node's identity — a silently truncated key would register a
/// node that no committee signature ever validates for.
pub fn parse_bls_pub_key(src: &str) -> Option<B256> {
    let hex_str = src.strip_prefix("0x").unwrap_or(src);
    if hex_str.len() != 64 || !hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).ok()?;
    Some(B256::from(out))
}

/// Turn the CLI into a figment provider.
///
/// `figment::providers::Serialized::from(&cli)` cannot be used directly: `Cli` is a flat struct
/// whose field names (`rpc_url`, `task_address`) do not correspond to the nested `Config` shape
/// (`chain.rpc_url`, `contracts.cipher_task`), so serialising it directly produces keys that
/// `Config::extract` ignores and every flag becomes a no-op. The mapping is therefore spelled
/// out.
///
/// Every field is `Option` + `skip_serializing_if`, so only flags the user actually passed reach
/// figment and the lower-precedence layers (file, env) keep their value. This is why the
/// structs below exist instead of reusing `Cli`: clap's `default_value_t` fields would always
/// look "set" and would clobber the file.
#[derive(Debug, Serialize)]
struct CliOverrides {
    chain: ChainOverride,
    contracts: ContractsOverride,
    node: NodeOverride,
    mesh: MeshOverride,
    stark: StarkOverride,
}

#[derive(Debug, Default, Serialize)]
struct ChainOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    rpc_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ws_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_block: Option<u64>,
}

#[derive(Debug, Default, Serialize)]
struct ContractsOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    cipher_task: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_vault: Option<Address>,
}

#[derive(Debug, Default, Serialize)]
struct NodeOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    operator_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bls_pub_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_filter: Option<B256>,
}

#[derive(Debug, Serialize)]
struct MeshOverride {
    listen: SocketAddr,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    peers: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
struct StarkOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    digest_only: Option<bool>,
}

fn cli_overrides(cli: &Cli) -> figment::providers::Serialized<CliOverrides> {
    // `mesh.listen` and `mesh.peers` are applied unconditionally: a clap default listen
    // address is a legitimate operator choice, not an override of a file value.
    let ov = CliOverrides {
        chain: ChainOverride {
            rpc_url: cli.rpc_url.clone(),
            ws_url: cli.ws_url.clone(),
            chain_id: cli.chain_id,
            start_block: cli.start_block,
        },
        contracts: ContractsOverride {
            cipher_task: cli.task_address,
            payment_vault: cli.vault_address,
        },
        node: NodeOverride {
            operator_key: cli.operator_key.clone(),
            bls_pub_key: cli.bls_pub_key.clone(),
            task_filter: cli.task_filter,
        },
        mesh: MeshOverride {
            listen: cli.mesh_listen,
            peers: cli.mesh_peers.clone(),
        },
        stark: StarkOverride {
            digest_only: cli.dispute_only.then_some(true),
        },
    };
    figment::providers::Serialized::defaults(ov)
}

/// Test-only helper: build a config from TOML text.
#[cfg(test)]
pub fn from_toml_str(src: &str) -> Result<Config> {
    let figment = Figment::from(Serialized::defaults(Config::default())).merge(Toml::string(src));
    let cfg: Config = figment
        .extract()
        .map_err(|e| ConfigError::Load(e.to_string()))?;
    cfg.validate()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    const MINIMAL: &str = r#"
        [contracts]
        cipher_task = "0x1111111111111111111111111111111111111111"
        payment_vault = "0x2222222222222222222222222222222222222222"
        network_params = "0x3333333333333333333333333333333333333333"

        [node]
        operator_key = "0xdeadbeef"

        [fhe]
        public_key_hash = "0x4444444444444444444444444444444444444444444444444444444444444444"
    "#;

    /// A config that passes every check in [`Config::validate`], for tests that only care about
    /// one of them. Built by mutation so a new required field shows up as a compile error here
    /// rather than as twelve unrelated test failures.
    fn base() -> Config {
        let mut cfg = Config::default();
        cfg.contracts.cipher_task = Address::repeat_byte(0x11);
        cfg.contracts.payment_vault = Address::repeat_byte(0x22);
        cfg.contracts.network_params = Address::repeat_byte(0x33);
        cfg.node.operator_key = "0xdeadbeef".into();
        cfg.fhe.public_key_hash = Some(B256::repeat_byte(0x44));
        cfg
    }

    #[test]
    fn defaults_apply_when_the_file_omits_a_section() {
        let cfg = from_toml_str(MINIMAL).expect("valid config");
        assert_eq!(cfg.chain.chain_id, Config::default().chain.chain_id);
        assert_eq!(cfg.fhe.backend, FheBackend::Reference);
        assert_eq!(cfg.finality.confirmations, 2);
    }

    #[test]
    fn the_file_overrides_defaults() {
        let cfg = from_toml_str(
            r#"
            [chain]
            chain_id = 97

            [contracts]
            cipher_task = "0x1111111111111111111111111111111111111111"
            payment_vault = "0x2222222222222222222222222222222222222222"
            network_params = "0x3333333333333333333333333333333333333333"

            [node]
            operator_key = "0xdeadbeef"

            [fhe]
            public_key_hash = "0x4444444444444444444444444444444444444444444444444444444444444444"
            "#,
        )
        .expect("valid config");
        assert_eq!(cfg.chain.chain_id, 97);
    }

    #[test]
    fn zero_contract_addresses_are_rejected() {
        let err = from_toml_str(
            r#"
            [contracts]
            cipher_task = "0x0000000000000000000000000000000000000000"
            payment_vault = "0x2222222222222222222222222222222222222222"
            network_params = "0x3333333333333333333333333333333333333333"

            [node]
            operator_key = "0xdeadbeef"

            [fhe]
            public_key_hash = "0x4444444444444444444444444444444444444444444444444444444444444444"
            "#,
        )
        .expect_err("zero task address must be rejected");
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::Missing("contracts.cipher_task"))
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn a_missing_operator_key_is_rejected() {
        let err = from_toml_str(
            r#"
            [contracts]
            cipher_task = "0x1111111111111111111111111111111111111111"
            payment_vault = "0x2222222222222222222222222222222222222222"
            network_params = "0x3333333333333333333333333333333333333333"

            [fhe]
            public_key_hash = "0x4444444444444444444444444444444444444444444444444444444444444444"
            "#,
        )
        .expect_err("missing operator key must be rejected");
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::Missing("node.operator_key"))
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn an_unimplemented_aead_transport_is_rejected() {
        // `shard.aead_transport` was accepted and never read: `true` meant "protected"
        // while nothing was protected. Fail closed until a real AEAD transport exists.
        let mut cfg = base();
        assert!(
            !cfg.shard.aead_transport,
            "the default must not claim protection"
        );
        cfg.shard.aead_transport = true;
        let err = cfg
            .validate()
            .expect_err("an unimplemented transport flag must be rejected");
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::Invalid {
                    field: "shard.aead_transport",
                    ..
                })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn mesh_throttle_and_stream_caps_reject_zero() {
        // Zero here means "serve no peer" / "admit no stream" — a silent mesh outage
        // that looks like an empty network. Each field fails closed with its own name.
        let mut cfg = base();
        cfg.mesh.inbound_rps = 0;
        assert!(
            matches!(
                cfg.validate(),
                Err(Error::Config(ConfigError::Invalid {
                    field: "mesh.inbound_rps",
                    ..
                }))
            ),
            "zero rps must be rejected"
        );
        let mut cfg = base();
        cfg.mesh.inbound_burst = 0;
        assert!(
            matches!(
                cfg.validate(),
                Err(Error::Config(ConfigError::Invalid {
                    field: "mesh.inbound_burst",
                    ..
                }))
            ),
            "zero burst must be rejected"
        );
        let mut cfg = base();
        cfg.mesh.max_streams_per_connection = 0;
        assert!(
            matches!(
                cfg.validate(),
                Err(Error::Config(ConfigError::Invalid {
                    field: "mesh.max_streams_per_connection",
                    ..
                }))
            ),
            "zero stream cap must be rejected"
        );
    }

    #[test]
    fn lanes_per_ciphertext_must_be_a_power_of_two() {
        let mut cfg = base();
        cfg.fhe.lanes_per_ciphertext = 3;
        let err = cfg
            .validate()
            .expect_err("3 lanes is not a Bleve batch size");
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::Invalid {
                    field: "fhe.lanes_per_ciphertext",
                    ..
                })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn zero_confirmations_are_rejected() {
        let mut cfg = base();
        cfg.finality.confirmations = 0;
        cfg.validate()
            .expect_err("acting on unconfirmed logs must be rejected");
    }

    #[test]
    fn unsupported_security_bits_are_rejected() {
        let mut cfg = base();
        cfg.stark.security_bits = 256;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_zero_watcher_divisor_is_rejected_at_load_not_at_runtime() {
        // Each of these is a `%`, a `- 1`, or a chunk size in `Watcher::scan`. A zero would be an
        // arithmetic panic minutes into a backfill, with an epoch commit in flight.
        let cases: [fn(&mut Config); 4] = [
            |c: &mut Config| c.finality.checkpoint_interval = 0,
            |c: &mut Config| c.chain.get_logs_window = 0,
            |c: &mut Config| c.chain.get_logs_chunk = 0,
            |c: &mut Config| c.chain.get_logs_chunk = c.chain.get_logs_window + 1,
        ];
        for case in cases {
            let mut cfg = base();
            case(&mut cfg);
            let err = cfg.validate().expect_err("zero-sized scan arithmetic");
            assert!(
                matches!(err, Error::Config(ConfigError::Invalid { .. })),
                "got {err:?}"
            );
        }
    }

    #[test]
    fn a_key_pin_needs_something_to_compare_against() {
        let mut cfg = base();
        cfg.node.enforce_key_pin = true;
        cfg.fhe.public_key_hash = None;
        let err = cfg
            .validate()
            .expect_err("enforce_key_pin without a local hash cannot enforce anything");
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::Missing("fhe.public_key_hash"))
            ),
            "got {err:?}"
        );

        // Opting out of the pin is an explicit operator choice, and then the missing hash is
        // allowed.
        cfg.node.enforce_key_pin = false;
        cfg.validate().expect("an un-pinned node may start");

        let mut cfg = base();
        cfg.node.enforce_key_pin = true;
        cfg.contracts.network_params = Address::ZERO;
        assert!(
            matches!(
                cfg.validate().expect_err("the pin has no contract to read"),
                Error::Config(ConfigError::Missing("contracts.network_params"))
            ),
            "the pin needs an address"
        );
    }

    #[test]
    fn cli_task_address_maps_onto_contracts_cipher_task() {
        // The regression this guards: `Serialized::from(&cli)` produced `task_address`, which
        // `Config` ignores, so `--task-address` silently had no effect.
        let cli = Cli {
            config: PathBuf::from("nonexistent.toml"),
            task_address: Some(Address::repeat_byte(0x33)),
            vault_address: Some(Address::repeat_byte(0x44)),
            operator_key: Some("0xabcd".into()),
            ..Cli::parse_from(["shroud-node"])
        };
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(cli_overrides(&cli))
            .extract()
            .expect("extract succeeds");
        assert_eq!(cfg.contracts.cipher_task, Address::repeat_byte(0x33));
        assert_eq!(cfg.contracts.payment_vault, Address::repeat_byte(0x44));
        assert!(!cfg.node.operator_key.is_empty());
    }

    #[test]
    fn unset_cli_options_do_not_shadow_the_toml_file() {
        // The `chain` table is present but empty, which figment merges as a no-op. What
        // matters is that no key inside it can overwrite the file's value.
        let cli = Cli::parse_from(["shroud-node"]);
        let toml = r#"
            [chain]
            rpc_url = "http://from-file:8545"
            [contracts]
            cipher_task = "0x0000000000000000000000000000000000000001"
            payment_vault = "0x0000000000000000000000000000000000000002"
            network_params = "0x0000000000000000000000000000000000000003"
            [node]
            operator_key = "0xdeadbeef"
        "#;
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::string(toml))
            .merge(cli_overrides(&cli))
            .extract()
            .expect("extract succeeds");
        assert_eq!(cfg.chain.rpc_url, "http://from-file:8545");
    }

    #[test]
    fn cli_chain_id_maps_onto_chain_config() {
        // The regression this guards: `CM_CHAIN_ID` reached figment as a top-level
        // `chain_id` key that `Config` ignores, so the variable silently had no effect
        // (the compose devnet sets it). Now the flag carries it to `chain.chain_id`.
        let cli = Cli::parse_from(["shroud-node", "--chain-id", "97"]);
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(cli_overrides(&cli))
            .extract()
            .expect("extract succeeds");
        assert_eq!(cfg.chain.chain_id, 97);

        let plain = Cli::parse_from(["shroud-node"]);
        let kept: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(cli_overrides(&plain))
            .extract()
            .expect("extract succeeds");
        assert_eq!(kept.chain.chain_id, Config::default().chain.chain_id);
    }

    #[test]
    fn dispute_only_maps_onto_stark_digest_only() {
        let cli = Cli::parse_from(["shroud-node", "--dispute-only"]);
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(cli_overrides(&cli))
            .extract()
            .expect("extract succeeds");
        assert!(cfg.stark.digest_only);
    }

    #[test]
    fn bls_pub_key_maps_onto_node_config_and_parses_both_spellings() {
        let cli = Cli::parse_from(["shroud-node", "--bls-pub-key", &"ab".repeat(32)]);
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(cli_overrides(&cli))
            .extract()
            .expect("extract succeeds");
        assert_eq!(
            cfg.node.bls_pub_key.as_deref(),
            Some("ab".repeat(32).as_str()),
            "--bls-pub-key must reach node.bls_pub_key"
        );

        let unprefixed = parse_bls_pub_key(&"ab".repeat(32)).expect("parses");
        let prefixed = parse_bls_pub_key(&format!("0x{}", "ab".repeat(32))).expect("parses");
        assert_eq!(unprefixed, prefixed);
        assert_eq!(unprefixed.0, [0xab; 32]);
    }

    #[test]
    fn a_malformed_bls_pub_key_is_rejected_at_load() {
        for bad in [
            "0xdeadbeef".to_string(),
            "zz".repeat(32),
            String::new(),
            "0x".to_string(),
        ] {
            let mut cfg = base();
            cfg.node.bls_pub_key = Some(bad.clone());
            let err = cfg
                .validate()
                .expect_err(&format!("{bad} is not a 32-byte key"));
            assert!(
                matches!(
                    err,
                    Error::Config(ConfigError::Invalid {
                        field: "node.bls_pub_key",
                        ..
                    })
                ),
                "got {err:?} for {bad:?}"
            );
        }
        // Unset is legal: the node simply refuses to register, which the worker reports.
        let cfg = base();
        assert_eq!(cfg.node.bls_pub_key, None);
        cfg.validate()
            .expect("a node without a BLS key may still start");
    }
}
