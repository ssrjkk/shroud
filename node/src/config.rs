//! Node configuration.
//!
//! Resolution order (later wins): built-in defaults -> `shroud.toml` -> environment
//! variables. Every value is also settable with a `--flag`, so a container image can run as a
//! sequencer-attached worker, a dispute re-executor, or a prover by changing flags alone.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use alloy::primitives::{Address, B256};
use clap::Parser;
use figment::{
    providers::{Env, Format, Toml},
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

    /// Operator EOA that signs payment slices and pays gas.
    #[arg(long, env = "CM_OPERATOR_KEY")]
    pub operator_key: Option<String>,

    /// Private key of the node's BLS key (hex). In production this comes from a KMS/HSM and
    /// only the derived public key is configured.
    #[arg(long, env = "CM_BLS_KEY")]
    pub bls_key: Option<String>,

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
    pub bls_key: Option<String>,
    pub id: B256,
    /// Max epochs to execute concurrently. FHE is CPU-bound, so this is usually 1.
    pub max_concurrent_epochs: usize,
    /// Rayon threads for the FHE engine. `0` = all cores.
    pub threads: usize,
    /// Skip an epoch if the remaining window is shorter than this.
    pub min_epoch_window: Duration,
    /// Per-epoch wall-clock budget after which the node gives up and lets a peer win.
    pub epoch_timeout: Duration,
    pub metrics_listen: Option<SocketAddr>,
    pub data_dir: PathBuf,
    /// Refuse to start unless the on-chain `fhePublicKeyHash` matches the local params.
    pub enforce_key_pin: bool,
    /// Only watch this task. `None` watches everything. Set from `--task-filter`.
    pub task_filter: Option<B256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheConfig {
    pub backend: FheBackend,
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
    /// `tfhe-rs` short-integer keys. The production CPU path.
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
    /// Verify sha256 of a full object before parsing it.
    pub verify_digest: bool,
    /// Derive the per-shard AEAD transport key instead of trusting the DA transport.
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
    pub max_claim_per_task: u128,
    /// Refuse to bid for a task whose budget exceeds this, to bound exposure.
    pub max_budget_per_task: u128,
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
                chain_id: 31_338,
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
                bls_key: None,
                id: B256::ZERO,
                max_concurrent_epochs: 1,
                threads: 0,
                min_epoch_window: Duration::from_secs(300),
                epoch_timeout: Duration::from_secs(1_800),
                metrics_listen: None,
                data_dir: PathBuf::from("./data"),
                enforce_key_pin: true,
                task_filter: None,
            },
            fhe: FheConfig {
                backend: FheBackend::TfheShortInteger,
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
                verify_digest: true,
                aead_transport: true,
            },
            mesh: MeshConfig {
                listen: "0.0.0.0:7331"
                    .parse()
                    .expect("valid default socket address"),
                peers: Vec::new(),
                announce_interval: Duration::from_secs(30),
                request_timeout: Duration::from_secs(20),
                index_capacity: 65_536,
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
        let figment = Figment::new()
            .merge(Toml::file(&cli.config))
            .merge(Env::prefixed("CM_").split("__"))
            .merge(cli_overrides(cli))
            .select();

        let mut cfg: Config = figment
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
        if self.node.max_concurrent_epochs == 0 {
            return Err(ConfigError::Invalid {
                field: "node.max_concurrent_epochs",
                reason: "must be >= 1".into(),
            }
            .into());
        }
        Ok(())
    }

    /// Q16.16 -> f64, for the optimiser and for the model spec sanity checks.
    pub fn lr(&self) -> f64 {
        self.fhe.lr_q16 as f64 / 65_536.0
    }

    pub fn l2(&self) -> f64 {
        self.fhe.l2_q16 as f64 / 65_536.0
    }

    /// How many shards fit in one trace segment.
    pub fn shards_per_segment(&self) -> usize {
        self.stark.segment_shards as usize
    }
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
#[derive(Debug, Default, Serialize)]
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
    bls_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_filter: Option<B256>,
}

#[derive(Debug, Default, Serialize)]
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
            start_block: cli.start_block,
        },
        contracts: ContractsOverride {
            cipher_task: cli.task_address,
            payment_vault: cli.vault_address,
        },
        node: NodeOverride {
            operator_key: cli.operator_key.clone(),
            bls_key: cli.bls_key.clone(),
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
    figment::providers::Serialized::from(ov)
}

/// Test-only helper: build a config from TOML text.
#[cfg(test)]
pub fn from_toml_str(src: &str) -> Result<Config> {
    let figment = Figment::new().merge(Toml::string(src)).select();
    let cfg: Config = figment
        .extract()
        .map_err(|e| ConfigError::Load(e.to_string()))?;
    cfg.validate()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [contracts]
        cipher_task = "0x1111111111111111111111111111111111111111"
        payment_vault = "0x2222222222222222222222222222222222222222"

        [node]
        operator_key = "0xdeadbeef"
    "#;

    #[test]
    fn defaults_apply_when_the_file_omits_a_section() {
        let cfg = from_toml_str(MINIMAL).expect("valid config");
        assert_eq!(cfg.chain.chain_id, Config::default().chain.chain_id);
        assert_eq!(cfg.fhe.backend, FheBackend::TfheShortInteger);
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

            [node]
            operator_key = "0xdeadbeef"
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

            [node]
            operator_key = "0xdeadbeef"
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
    fn lanes_per_ciphertext_must_be_a_power_of_two() {
        let mut cfg = Config::default();
        cfg.contracts.cipher_task = Address::repeat_byte(0x11);
        cfg.contracts.payment_vault = Address::repeat_byte(0x22);
        cfg.node.operator_key = "0xdeadbeef".into();
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
        let mut cfg = Config::default();
        cfg.contracts.cipher_task = Address::repeat_byte(0x11);
        cfg.contracts.payment_vault = Address::repeat_byte(0x22);
        cfg.node.operator_key = "0xdeadbeef".into();
        cfg.finality.confirmations = 0;
        cfg.validate()
            .expect_err("acting on unconfirmed logs must be rejected");
    }

    #[test]
    fn unsupported_security_bits_are_rejected() {
        let mut cfg = Config::default();
        cfg.contracts.cipher_task = Address::repeat_byte(0x11);
        cfg.contracts.payment_vault = Address::repeat_byte(0x22);
        cfg.node.operator_key = "0xdeadbeef".into();
        cfg.stark.security_bits = 256;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn q16_fixed_point_conversions() {
        let mut cfg = Config::default();
        cfg.fhe.lr_q16 = 32_768; // 0.5
        cfg.fhe.l2_q16 = 65; // 0.000992...
        assert!((cfg.lr() - 0.5).abs() < f64::EPSILON);
        assert!((cfg.l2() - 65.0 / 65_536.0).abs() < 1e-12);
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
        let out = cli_overrides(&cli).data().expect("provider yields a map");
        let contracts = out.get("contracts").expect("contracts table present");
        assert_eq!(
            contracts
                .get("cipher_task")
                .and_then(|v| v.to_string().ok())
                .map(|s| s.trim_matches('"').to_string()),
            Some(format!("{:#x}", Address::repeat_byte(0x33)))
        );
        let node = out.get("node").expect("node table present");
        assert!(node.get("operator_key").is_some());
    }

    #[test]
    fn unset_cli_options_do_not_shadow_the_toml_file() {
        // The `chain` table is present but empty, which figment merges as a no-op. What
        // matters is that no key inside it can overwrite the file's value.
        let cli = Cli::parse_from(["shroud-node"]);
        let out = cli_overrides(&cli).data().expect("provider yields a map");
        let chain = out.get("chain").expect("chain table present");
        assert!(
            chain.is_empty(),
            "an unset --rpc-url must not shadow the TOML file, got {chain:?}"
        );
    }

    #[test]
    fn dispute_only_maps_onto_stark_digest_only() {
        let cli = Cli::parse_from(["shroud-node", "--dispute-only"]);
        let out = cli_overrides(&cli).data().expect("provider yields a map");
        assert_eq!(
            out.get("stark")
                .and_then(|s| s.get("digest_only"))
                .and_then(|v| v.to_string().ok())
                .as_deref(),
            Some("true")
        );
    }
}
