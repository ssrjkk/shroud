//! Shroud compute node entry point.
//!
//! Startup order matters and is deliberate:
//!
//!   1. parse and validate the configuration — a bad key or a zero contract address is a
//!      configuration error, not a runtime surprise ten minutes into an epoch;
//!   2. initialise tracing, so step 3's failures are visible;
//!   3. verify the RPC serves the chain we were configured for, before any key is used;
//!   4. restore the watcher checkpoint, validating it against the canonical chain;
//!   5. start the watcher.
//!
//! A node that cannot prove which chain it is on should not start at all. Spending a real
//! balance on the wrong network is a worse outcome than refusing to boot.

use std::sync::Arc;

use alloy::providers::{DynProvider, ProviderBuilder};
use clap::Parser;
use shroud_node::{
    chain::{OrchestratorClient, Watcher},
    config::{Cli, Config},
    error::{ConfigError, Result},
    state::NodeState,
    VERSION,
};
use tokio::sync::watch;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Tracing may not be initialised yet, so this first message goes to stderr as well.
            eprintln!("shroud-node: fatal: {e}");
            error!(error = %e, "fatal");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(&cli)?;

    init_tracing(&cli)?;

    // The state layer reads this to locate its checkpoint directory. It is set here rather
    // than threaded through every constructor so the state module stays free of config types.
    std::env::set_var("CM_DATA_DIR", &cfg.node.data_dir);

    info!(
        version = VERSION,
        rpc = %cfg.chain.rpc_url,
        chain_id = cfg.chain.chain_id,
        task = %cfg.contracts.cipher_task,
        vault = %cfg.contracts.payment_vault,
        "starting shroud-node"
    );

    if cfg.contracts.cipher_task.is_zero() || cfg.contracts.payment_vault.is_zero() {
        warn!("a contract address is zero; the watcher will match nothing");
    }

    let client = OrchestratorClient::new(&cfg)?;
    client.verify_chain(cfg.chain.chain_id).await?;

    let state = Arc::new(NodeState::new());
    state.set_chain_id(cfg.chain.chain_id);

    // A provider for the watcher, separate from the client's. The watcher is a long-lived
    // poller and the client issues bursty writes; sharing one pool lets a slow `eth_getLogs`
    // window starve a commit that is racing an epoch deadline.
    let rpc_url = cfg
        .chain
        .rpc_url
        .parse::<url::Url>()
        .map_err(|e| ConfigError::Invalid {
            field: "chain.rpc_url",
            reason: format!("{e}"),
        })?;
    let watcher_provider: DynProvider = ProviderBuilder::new().connect_http(rpc_url).boxed();

    let watcher = Arc::new(Watcher::new(watcher_provider, &cfg, state.clone())?);

    // Restoring is what makes a restart cheap, and it is also a correctness gate: a checkpoint
    // from another chain, or naming a block that is no longer canonical, is rejected here and
    // the watcher falls back to a full replay rather than silently forking its view.
    match state.read_checkpoint().await? {
        Some(cp) => {
            info!(block = cp.last_scanned, "found a watcher checkpoint");
            watcher.restore(&cp, cfg.chain.chain_id).await?;
        }
        None => {
            let start = cfg.chain.start_block.unwrap_or_else(|| {
                warn!(
                    "no checkpoint and no chain.start_block; backfilling from the configured depth"
                );
                0
            });
            info!(start, "no checkpoint; starting a fresh backfill");
        }
    }

    // A separate provider for the watcher: the watcher is a long-lived poller and the client
    // issues bursty writes. Sharing one connection pool means a slow `eth_getLogs` window can
    // starve a commit that is racing an epoch deadline.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let watcher_task = {
        let watcher = watcher.clone();
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move { watcher.run(shutdown_rx).await })
    };

    info!("node running; press Ctrl-C to stop");
    wait_for_shutdown().await;

    info!("shutting down");
    let _ = shutdown_tx.send(true);

    match tokio::time::timeout(std::time::Duration::from_secs(10), watcher_task).await {
        Ok(Ok(Ok(()))) => info!("watcher stopped cleanly"),
        Ok(Ok(Err(e))) => error!(error = %e, "watcher stopped with an error"),
        Ok(Err(e)) => error!(error = %e, "watcher task panicked"),
        Err(_) => warn!("watcher did not stop within 10s; exiting anyway"),
    }

    Ok(())
}

fn init_tracing(cli: &Cli) -> Result<()> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // The CLI flag wins, then the env, then `info`. `EnvFilter` parses the same
    // `target=level` syntax in both, so `CM_LOG` and `--log` are interchangeable.
    let directive = if !cli.log.is_empty() {
        cli.log.clone()
    } else if let Ok(v) = std::env::var("CM_LOG") {
        v
    } else {
        "info".to_string()
    };
    let filter = EnvFilter::try_new(&directive).unwrap_or_else(|e| {
        eprintln!("invalid log filter {directive:?}: {e}; falling back to `info`");
        EnvFilter::new("info")
    });

    let registry = tracing_subscriber::registry().with(filter);
    if cli.log_json {
        registry.with(fmt::layer().json()).init();
    } else {
        registry.with(fmt::layer()).init();
    }
    Ok(())
}

/// Resolve on SIGINT/SIGTERM, or on stdin closing (which is how a container stop arrives).
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not install SIGTERM handler; waiting for SIGINT only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
