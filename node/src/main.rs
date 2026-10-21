//! Shroud compute node entry point.
//!
//! Startup order matters and is deliberate:
//!
//!   1. parse and validate the configuration — a bad key or a zero contract address is a
//!      configuration error, not a runtime surprise ten minutes into an epoch;
//!   2. initialise tracing, so every step below is visible when it fails;
//!   3. verify the RPC serves the chain we were configured for, before any key is used;
//!   4. verify the local FHE params against the pinned on-chain key, because a stale key produces
//!      work that only fails after the task is sealed;
//!   5. restore the watcher checkpoint, validating it against the canonical chain;
//!   6. start the watcher, the work loop, and the peer mesh on one shutdown signal.
//!
//! A node that cannot prove which chain it is on should not start at all. Spending a real balance
//! on the wrong network is a worse outcome than refusing to boot.

use std::{sync::Arc, time::Duration};

use clap::Parser;
use shroud_node::{
    chain::{OrchestratorClient, Watcher},
    config::{Cli, Config},
    error::Result,
    state::NodeState,
    worker::Worker,
    VERSION,
};
use tokio::{sync::watch, task::JoinHandle};
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

    // Register the RPC endpoint before the configuration is even loaded: a
    // configuration error quotes the offending value, and the offending value may
    // be the endpoint with the provider's key in it. The flag and the environment
    // are the two sources that can be known this early; the effective endpoint
    // replaces them below.
    if let Some(url) = cli.rpc_url.as_deref() {
        shroud_node::redact::set_rpc_secret(url);
    } else {
        // The flag's own environment variable, and the nested config key's.
        for name in ["CM_RPC_URL", "CM_CHAIN__RPC_URL"] {
            if let Ok(url) = std::env::var(name) {
                if !url.is_empty() {
                    shroud_node::redact::set_rpc_secret(&url);
                    break;
                }
            }
        }
    }

    let cfg = Config::load(&cli)?;

    init_tracing(&cli)?;

    // The effective endpoint, now that the configuration is known.
    shroud_node::redact::set_rpc_secret(&cfg.chain.rpc_url);

    // The state layer reads this to locate its checkpoint directory. It is set here rather
    // than threaded through every constructor so the state module stays free of config types.
    std::env::set_var("CM_DATA_DIR", &cfg.node.data_dir);

    info!(
        version = VERSION,
        rpc = %shroud_node::redact::redact_rpc_url(&cfg.chain.rpc_url),
        chain_id = cfg.chain.chain_id,
        task = %cfg.contracts.cipher_task,
        vault = %cfg.contracts.payment_vault,
        "starting shroud-node"
    );

    if cfg.contracts.cipher_task.is_zero() || cfg.contracts.payment_vault.is_zero() {
        warn!("a contract address is zero; the watcher will match nothing");
    }

    let client = Arc::new(OrchestratorClient::new(&cfg)?);
    client.verify_chain(cfg.chain.chain_id).await?;
    client.verify_key_pin(&cfg).await?;

    let state = Arc::new(NodeState::new());
    state.set_chain_id(cfg.chain.chain_id);
    // The fold only emits payment work once it knows which address the operator controls; without
    // this the node watches, and never redeems.
    state.set_operator(client.operator());

    // The watcher builds its own provider. That is a rule rather than a convenience: the watcher is
    // a long-lived poller and the client issues bursty writes, so sharing one pool lets a slow
    // `eth_getLogs` window starve a commit that is racing an epoch deadline.
    let watcher = Arc::new(Watcher::new(&cfg, state.clone())?);

    // Hydrating the derived fold is what makes a restart cheap, and restoring the cursor is a
    // correctness gate: a checkpoint from another chain, or naming a block that is no longer
    // canonical, is rejected and the watcher falls back to a full replay rather than silently
    // forking its view. The cursor is only resumed when a snapshot came with it - otherwise the
    // fold would rebuild with every pre-checkpoint task missing, and the node would neither
    // redeem, finalize nor reclaim until the chain moved on its own.
    if state.restore_snapshot(&cfg.node.data_dir).await? {
        info!("hydrated the derived fold from a snapshot");
        if let Some(cp) = state.last_checkpoint() {
            info!(
                block = cp.last_scanned,
                "resuming the watcher at the snapshot's checkpoint"
            );
            watcher.restore(&cp, cfg.chain.chain_id).await?;
        }
    } else {
        info!(
            backfill = cfg.chain.backfill_blocks,
            start_block = ?cfg.chain.start_block,
            "no usable snapshot; the watcher derives its own start and rebuilds the fold"
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let watcher_task = {
        let watcher = watcher.clone();
        let shutdown = shutdown_rx.clone();
        tokio::spawn(async move { watcher.run(shutdown).await })
    };
    let worker_task = {
        let worker = Arc::new(Worker::new(cfg.clone(), client.clone(), state.clone()));
        let shutdown = shutdown_rx.clone();
        tokio::spawn(async move { worker.run(shutdown).await })
    };
    // Snapshots on a timer, so the next restart can skip the backfill. Best-effort by design: a
    // failed write only costs the next restart its shortcut - the fold still rebuilds from the
    // chain, which is exactly the fallback the startup path above takes.
    //
    // Spawned before the mesh task on purpose: the mesh block's `async move` closure takes
    // `cfg` and `state` with it, so anything needing either has to be set up first.
    let snapshot_task = {
        let state = state.clone();
        let dir = cfg.node.data_dir.clone();
        let mut shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            const EVERY: Duration = Duration::from_secs(30);
            let mut tick = tokio::time::interval(EVERY);
            // The first tick fires immediately; at that point the fold has nothing in it that
            // is worth a file write, so burn it before entering the loop.
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        if let Err(e) = state.snapshot(&dir).await {
                            warn!(error = %e, "could not write the derived snapshot");
                        }
                    }
                    _ = shutdown.changed() => return Ok(()),
                }
            }
        })
    };

    // A node built without `grpc-server` is a pure chain follower: it still executes every write
    // arm, it just cannot be asked for shards by anybody.
    #[cfg(feature = "grpc-server")]
    let mesh_task: Option<JoinHandle<Result<()>>> = {
        let shutdown = shutdown_rx.clone();
        Some(tokio::spawn(async move {
            shroud_node::mesh::server::serve(cfg.clone(), state.clone(), shutdown).await
        }))
    };
    #[cfg(not(feature = "grpc-server"))]
    let mesh_task: Option<JoinHandle<Result<()>>> = None;

    info!("node running; press Ctrl-C to stop");
    wait_for_shutdown().await;

    info!("shutting down");
    let _ = shutdown_tx.send(true);

    finish("watcher", watcher_task).await;
    finish("worker", worker_task).await;
    finish("snapshot", snapshot_task).await;
    if let Some(task) = mesh_task {
        finish("mesh", task).await;
    }

    Ok(())
}

/// Report how one background task exited, with a bounded wait.
///
/// A stuck task must not hang the process after a container stop: the deadline is what turns
/// "shutdown is slow" into a log line the operator can act on.
async fn finish(name: &'static str, task: JoinHandle<Result<()>>) {
    const GRACE: Duration = Duration::from_secs(10);
    match tokio::time::timeout(GRACE, task).await {
        Ok(Ok(Ok(()))) => info!(stage = name, "stopped cleanly"),
        Ok(Ok(Err(e))) => error!(stage = name, error = %e, "stopped with an error"),
        Ok(Err(e)) => error!(stage = name, error = %e, "task panicked"),
        Err(_) => warn!(
            stage = name,
            "did not stop within the grace period; exiting anyway"
        ),
    }
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
