# Shroud devnet (`infra/`)

Local single-host devnet: an fhEVM hardhat node with the contracts deployed, a content-addressed
DA (ShardStore), and (optionally) three Rust compute nodes.

```
┌─────────┐   RPC :8545    ┌──────────┐    :8080     ┌────────────┐
│ devnet  │◄──────────────►│ shardstore│◄────────────►│ node a/b/c │
│ (fhEVM) │                │ (DA)     │               │ (Rust)     │
└─────────┘                └──────────┘               └────────────┘
```

## 1. Chain + DA (runnable now)

```sh
docker compose up -d --build devnet shardstore
```

- `devnet` starts a hardhat fhEVM node (the plugin etches the mock coprocessor into the
  standalone node) and deploys the contracts, writing addresses to `infra/devnet/addresses.json`
  (plus the shell-sourcable `addresses.env`).
- `shardstore` serves the content-addressed store the SDK talks to (`PUT /objects`, `GET /objects/:cid`).

The SDK smoke tests cross-check their embedded ABIs against the compiled contracts, so the
contracts must be compiled first: `cd packages/contracts && npm run build`.

## 2. Rust nodes (requires a Rust build - see below)

```sh
docker compose build node-a node-b node-c
docker compose up -d node-a node-b node-c
```

Set `CM_TASK_ADDRESS` / `CM_VAULT_ADDRESS` on the nodes from `addresses.json` before bringing
them up.

## Why the nodes are not built on this host

The Rust node is compiled by Cargo, which must **execute build-script binaries** during a build.
On this workstation Windows Smart App Control / WDAC blocks unsigned Cargo build scripts
(`os error 4551`, event `3033/3077`, policy `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`), so the
node cannot be built here. Build it where that policy does not apply - a developer machine, a
container, or CI (see `.github/workflows/rust.yml`):

```sh
# on a normal Linux/macOS/Windows dev box:
cd node
cargo build --release
```

then `docker build -t shroud-node:dev -f infra/node/Dockerfile .` from the repo root.

## 3. Node configuration

The node reads `shroud.toml` (plus `CM_*` env and CLI flags — see `node/src/config.rs`,
the only authority). The knobs that decide what the node actually *does*:

```toml
[chain]
rpc_url = "http://127.0.0.1:8545"
chain_id = 31337          # verified against the RPC at startup; mismatch refuses to boot.
                          # `--chain-id` / `CM_CHAIN_ID` set the same value (the compose
                          # devnet relies on this) and win over TOML when passed.

[contracts]
cipher_task = "0x..."     # zero address = watcher matches nothing (warns, still runs)
payment_vault = "0x..."
network_params = "0x..."  # only needed with enforce_key_pin

[node]
operator_key = "0x..."    # pays gas, receives rewards; NEVER commit a funded key
bls_pub_key = "0x..."     # per-task registration identity (must be unique per task)
# Durations below use serde's map form, e.g. min_epoch_window = { secs = 300, nanos = 0 }.
# A bare "300s" string does NOT parse, and neither env vars nor CLI flags can set
# durations today (there is no humantime layer and no duration flag): omit them and the
# built-in defaults apply. In particular min_epoch_window defaults to 300 s, so tasks
# with shorter epoch windows than that can never be committed to — plan epochDuration
# accordingly.
min_epoch_window = { secs = 300, nanos = 0 }  # refuse commits with less time left (a
                          # commit that cannot finish before the deadline is burned gas)
enforce_key_pin = false   # opt-in: refuse to start unless fhe.public_key_hash equals
                          # the on-chain pin (one check at boot, not per epoch)

[fhe]
backend = "reference"     # reference | tfhe-short-integer | tfhe-concrete | accelerator
scale = 10000             # fixed-point scale; must match the shards' quantization
lr_q16 = 65536            # learning rate, Q16.16 (65536 = 1.0)
l2_q16 = 65               # L2 shrinkage, Q16.16
minibatch = 8
# server_key_path = "/keys/network.skey"  # REQUIRED for tfhe-* backends: a
                          # safe_serialized CompressedServerKey from the key ceremony.
                          # Without it tfhe executions fail loudly with NoKeyShare while
                          # the node keeps watching, finalizing and redeeming.

[shard]
cache_dir = "./data/cache"      # content-addressed store this node also serves to peers
da_endpoint = "file://./data/da" # file:// = local-dev; s3://, gs://, https:// need
                                # `--features da`, otherwise remote reads refuse loudly
max_ciphertext_bytes = 8589934592

[stark]
digest_only = false       # true = dispute-only watchdog: never join the commit race,
                          # only re-execute, report and collect payment duties
```

Backend choice is a privacy decision, not just a performance one: `reference`
executes over development (`shroud/noop/v1`) shards whose rows are visible — it
refuses anything else rather than training on bytes it cannot read. Point it at real
encrypted shards and every epoch errors out loudly with no gas spent. Encrypted data
needs a `tfhe-*` backend **plus** `server_key_path`, on a binary built with
`--features prover`.
