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

### 1a. ShardStore perimeter (`infra/shardstore/guard.mjs`)

The DA is a public HTTP surface, so it runs behind an in-process guard (zero
dependencies, in-memory engines + `StoreAdapter` interface for a future Redis swap):

- hierarchical throttling: global load-shed + per-IP quotas, reads and writes priced
  separately (`429` + `Retry-After`); repeat offenders land in a penalty box with
  exponential backoff `t·2^k` (capped);
- decay risk scoring per IP (auth failures, rate hits, 404-probing, duplicate
  payloads, machine-regular PUT timing): `MEDIUM` → tarpit on violating requests,
  `HIGH` → shadowban — an authorized write gets a plausible `201` with the correct
  cid but is **not stored** (subsequent `GET` → `404`), so the attacker cannot tell
  isolation from success;
- `Idempotency-Key` on PUT (replay returns the first result, parallel duplicates
  collapse into one execution — singleflight), strict input sanitization
  (null-bytes, dot-segments, invisible unicode, single-range only), bearer-auth
  timing-safe compare, `x-request-id` tracing, secret-masked JSONL audit
  (`FRAUD`/`RATE_LIMIT`/`SHADOWBAN` series) and in-memory metrics on `/healthz`;
- fail-open everywhere: guard failure → `CRITICAL` log + local pass, never a 500
  from the guard itself; disk persist runs behind a Circuit Breaker (fallback:
  memory-only + `degraded` + DLQ spill); atomic `tmp+rename` writes; socket
  timeouts; global in-flight byte budget; `SIGINT`/`SIGTERM` graceful shutdown
  with a deadline (`SHUTDOWN_TIMEOUT_MS`, default 10s).

Tuning is env-only, all `GUARD_*` (see `loadGuardConfig` defaults in `guard.mjs`):
`GUARD_WRITE_BURST`/`GUARD_WRITE_RPS`, `GUARD_PENALTY_*`, `GUARD_RISK_*`,
`GUARD_TARPIT_*`, `GUARD_IDEMPOTENCY_*`, `GUARD_CB_*`, `GUARD_MAX_INFLIGHT_BYTES`.
Tests: `guard.test.mjs` (27 unit proofs incl. 50-way race singleflight) and
`hardening.test.mjs` (live-server: 429, penalty block, shadowban isolation,
idempotent replay, graceful restart with data intact).

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
network_params = "0x..."  # required by the default enforce_key_pin (see [node] below)

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
enforce_key_pin = true    # default: refuse to start unless fhe.public_key_hash equals
                          # the on-chain pin (one check at boot, not per epoch).
                          # Needs fhe.public_key_hash + contracts.network_params, else
                          # the node refuses to boot. Off logs a WARN naming F-08: without
                          # the pin a substituted s_pub is undetectable. Devnet sets it false.
strict_weights = true     # default: refuse epochs whose seed weights are not a decodable
                          # shroud/weights/v1 file, instead of executing from genesis
                          # zeros. Turn it off only where the deployment knowingly serves
                          # non-file pins (devnet mocks).

[fhe]
backend = "reference"     # reference | tfhe-short-integer | tfhe-concrete | accelerator
# public_key_hash = "0x..."  # REQUIRED while enforce_key_pin is on (the default): the
                           # keccak(s_pub) the chain pins. Without it the node refuses
                           # to boot. The devnet config sets enforce_key_pin = false
                           # instead — its mock coprocessor publishes no pin.
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

[mesh]
# listen = "0.0.0.0:7331" # gRPC endpoint peers dial (compose maps it per node)
# Peers are untrusted: fetch_shard does disk I/O and gossip writes grow the shard
# index, so inbound work is token-bucketed per peer IP (burst headroom, sustained rate)
# and gossip streams are capped per connection. Over quota → gRPC RESOURCE_EXHAUSTED
# (fetch) or a negative ack on the stream (gossip); the stream stays alive.
inbound_rps = 100           # sustained inbound requests/sec per peer IP
inbound_burst = 200         # burst headroom per peer IP
max_streams_per_connection = 100  # each gossip stream costs a task + channel
max_throttle_peers = 10000  # peer-IP buckets in the inbound throttle; past it the stalest bucket is evicted
# mTLS (all three or none; without it the mesh serves plaintext — logged as WARN):
# mtls_cert = "/keys/mesh.crt"
# mtls_key = "/keys/mesh.key"
# ca_cert = "/keys/ca.crt"
```

Backend choice is a privacy decision, not just a performance one: `reference`
executes over development (`shroud/noop/v1`) shards whose rows are visible — it
refuses anything else rather than training on bytes it cannot read. Point it at real
encrypted shards and every epoch errors out loudly with no gas spent. Encrypted data
needs a `tfhe-*` backend **plus** `server_key_path`, on a binary built with
`--features prover`.

Settlement timing is a protocol rule, not an operator choice: the final settlement page
reverts `ChannelsImmature` while any reward channel of the task is still redeemable, and
succeeds once the 7-day reward window passes. Contributor pages settle any time; the
committee cut and buyer refund land up to one window after the last epoch. The node waits
for the earliest channel `unlockAt` instead of burning gas on the revert, and disputes go
out commit-reveal (`commitDispute` → `reportDisputeWithSalt`), so no operator action is
needed on either path.
