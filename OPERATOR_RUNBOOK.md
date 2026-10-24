# Operator runbook

Run a node and a ShardStore without surprises. Every default below is the code
default (`node/src/config.rs`, `infra/shardstore/guard.mjs`) — this file explains,
never overrides.

## ShardStore

```sh
PORT=8080 DATA_DIR=./data AUTH_TOKEN="$(openssl rand -hex 32)" node infra/shardstore/server.mjs
```

- Writes require `AUTH_TOKEN` (reads stay open by design); without it the server
  refuses to start unless `ALLOW_UNAUTHENTICATED=1` (dev only, localhost).
  Minimum 16 chars; generate with `openssl rand -hex 32`.
- Rotating `AUTH_TOKEN`: set the new value, restart the process (no hot-reload by
  design — a live secret swap would split the fleet mid-upload). Clients retry with
  backoff; in-flight PUTs fail closed with 401 and must be retried.
- Empty objects are rejected (400): they would otherwise evict legit shards via LRU.
- `NOT_FOUND`/`DUP_PAYLOAD` never count as hard abuse signals (retries are normal);
  only `AUTH_FAIL`/`RATE_HIT`/`RANGE_ABUSE` can trigger the honeypot shadowban.
- Caps: `MAX_OBJECT_BYTES` (default 64 MiB), `MAX_OBJECTS` (default 4096, LRU).
  Over-cap PUTs get 413 mid-stream; full in-flight budget sheds with 503 + `Retry-After`.
- TLS terminates with `TLS_CERT`/`TLS_KEY` (both or neither); behind a proxy set
  `TRUST_PROXY=1` so throttling and risk scoring see real client IPs.
- Health: `GET /healthz` reports objects, degraded persistence, breaker state.
- Data survives restarts: disk copies under `DATA_DIR` rebuild the index on boot;
  `DELETE /objects/:cid` removes both entry and file.

## Node

```sh
cd infra && docker compose up -d --build devnet shardstore   # chain + DA
# operator key funded on the devnet faucet first, then:
shroud-node --config shroud.toml
```

- `shroud.toml` needs `chain.rpc_url`, `contracts.*`, `node.operator_key`,
  `data_dir`; see `infra/README.md` for the full annotated example.
- The operator key pays gas + the registration bond (10 units, pulled per task,
  approval is one-per-lifetime and exact-allowance checked first).
- `node.enforce_key_pin` is on by default: the node compares the on-chain FHE key at startup
  and refuses to boot on a mismatch. It needs `fhe.public_key_hash` plus
  `contracts.network_params` — without them the node will not start. Devnet sets it false
  explicitly, and the node then logs a loud warning that the key is NOT checked.
- Mesh serves plaintext without `mesh.mtls_*` (all three paths or none) — logged
  as WARN. Throttle: `inbound_rps`/`inbound_burst` per IP, `max_throttle_peers`
  buckets with stalest-eviction, `max_streams_per_connection` per h2 connection.
- `shard.aead_transport = true` fails closed (unimplemented — use mTLS + DA TLS).

## Upgrades and recovery

- Config changes need a restart; there is no hot reload by design.
- Chain reorgs below the cursor rewind the watcher (idempotent fold); a reorg
  deeper than `finality.reorg_threshold + confirmations` triggers full rebuild
  from the last checkpoint (`checkpoint_interval` blocks).
- Reward channels redeem via `PaymentVault`; unclaimed channels sweep back into
  the task sub-balance at settlement — nothing strands while the node is down,
  but deadlines (`epochDuration`, dispute windows) do not wait for restarts.
