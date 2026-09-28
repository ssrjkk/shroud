# CipherMesh devnet (`infra/`)

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

- `devnet` starts a hardhat fhEVM node (in-process FHE mock coprocessor) and deploys the
  contracts, writing addresses to `infra/devnet/addresses.json`.
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

then `docker build -t ciphermesh-node:dev -f infra/node/Dockerfile .` from the repo root.
