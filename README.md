# Shroud — Private, programmable ML with verifiable compute and streaming payouts

[![contracts](https://github.com/ssrjkk/shroud/actions/workflows/contracts.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/contracts.yml)
[![sdk](https://github.com/ssrjkk/shroud/actions/workflows/sdk.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/sdk.yml)
[![rust](https://github.com/ssrjkk/shroud/actions/workflows/rust.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/rust.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

**Train a model over other people's encrypted data — without ever seeing it. Sell the model /
your data's value without revealing either.**

Shroud is an fhEVM (Fully Homomorphic Encryption) app chain where data never leaves its
owner's device in cleartext. Buyers escrow a budget, nodes execute training over ciphertext,
prove the work with a STARK, and settle via streaming payment channels.

```
plaintext ──► FHEWasm ──► ciphertext ──► DA ──► node (FHE execute) ──► STARK proof
                                                                        │
buyer ──► CipherTask (escrow + FSM + payment channels) ◄──────────────┘
```

## Why this matters (2027 lens: AI × Privacy)

- **Compute on encrypted data** — the natural successor to "compute on public data". ZK proved
  *what was computed*; FHE removes the need to reveal *the input* at all.
- **Data DAOs / private data marketplaces** — sell the *value* of data and models without
  selling (or leaking) the data.
- **Agent economies** — privacy-preserving inference and model licensing are infrastructure
  they all lean on.

Shroud is the plumbing for the highest-value version of that: **train and sell a model over
private data, with settlement that only happens when the work is verifiably done.**

## Core properties

- **FHE end-to-end**: input rows are encrypted client-side (FHEWasm) and never decrypted; the
  final weights are committee-revealed after settlement.
- **Proof of compute**: each epoch's execution is pinned by a STARK public input binding the
  chain, task, dataset root, and prior weights. Disputes trigger re-execution and a committee
  quorum.
- **Streaming payments**: `PaymentVault` settles in slices (EIP-712) so contributors and nodes
  are paid as epochs complete, with un-redeemed rewards clawed back after their window.
- **Explicit budgets**: `createTask(budget, params)` escrows exactly what the buyer names.

## Repository

| path | what |
|------|------|
| `packages/contracts/` | fhEVM Solidity: `CipherTask`, `PaymentVault`, `DecryptionGate`, `NetworkParams`, `ProofVerifier` + Hardhat suite (39 tests) |
| `packages/sdk/` | `@shroud/sdk` — `uploadAndMonetize(data, taskId)`, EIP-712 binding, DA + FHE abstractions |
| `node/` | Rust compute node (tonic gRPC, alloy JSON-RPC, winterfell STARK, tfhe-rs FHE) |
| `infra/` | docker-compose devnet: fhEVM node, ShardStore (DA), 3 nodes |
| `docs/` | architecture, cryptography, proof-of-compute, threat model, honest limitations |

## Build & test

```sh
# contracts
cd packages/contracts
npm ci && npx hardhat compile && npx hardhat test && npx tsc --noEmit   # 39 passing

# sdk
cd packages/sdk
npm ci && npm test                                                       # selector + EIP-712 checks

# devnet (chain + DA)
cd infra
docker compose up -d --build devnet shardstore
```

> **Note on the Rust node:** on this host, Windows Smart App Control / WDAC blocks Cargo
> build-script binaries, so `node/` cannot be compiled here. It builds on any normal machine or
> in CI (`.github/workflows/rust.yml`). See `infra/README.md`.

## Docs

- [`docs/01-architecture.md`](docs/01-architecture.md) — system design and lifecycle
- [`docs/02-cryptography.md`](docs/02-cryptography.md) — TFHE, quantization, DKG, threshold reveal
- [`docs/03-proof-of-compute.md`](docs/03-proof-of-compute.md) — STARK + dispute protocol
- [`docs/04-threat-model.md`](docs/04-threat-model.md) — security analysis
- [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) — honest MVP scope

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, test and contribute.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability (this protocol moves funds).

## License

MIT — see [LICENSE](LICENSE).
