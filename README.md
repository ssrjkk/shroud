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
private data, with settlement gated on a verified proof of compute.** Read
[`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) before believing any of it —
several parts are stubbed and are called out there explicitly.

## Core properties

- **FHE end-to-end**: input rows are encrypted client-side (FHEWasm) and never decrypted; the
  final weights are committee-revealed after settlement.
- **Proof of compute**: each epoch's execution is pinned by a STARK public input binding the
  chain, task, dataset root, and prior weights. A registered node can dispute by re-executing and
  reporting a different digest; a quorum of 3 distinct reporters rejects the epoch and pays nobody
  (see the caveat in [Security status](#security-status) — this quorum is *not* Sybil-resistant).
- **Streaming payments**: `PaymentVault` settles in slices (EIP-1271) so contributors and nodes are
  paid as epochs complete. A node that has not redeemed by the end of its reward window can
  `reclaim` the remainder itself; whatever is still locked when the task settles or aborts is
  swept back into the task sub-balance and ultimately refunded to the buyer.
- **Explicit budgets**: `createTask(budget, params)` escrows exactly what the buyer names.
- **Settlement always completes**: paying every contributor in one call measured at ~584M gas
  against a 30M block limit, so a task at the contributor cap could finish every epoch and become
  permanently unsettleable — contributors' funds stuck in the vault with no route out.
  `settleFrom(taskId, cursor)` pays `SETTLE_PAGE_SIZE` (200) contributors per call; the final page
  also pays the committee and refunds the buyer.
- **Disclosure is attested, not self-declared**: a task only reaches `Disclosed` once the
  decryption committee has actually submitted `threshold` distinct partial decryptions. The buyer
  cannot shortcut the ceremony to obtain the status.

## Repository

| path | what |
|------|------|
| `packages/contracts/` | fhEVM Solidity: `CipherTask`, `PaymentVault`, `DecryptionGate`, `NetworkParams`, `ProofVerifier` + Hardhat suite (69 tests) |
| `packages/sdk/` | `@shroud/sdk` — `uploadAndMonetize(data, taskId)`, EIP-712 binding, hardened DA client, on-chain key-pin check (20 tests) |
| `node/` | Rust compute node (tonic gRPC, alloy JSON-RPC, winterfell STARK, tfhe-rs FHE) — compiles clean; see the note below |
| `bot/` | Telegram ops bot: task pool, disputes, **network key rotation alerts** (22 tests) |
| `web/` | Project site — landing page and the full honest security posture |
| `infra/` | docker-compose devnet: fhEVM node, ShardStore (DA, size-capped + range-pull), 3 nodes |
| `docs/` | architecture, cryptography, proof-of-compute, threat model, honest limitations |

## Build & test

```sh
# contracts — the only fully working path
cd packages/contracts
npm ci && npx hardhat compile && npx hardhat test && npx tsc --noEmit   # 69 passing

# sdk
cd packages/sdk
npm ci && npm test                                                       # 20 passing

# ops bot (no token and no chain needed for the tests)
cd bot
npm ci && npm test                                                       # 22 passing
npm start                                                                # needs bot/.env

# node — needs protoc and a C toolchain (MSVC build tools or MinGW-w64)
cd node
cargo check --all-features

# site — any static server
cd web && python -m http.server 4173

# DA only (chain + DA)
cd infra
docker compose up -d --build shardstore
```

> **The `devnet` service does not currently deploy.** `hardhat run` does not install the FHE mock
> coprocessor (so `CipherTask`'s constructor reverts with no reason), and the plugin refuses to
> deploy to a standalone `hardhat node` (`Provider type mismatch`). `deploy.ts` now detects this and
> prints the diagnosis and workarounds instead of a bare revert. The contracts are still fully
> exercised by `hardhat test`; see [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md).

> **Note on the Rust node:** `node/`'s own source now **compiles and typechecks with zero
> warnings** — `cargo check --all-features` reported no errors and no warnings in `shroud-node`
> itself. Getting there meant fixing real API drift that had been sitting there because the crate
> had never been built: `BoxedProvider` was renamed to `DynProvider`, `Filter::selectors` no longer
> exists, `PendingTransactionBuilder` lost `block_id`, `get_chain_id` stopped returning `Option`,
> figment 0.10 removed `Serialized::from` and made `select()` take a profile, and the RPC
> `Connect` collided with tonic's generated `connect` constructor. Three latent bugs surfaced at
> the same time: `TaskStatus::from_u8` returned a `TaskStatus` where an `Option` was required (a
> variant named `None` shadowing `Option::None` under `use TaskStatus::*`), a double mutable
> borrow made the reorg-taint flag uncompilable, and two call sites referenced a
> `self_zero_address()` that was never defined — replaced with a real operator address carried on
> `NodeState`.
>
> **But the crate's tests have never run.** `cargo test` cannot link: `tfhe` and `alloy-transport`
> fail with `E0463: can't find crate` for their *proc-macro* dependencies (`strum`, `auto_impl`)
> on this Windows + MinGW-w64 toolchain. That is a dependency-graph or toolchain problem in
> third-party crates, not in this repository's code, and it is unresolved. So the three state-fold
> fixes above are **verified to typecheck but not verified to be correct** — treat them as
> unproven until `cargo test` runs. See [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) §8.
>
> Building it also needs a C toolchain and `protoc` (tonic's codegen shells out). On Windows that
> means MinGW-w64 and protobuf; the rust CI job installs neither.

## Security status

**This code moves funds and has not been externally audited. Do not deploy it with real value.**

What is actually enforced on chain today, and what is not:

| claim | status |
|---|---|
| Escrow accounting is internally consistent | **Enforced.** `PaymentVault` asserts `totalLocked == subBalancesTotal + channelLocksTotal` on every balance movement, and the check is O(1). |
| A reentrancy guard covers the money path | **Enforced and tested** with a hostile token that calls back mid-`transferFrom`. |
| Buyers cannot take funds owed to contributors or the committee | **Enforced.** `settle` and `reclaimUnspentEpochs` draw from disjoint pools, and reclaim reserves the contributor and committee shares. |
| Nothing is stranded by `abort` | **Enforced.** The retained work-in-progress slice is only withheld when a node actually verified an epoch, and it is paid as a redeemable channel. |
| The winner's digest is the dispute target | **Enforced.** A losing committer cannot redirect the dispute and get an honest epoch rejected for free. |
| Re-executors are paid, so disputing is rational | **Enforced.** `reexecutionBps` of the disputed lock is split between the reporters. |
| `Disclosed` means the committee decrypted the output | **Enforced.** `withdraw` requires the gate to have reached threshold. |
| A substituted FHE public key is detected before upload | **Enforced in the SDK, not in the node.** Pass `networkParams` + `fhePublicKeyHash` and `uploadAndMonetize` refuses on `isCurrentKey === false`. The node's `enforce_key_pin` flag is still dead code. |
| The SDK cannot upload cleartext by omission | **Enforced.** `Encryptor.providesConfidentiality` is required, and the `NoopEncryptor` default is refused unless `allowUnencrypted` is set. |
| The SDK checks the chain it signs against | **Enforced.** A configured `chainId` that disagrees with the provider is a hard error. |
| The DA client treats CIDs and responses as hostile | **Enforced.** CIDs are validated before entering a request path (they come from on-chain data any contributor controls), responses are size-capped, timed out, and the store's address and digest are never trusted — `getVerified` re-hashes the bytes with keccak256 against the on-chain `ctDigest`. |
| The surface doesn't imply guarantees that don't exist | **Enforced.** Unreachable declarations that implied missing mechanisms (a slashable contribution bond, a rejected-contribution event, a finalize step that never ran) were removed rather than left to be misread. See threat model F-34. |
| Parameter rotation installs exactly what it validated | **Enforced.** `NetworkParams` binds the candidate to its hash at proposal time and re-validates at execution, so a struct that was checked is the struct that reaches `current`. |
| The verifier that gates all payouts can be swapped instantly | **Enforced.** `ProofVerifier` rotation is propose → 7-day wait → execute, and execution is permissionless so a queued rotation cannot be frozen by a compromised owner. |
| The dispute quorum is Sybil-resistant | **NOT enforced.** `registerNode` is permissionless and takes no stake; the quorum is a flat count of 3 registered addresses. A ring of three cheap addresses can deny a node its reward (it cannot *steal* it). See [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) §2a. |
| A slashable contribution bond deters fake rows | **NOT implemented.** `contributionBond` does not exist anywhere in the tree. Sybil farming is mitigated only by `sqrt(rows)` weighting plus one-shard-per-address. F-01 in the threat model previously claimed otherwise and has been corrected. |
| The chain fully verifies the STARK | **NOT implemented.** Verification is sampled on chain and completed off-chain. See §3 of the limitations doc. |
| Committee majority cannot decrypt user rows | **NOT mitigated, by design.** Documented as residual F-10. |
| Participants detect a substituted FHE public key | **NOT enforced.** `NetworkParams` pins the key correctly on chain, but nothing reads it: the SDK has no reference to `s_pub`, and the node's `enforce_key_pin` flag is never used. A malicious sequencer can swap the key and harvest ciphertexts undetectably. The on-chain history allows *forensic* detection after the fact. See F-08. |

`docs/05-honest-limitations.md` is the document to read before trusting any of this.

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
