# Shroud — Private, programmable ML with verifiable compute and streaming payouts

[![contracts](https://github.com/ssrjkk/shroud/actions/workflows/contracts.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/contracts.yml)
[![sdk](https://github.com/ssrjkk/shroud/actions/workflows/sdk.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/sdk.yml)
[![rust](https://github.com/ssrjkk/shroud/actions/workflows/rust.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/rust.yml)
[![site](https://github.com/ssrjkk/shroud/actions/workflows/site.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/site.yml)
[![bot](https://github.com/ssrjkk/shroud/actions/workflows/bot.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/bot.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

🌐 **Live site: [ssrjkk.github.io/shroud](https://ssrjkk.github.io/shroud/)** — the project,
the protocol, the honest security posture, and a lab that runs the pipeline in your browser.

| [Home](https://ssrjkk.github.io/shroud/) · [Lab](https://ssrjkk.github.io/shroud/playground.html) · [Protocol](https://ssrjkk.github.io/shroud/protocol.html) · [Security](https://ssrjkk.github.io/shroud/security.html) · [License](https://ssrjkk.github.io/shroud/license.html) |
|---|

| ![Home — pipeline, guarantees, repo map](docs/shots/home.png) | ![Lab — the protocol running in the browser](docs/shots/lab.png) |
|---|---|
| ![Protocol — full spec, params, roles](docs/shots/protocol.png) | ![Mobile layout](docs/shots/mobile.png) |

The site is fully static (`web/`, no build step): bilingual RU/EN, ink/paper themes,
newcomer/pro audience modes. The lab computes with the same math as the node
and the SDK — quantization, reference SGD, trace digest, proof reference, settlement —
entirely client-side, byte-for-byte against `packages/sdk` and `node/`.

**Train a model over other people's encrypted data — without ever seeing it. Sell the model /
your data's value without revealing either.**

Shroud is an fhEVM (Fully Homomorphic Encryption) app chain. Buyers escrow a budget, nodes
execute training over ciphertext, each epoch is pinned by a proof-of-compute digest that a
quorum of re-executors can dispute, and contributors, nodes and the committee are paid
through streaming payment channels.

```
plaintext ──► FHEWasm ──► ciphertext ──► DA ──► node (FHE execute) ──► STARK proof
                                                                        │
buyer ──► CipherTask (escrow + FSM + payment channels) ◄──────────────┘
```

> **Status: research-grade implementation, not audited, do not use with real value.**
> What is actually enforced — and what is not — is listed under
> [Security status](#security-status) and in full in
> [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md). Read that file before
> trusting any claim below.

## Quickstart (devnet)

```sh
cd infra && docker compose up -d --build devnet shardstore   # fhEVM chain + DA
cd ../packages/contracts && npm run deploy:devnet             # deploy contracts
npx hardhat run scripts/devnet-e2e-check.ts --network localhost  # create → seal → register smoke
```

`--network localhost` is load-bearing: the fhevm plugin instruments a standalone node only
under that name (port 8545, chainId 31337). Anything else resolves to provider type `Unknown`,
the mock coprocessor is never installed, and `CipherTask`'s constructor reverts with no reason.

## Who is this for, and how to use it

- **Buyer — fund a private training task.** Escrow a budget and describe the model:
  `packages/contracts/scripts/devnet-e2e-check.ts` shows the calls
  (`createTask` → contributions land → `sealTask` → `openEpoch` per epoch); the SDK wraps
  them in `ShroudSdk`. Settlement pays contributors, the winning node and the committee
  out of your escrow, and refunds the rest.
- **Contributor — sell your data's value, not the data.** Encrypt rows client-side and
  commit the shard: `sdk.uploadAndMonetize(data, taskId, { features, allowUnencrypted })`
  (production: a real `Encryptor`, e.g. `@shroud/sdk/relayer`). Plaintext never leaves
  your machine; the chain only ever sees CIDs and digests. End-to-end example:
  `packages/sdk/scripts/devnet-check.mjs`.
- **Node operator — run compute and earn epochs.** `docker compose up -d node-a` (see
  [`infra/README.md`](infra/README.md) §3 for every knob: backends, DA, key pin, windows),
  or build `node/` and point it at a task. The node registers, executes, commits, disputes
  from its own commits, and redeems its reward channels.
- **Ops — watch a deployment.** Run the Telegram bot (`bot/`, needs `bot/.env` with a token
  and an allowlist): `/pool`, `/task <id>`, mismatch/dispute/rotation alerts. Setup and
  limits: [`bot/README.md`](bot/README.md).

## Repository

| path | what |
|------|------|
| `packages/contracts/` | fhEVM Solidity: `CipherTask`, `PaymentVault`, `DecryptionGate`, `NetworkParams`, `ProofVerifier` + Hardhat suite (lifecycle, stateful fuzz, gas snapshot, admin controls, byte-layout vectors — [counts live in CI](https://github.com/ssrjkk/shroud/actions/workflows/contracts.yml)) |
| `packages/sdk/` | `@shroud/sdk` — `uploadAndMonetize(data, taskId)`, `publishWeights`, EIP-712 binding, hardened DA client, on-chain key-pin check, weight files ([counts live in CI](https://github.com/ssrjkk/shroud/actions/workflows/sdk.yml)) |
| `node/` | Rust compute node: chain follower + epoch executor (deterministic reference engine, `tfhe-rs` behind `prover`), gRPC mesh, content-addressed DA (`da` feature for remote) — see [Node](#node) |
| `bot/` | Telegram ops bot: task pool, disputes, **network key rotation alerts** ([counts live in CI](https://github.com/ssrjkk/shroud/actions/workflows/bot.yml), incl. stub-RPC read coverage) |
| `web/` | Project site (static, no build): home, in-browser lab, protocol, security status, license — RU/EN, ink/paper themes, newcomer/pro modes |
| `infra/` | docker-compose devnet: fhEVM node, ShardStore (DA, size-capped + range-pull), 3 nodes — operator runbook in [`infra/README.md`](infra/README.md) |
| `docs/` | architecture, cryptography, proof-of-compute, threat model, honest limitations |

## Build & test

```sh
# contracts
cd packages/contracts
npm ci && npx hardhat compile && npx hardhat test && npx tsc --noEmit   # counts in CI

# sdk
cd packages/sdk
npm ci && npm test                                                       # counts in CI

# ops bot (no token and no chain needed for the tests)
cd bot
npm ci && npm test                                                       # counts in CI
npm start                                                                # needs bot/.env

# node — needs protoc and a C toolchain; see the note below
cd node
cargo check --all-features && cargo check --no-default-features
cargo test --all-features && cargo test --no-default-features

# site — any static server
cd web && python -m http.server 4173
```

## Node

`node/` follows the chain (reorg-safe watcher → derived fold), executes open epochs
(deterministic fixed-point engine over sealed shards, artefacts published to the
content-addressed store), files disputes from its own commits, and collects its payment
duties (finalize/settle/redeem/reclaim/claim/bond). What it is today:

- **Executes for real** (`reference-cpu` engine, golden-tested; `tfhe-rs` backend behind
  `--features prover`), with the genuine constraints documented in the module docs.
- **Commits a 32-byte proof *reference*** that verifies on mock-verifier chains; a real
  proving system is Phase 3.
- **Verified by CI on Linux, never locally**: on machines where freshly built binaries
  cannot load (locked-down Windows/Smart App Control), `cargo check`/`cargo test` cannot
  run at all — see [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) §8.
  `cargo fmt` is green.

Operator configuration (backends, DA, key pin, timeouts) is documented in
[`infra/README.md`](infra/README.md) §3.

## Core properties

- **FHE end-to-end**: input rows are encrypted client-side and never decrypted; the final
  weights are committee-revealed after settlement.
- **Proof of compute**: each epoch pins chain, task, dataset root and prior weights in a
  transcript-bound digest. Any registered node can re-execute and report a different digest;
  3 distinct reporters reject the epoch and pay nobody. The quorum is priced by a
  registration bond, **not** Sybil-resistant — see below.
- **Streaming payments**: `PaymentVault` settles in EIP-712 slices as epochs complete, with
  reclaim and buyer-refund paths that cannot touch contributor or committee shares.
- **Settlement scales**: paying a capped contributor set in one call was measured at ~584M
  gas against a 30M block limit, so `settleFrom(taskId, cursor)` pays `SETTLE_PAGE_SIZE`
  (200) contributors per call instead; the final page pays the committee and refunds the buyer.
- **Budgets are explicit**: `createTask(budget, params)` escrows exactly the named amount.
- **Disclosure is attested**: `Disclosed` requires `threshold` real committee partial
  decryptions — the buyer cannot self-declare it.

## Security status

**This code moves funds and has not been externally audited. Do not deploy it with real value.**

| claim | status |
|---|---|
| Escrow accounting is internally consistent | **Enforced.** `totalLocked == subBalances + channelLocks` asserted on every movement (O(1)), plus a deterministic fuzz asserting it after every lifecycle step. |
| Reentrancy on the money path | **Enforced and tested** with a hostile token calling back mid-`transferFrom`. |
| Buyers cannot take contributor/committee funds | **Enforced.** Settle and reclaim draw from disjoint pools. |
| `abort` strands nothing | **Enforced.** Only verified work-in-progress is withheld, as a redeemable channel. |
| Disputes target the real winner | **Enforced.** A losing committer cannot redirect a dispute onto an honest epoch. |
| Disputing is rational | **Enforced.** `reexecutionBps` of the lock goes to reporters; the winner's bond slashes into the buyer refund on quorum reject. |
| `Disclosed` means decrypted | **Enforced.** `withdraw` requires the threshold gate. |
| Key substitution is detected before upload | **Enforced, fail-closed for real encryptors.** A confidential encryptor with a declared key refuses to run without `networkParams` (unless `allowUnpinnedKey`); node-side check is opt-in but its absence is a startup `WARN`. |
| Cleartext upload by omission | **Enforced.** Non-encrypting encryptors are refused without `allowUnencrypted`. |
| Wrong-chain signing | **Enforced.** A configured `chainId` mismatch is a hard error. |
| Hostile DA | **Enforced.** CIDs validated pre-request, responses size-capped and timed out, payloads re-hashed locally against the on-chain pin. |
| Admin surface | **Enforced.** Treasury/proof-flag/pause switches are owner-only, tested; verifier and manager rotations go through timelocks executable by anyone; live rotations cannot be overwritten without a cancel. |
| Fee-on-transfer escrow tokens | **Enforced (fail-closed).** Vault ledgers the balance diff actually received; shortfalls revert instead of mis-accounting. |
| Dispute front-running | **Enforced.** Commit-reveal reporting (`commitDispute` → `reportDisputeWithSalt`); the node files disputes this way. |
| Epoch-authorship by the owner | **Enforced.** Only buyer/update-manager may `openEpoch`; the owner keeps `emergencyUnwind`. |
| Settlement against immature channels | **Enforced.** The final page reverts `ChannelsImmature` until the reward window passes; earlier pages proceed. |
| Sybil-resistant dispute quorum | **NOT enforced — priced, not prevented.** Flat count of 3; locked capital returns after terminality. See `05` §2a. |
| Slashable contribution bond | **Opt-in, not a fraud proof.** `setContributionBondRequirement` + slash-to-treasury exists; no requirement by default and no on-chain proof of poison. |
| Full on-chain STARK verification | **NOT implemented.** Segmented path is reachable (`commitEpochSegmented`) but no prover exists; sampled on chain, completed off-chain. See `05` §3. |
| Committee cannot decrypt rows | **NOT mitigated, by design** (residual F-10). |
| Key-substitution detection by default | **NOT enforced for default configs** (fail-closed only once a confidential encryptor declares its key; node opt-in; forensic detection after the fact). |

## Roadmap

### Done

- **Protocol core:** task FSM + escrow + streaming channels + threshold reveal + rotation
  timelocks; dispute quorum with winner-bond slash; commit-reveal dispute reporting with
  reporter-bound salt; BLS-key proof-of-possession on registration; opt-in contribution
  bonds (slash-to-treasury); segmented-proof commit path; settlement gated on reward
  maturity; fee-on-transfer fail-closed accounting; admin controls under test.
- **Compute:** deterministic execution engine wired into the worker (commit, re-execute,
  commit-reveal disputes from own commits); `tfhe-rs` backend + remote DA behind cargo features;
  inbound mesh throttling per peer IP + stream cap; `strict_weights` opt-in; two-node
  devnet agreement check in CI.
- **Clients & ops:** SDK upload/weights/key-pin (fail-closed)/DA hardening + DecryptionGate
  client, Telegram ops bot with read coverage + per-chat abuse quotas + alert dedupe,
  content-addressed DA service with perimeter guard (rate limits, penalty box, shadowban,
  idempotency, graceful shutdown), devnet compose, gas snapshot + lifecycle fuzz in the suite.

### Next

- [ ] **Proving (Phase 3):** zkVM guest circuit over the 8-field transcript; recursive
  aggregation so on-chain verification is literally true; CPU/GPU benchmarks.
- [ ] **Cryptoeconomics (Phase 4):** stake-weighted re-executor
  assignment (+ slashing both ways), fhEVM Gateway threshold re-encryption, Foundry
  native invariants.
- [ ] **Green devnet-live execution leg:** the two-node agreement script is wired in CI
  and awaiting its first green run.

## Docs

- [`docs/01-architecture.md`](docs/01-architecture.md) — system design and lifecycle
- [`docs/02-cryptography.md`](docs/02-cryptography.md) — TFHE, quantization, DKG, threshold reveal
- [`docs/03-proof-of-compute.md`](docs/03-proof-of-compute.md) — STARK + dispute protocol
- [`docs/04-threat-model.md`](docs/04-threat-model.md) — security analysis
- [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) — honest MVP scope
- [`infra/README.md`](infra/README.md) — devnet + node operator runbook
- [`bot/README.md`](bot/README.md) — ops bot setup and limits

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, test and contribute.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability (this protocol moves funds).

## License

MIT — see [LICENSE](LICENSE).
