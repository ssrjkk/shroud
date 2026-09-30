# Contributing to Shroud

Thanks for contributing! Shroud is a private ML protocol on fhEVM: buyers escrow a budget,
nodes train over encrypted data, prove the work with a STARK, and get paid via streaming
channels.

## Repository layout

```
packages/contracts/   fhEVM Solidity (CipherTask, PaymentVault, DecryptionGate, NetworkParams, ProofVerifier)
packages/sdk/         @shroud/sdk — client-side encryption + orchestration
node/                 Rust compute node (watcher, FHE executor, STARK prover)
infra/                docker-compose devnet (fhEVM node + ShardStore DA + 3 nodes)
docs/                 architecture, cryptography, proof-of-compute, threat model, limitations
```

## Getting started

```sh
# contracts (tests run against an in-process fhEVM mock)
cd packages/contracts
npm ci && npx hardhat compile && npx hardhat test

# sdk (smoke tests cross-check the SDK ABIs against compiled artifacts)
cd packages/sdk
npm ci && npm test

# devnet (chain + DA)
cd infra
docker compose up -d --build devnet shardstore
```

The Rust node compiles with `cargo build --release` (needs protoc; see `.github/workflows/rust.yml`).

## Contract changes

- Keep the EIP-712 domain string (`ShroudPaymentVault`) and protocol domains
  (`SHROUD/CTROOT/v1`, `SHROUD/PoC/v1`, `SHROUD/REVEAL/v1`) in sync between Solidity, the SDK
  and the Rust node.
- Add tests for every new branch: escrow/accounting invariants, channel lifecycle, dispute
  quorum, reveal gating.
- Never store proofs on-chain; only 32-byte references/digests.
- No real credentials: only `.env.example` files are committed.

## Pull request checklist

- [ ] `npx hardhat test` passes (contracts) and `npm test` passes (sdk).
- [ ] `npx tsc --noEmit` is clean for both packages.
- [ ] New behavior is covered by tests.
- [ ] Docs updated (`docs/`) if protocol behaviour changed.
- [ ] Commit message follows conventional format (`fix(contracts):`, `feat(sdk):`, `chore:`...).

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately — this project moves funds.

## License

MIT — see [LICENSE](LICENSE).