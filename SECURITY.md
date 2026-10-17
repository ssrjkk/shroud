# Security Policy

## Reporting a vulnerability

Shroud handles real money (escrow, streaming payments) and cryptographic secrets (FHE keys,
decryption committee). If you find a vulnerability — something that could drain funds, leak
plaintext data, or bypass proof verification — please report it **privately**:

- Open a private report via **GitHub Security Advisories**:
  `https://github.com/ssrjkk/shroud/security/advisories/new`
- Do **not** open a public issue for it.
- Do not include live credentials, keys or personal data in the report.

## What is in scope

- Contract logic errors in `CipherTask`, `PaymentVault`, `DecryptionGate`, `NetworkParams`,
  `ProofVerifier` (fund loss, reentrancy, accounting, signature/authorisation bypass).
- Cryptographic misuse (FHE handle handling, EIP-712/EIP-1271 bindings, BLS gating).
- Credential leaks in configs, Docker/k8s manifests, CI secrets.

## Out of scope

- Theoretical FHE/STARK limitations documented in `docs/` (e.g. a t-of-n committee colluding
  off-chain — see `docs/04-threat-model.md`).
- Governance keys held by a single operator (documented design trade-off).
- Feature requests or missing tests.

## Disclosure

We aim to acknowledge reports within 3 business days and coordinate a fix before public
disclosure. Do not exploit or publicly demonstrate an issue before a fix is released.

## Dependency security

`packages/contracts` builds on Hardhat 2 (`@fhevm/hardhat-plugin` peers on
`hardhat ^2`), whose transitive closure carries advisories that no in-range
upgrade can fix. They are pinned via flat `overrides` in
`packages/contracts/package.json` (flat keys — range keys like
`diff@>=6.0.0 <8.0.3` break `npm ci` on the npm 10 shipped with Node 22):

| transitive | pinned | fixes |
|---|---|---|
| `cookie` | `0.7.0` | GHSA-pxg6-pf52-xh8x |
| `tmp` | `0.2.7` | GHSA-52f5-9888-hmc6, GHSA-ph9p-34f9-6g65, GHSA-7c78-jf6q-g5cm |
| `undici` | `6.28.1` | GHSA-g9mf-h72j-4rw9 and the `<6.24.0` / `<6.27.0` / `<6.28.x` series |
| `diff` | `8.0.3` | GHSA-73rr-hh4g-fpgx |
| `serialize-javascript` | `7.0.5` | GHSA-5c6j-r48x-rmvq, GHSA-qj8w-gfj5-8c6v |
| `uuid` | `11.1.1` | GHSA-w5hq-g745-h8pq |
| `adm-zip` | `0.6.1` | the `<0.6.0` / `<0.6.1` / `<=0.6.0` series |
| `@fastify/busboy` | `3.2.2` | GHSA-x8mw-p69m-v3mx, GHSA-gxm5-99cw-xjw9 |

`npm audit` after the pins reports 0 high/moderate (16 low remain, all on the
`elliptic` chain). The `contracts` CI job gates on `npm audit --audit-level=high`,
so a new high/critical advisory fails the build instead of waiting for the
weekly Dependabot scan. All workspaces require `npm >= 10` (`engines`).

Known accepted risk: `elliptic<=6.6.1` (GHSA-848j-6mx2-7j84, low, no patched
version) arrives via `hardhat@2` (`@ethersproject/*`, `ethereumjs-util`).
Removing it requires Hardhat 3, which `@fhevm/hardhat-plugin` does not support.
It is dev/build tooling only — never shipped to production or used for
on-chain verification — and the Dependabot alert is dismissed as tolerable
risk until the fhevm plugin supports Hardhat 3.

## Funds

This is an MVP. Deploy only testnet/faucet funds. Do not escrow significant value until the
protocol has been audited by third parties.