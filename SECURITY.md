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

## Funds

This is an MVP. Deploy only testnet/faucet funds. Do not escrow significant value until the
protocol has been audited by third parties.