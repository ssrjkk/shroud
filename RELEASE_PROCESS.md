# Release process

How a `main` commit becomes a testnet release candidate. Every step leaves an
artifact; a step with no artifact did not happen.

## 1. Freeze

```sh
git checkout -b release/v0.1.0-testnet-rc.1
```

From here: release-blockers only. Docs typos ride along; behaviour changes re-cut
the RC. Open security-sensitive PRs (if any) stay out until merged to `main`
and re-cut.

## 2. Evidence pack

```sh
./scripts/evidence-pack.sh
```

Runs every suite that runs without secrets (contracts, SDK, bot, ShardStore,
`equiv.mjs`, `cargo fmt --check`) and writes `evidence/<UTC-timestamp>/` with:

- `versions.txt` — `git rev-parse HEAD`, node/npm/rustc/hardhat/solc versions, lockfile hashes;
- `ci.txt` — the CI run IDs covering the same commit (from `gh run list`);
- one log file per suite, unedited;
- `exit-codes.txt` — one `name=code` line per suite, the exit codes the release notes cite.

The directory is **not** committed. Its checksums go into the release notes;
the logs attach to the draft release.

## 3. Artifacts

- Contracts: `npx hardhat compile` → bytecode hashes (`artifacts/` build-info).
- SDK: `npm pack` tarball (from a clean `npm ci`).
- Node/bot: container digests from `infra/` Dockerfiles (pinned bases only).
- Site: the `web/` bundle checksum (`sha256sum`).
- `checksums.txt` over all of the above (SHA-256, one line per artifact).

## 4. Sign and publish

- `git tag -s v0.1.0-testnet-rc.1 -m "<evidence summary>"`.
- Draft GitHub release with `RELEASE_NOTES.md`: the research-prototype warning,
  trust assumptions pointer, known limitations, supported networks, commit hash,
  artifact checksums.
- An independent machine rebuilds from the tag and compares hashes before the
  `testnet` (non-RC) tag moves.

## 5. Promote or abandon

Green rebuild + no new findings → `v0.1.0-testnet` (signed, same pack).
Anything else → fix on `main`, re-cut `-rc.N+1`. Never rewrite a pushed RC.
