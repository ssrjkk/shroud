# Versioning

- Semantic versioning. While the protocol is unaudited, major version stays `0`:
  anything may break between minors.
- Release lines: `v0.1.0-testnet` (faucet funds only), later `v1.x` (never before
  an external audit with fixed findings — see `AUDIT_SCOPE.md`).
- Release candidates: `v0.1.0-testnet-rc.1`, `-rc.2`, … Cut as a `release/…` branch
  from a green `main`; the branch is frozen except for release-blockers, each
  re-cut as a new `-rc.N`.
- Tags are annotated and signed (`git tag -s`). The tag message names the evidence
  pack (CI run IDs + artifact checksums). histoire lives in `CHANGELOG.md`:
  behaviour entries, never test counts.
- No force-pushes to a release branch after the tag. A broken RC is abandoned
  (`-rc.N+1`), never rewritten.
