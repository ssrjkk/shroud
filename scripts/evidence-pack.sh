#!/usr/bin/env bash
# evidence-pack.sh — run every secret-free suite and record versions + logs.
# Output: evidence/<UTC-timestamp>/ (NOT committed; checksums go to release notes).
# Usage: ./scripts/evidence-pack.sh
# Fails fast: a red suite aborts the pack (set -e), the partial directory stays
# on disk for diagnosis but must never be attached to a release.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/evidence/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

SHA="$(git -C "$ROOT" rev-parse HEAD)"

# The solc version is the one that compiled the contracts, not the Hardhat
# version: `hardhat --version` prints Hardhat's own number, and the two differ
# (the pinned solc is 0.8.24 while Hardhat is 2.x). The build-info carries the
# real one; before the first compile there is nothing to read, and the pack
# says so rather than recording a wrong number.
solc_version() {
  local info
  info="$(ls -1 "$ROOT"/packages/contracts/artifacts/build-info/*.json 2>/dev/null | head -n 1)"
  if [ -n "$info" ]; then
    node -e 'const b=require(process.argv[1]);process.stdout.write(b.solcVersion||"UNKNOWN")' "$info" 2>/dev/null \
      || echo "UNKNOWN"
  else
    echo "NOT COMPILED (no artifacts/build-info)"
  fi
}

{
  echo "sha: $SHA"
  echo "node: $(node --version)  npm: $(npm --version)"
  echo "rustc: $(rustc --version 2>/dev/null || echo MISSING)"
  echo "hardhat: $(npx --prefix "$ROOT/packages/contracts" hardhat --version 2>/dev/null || echo MISSING)"
  echo "solc: $(solc_version)"
  echo "lockfiles:"
  sha256sum "$ROOT"/node/Cargo.lock "$ROOT"/packages/*/package-lock.json 2>/dev/null || true
} | tee "$OUT/versions.txt"

# The CI run IDs covering this commit. The release notes cite them, so they are
# part of the pack: a tag whose evidence cannot name the runs that cleared it
# is not auditable. `gh` may be missing on an offline machine; the file then
# says so rather than not existing.
{
  echo "sha: $SHA"
  if command -v gh >/dev/null 2>&1; then
    gh run list --commit "$SHA" --limit 50 2>/dev/null || echo "(gh run list failed)"
  else
    echo "(gh not installed: no CI run IDs recorded)"
  fi
} >"$OUT/ci.txt"

run() { # run <name> <dir> <cmd...>
  local name="$1" dir="$2"; shift 2
  echo "--- $name ($dir): $*"
  local status=0
  (cd "$ROOT/$dir" && "$@" >"$OUT/$name.log" 2>&1) || status=$?
  # The exit code goes into its own file, not into the log: the logs are evidence
  # and stay unedited, while the codes are what the release notes cite. A log
  # without a code cannot be told apart from a suite that was never run.
  echo "$name=$status" >>"$OUT/exit-codes.txt"
  echo "--- $name exit=$status (see $name.log)"
  return $status
}

run contracts packages/contracts npm test
run sdk packages/sdk npm test
run bot bot npm test
run shardstore infra/shardstore node --test keccak.test.mjs guard.test.mjs server.test.mjs hardening.test.mjs
run equiv web node tests/equiv.mjs
run fmt node cargo fmt --all -- --check

echo "evidence pack complete: $OUT"
