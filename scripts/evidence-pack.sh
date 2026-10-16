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

{
  echo "sha: $(git -C "$ROOT" rev-parse HEAD)"
  echo "node: $(node --version)  npm: $(npm --version)"
  echo "rustc: $(rustc --version 2>/dev/null || echo MISSING)"
  echo "solc: $(npx --prefix "$ROOT/packages/contracts" hardhat --version 2>/dev/null || echo MISSING)"
  echo "lockfiles:"
  sha256sum "$ROOT"/node/Cargo.lock "$ROOT"/packages/*/package-lock.json 2>/dev/null || true
} | tee "$OUT/versions.txt"

run() { # run <name> <dir> <cmd...>
  local name="$1" dir="$2"; shift 2
  echo "--- $name ($dir): $*"
  (cd "$ROOT/$dir" && "$@" >"$OUT/$name.log" 2>&1)
  echo "--- $name exit=$? (see $name.log)"
}

run contracts packages/contracts npm test
run sdk packages/sdk npm test
run bot bot npm test
run shardstore infra/shardstore node --test keccak.test.mjs guard.test.mjs server.test.mjs hardening.test.mjs
run equiv web node tests/equiv.mjs
run fmt node cargo fmt --all -- --check

echo "evidence pack complete: $OUT"
