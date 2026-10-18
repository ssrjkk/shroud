# Changelog

All notable changes. Counts live in CI — this file records behaviour, not test numbers.
No tags or releases are published yet; entries below are merge-PR scoped until the
first tagged release.

## Unreleased

### Site: motion and small tools (no new dependencies, no build step)

- **Animations**, all of them decorative and reversible: hero elements rise in
  sequence once on load; every section header draws a short accent tick when it
  enters the viewport; the arrows in Diagram A flow along their own direction;
  the status ticker now actually scrolls (seamless, pauses on hover); cards lift
  and light up their border on hover/focus; menu underlines grow from the left.
- **Small tools**: an auto-built section bar under the masthead with a scroll-spy
  (pages with 2+ sections: home, practice, security, protocol) — every section
  also gets a stable `id`, so `#sec-3` style deep links work and respect the
  existing `scroll-margin-top`; a copy button on every `pre.code` block (labels
  follow the language, hidden on touch devices where hover does not exist); a
  2px scroll-progress line and a "back to top" button.
- `prefers-reduced-motion` is honoured in both directions: CSS kills the motion,
  and JS skips ticker duplication and reveal observers entirely.
- Progress and "back to top" write styles straight from the scroll handler (no
  `requestAnimationFrame`), so they keep working when frames are throttled.
- 4 new i18n keys (`ui.copy`, `ui.copied`, `ui.toc`, `ui.top`), RU/EN symmetric
  at 563 keys each. No claim, number or guarantee was added or softened.
- New `web/tests/i18n.mjs` (wired into the `site` workflow and the CONTRIBUTING
  pre-push list): ru/en key-set symmetry, every `data-i18n*` key in the markup
  resolving in both languages, and keys that nothing references — markup or JS.
  It caught one leftover (`idx.more`) from the section that moved to
  `security.html`, which was removed.

### Site: one page per topic (home stops being a single scroll)

- `web/index.html` is now a hub: hero + the three plain-language steps + a
  "where to go" card grid (6 links) + repository table + the pro constants block.
  It went from 192 to 129 lines; the four long sections moved to pages of their own.
- New `web/pipeline.html` (data-and-money diagram, the FHE/PROOF/MONEY cards, the
  ticker) and new `web/use.html` (lab cycle, four roles, devnet quickstart). Each has
  its own title, meta description, topbar status and `nav` active item.
- The home page's `03 ENFORCED` / `04 NOT YET` sections were **folded into the existing
  tables on `security.html`** instead of being copied there: the three gaps already
  exist as `01 / GAPS` rows (F-04, F-01, §3, F-10), and the three unique rows survive
  as a new `sec.g6` gap (end-to-end FHE, still a goal) plus `sec.e13` / `sec.e14`
  (explicit budgets, paged settlement). No security claim was dropped.
- i18n: keys re-prefixed per page (`pip.*`, `use.*`, `sec.*`), 19 duplicated keys
  removed, 27 added — `ru` and `en` stay symmetric at 560 keys each, all 497 keys
  used in markup resolve in both languages.
- Nav is identical on all seven pages (home, pipeline, practice, lab, protocol,
  security, license); `active` moved per page; no JS added.

### Security hardening (merged as #14–#19)

- Contracts (#14): `abort` reverts once every epoch ran (`SettleReady` — buyer rug
  closed); duplicate `ciphertextCid` rejected per task (`DuplicateShard`); node
  registration capped (`MAX_NODES = 200`, `nodeCount`); winner seat follows the first
  verified commit (mempool proof-copy cannot steal it); SDK ABI re-exported.
- SDK + ShardStore (#15): store addresses by real keccak-256 (was SHA3-256);
  download caps enforced while streaming with early cancel; `206` always requires
  `content-range`; relayer proofs require a `CipherTask` binding (no `ZeroAddress`);
  `getVerified` memo (bounded FIFO, copies in/out).
- Bot (#16): command dispatch uses the guard's single parse; replies go through the
  bounded send queue (`droppedSends` stays honest).
- Node (#17): full-table throttle evicts the stalest bucket (was fail-open admit);
  `mesh.max_throttle_peers` configurable (default 10000, fail-closed validation).
- Site (#18): source links track HEAD; FHE claims reframed as goal/production-path;
  lab button assembles shards; EN findings count corrected to 39; equiv fuzzes
  non-zero lanes (incl. i32 edges) and weights rejections.
- Guards (#19): `--locked` cargo builds; `links.yml` (lychee + no-pinned-`/main/`
  guard); pre-push checklist in `CONTRIBUTING.md`.
- Docs (#20): hardcoded test counts replaced with CI links.
- Trust docs (#21): `SECURITY_MODEL.md`, `TRUST_ASSUMPTIONS.md`, `CHANGELOG.md`,
  advisory triage (§7b), CodeQL for JS/TS.
- Trust round 2 (#22): README research banner, honest titles, ShardStore ETags,
  `AUDIT_SCOPE.md`.
- Release hygiene (#23): `VERSIONING.md`, `RELEASE_PROCESS.md`, evidence-pack script.
- SDK batch reads (#24): `getManyVerified` (bounded parallelism, order-preserving).
- Site honesty (#25): download buttons name the actual demo files.

### Prior base (pre-split, PR #12 lineage)

- Phase 2 execution engine wired into the worker (reference-cpu + tfhe-rs behind
  `prover`); two-node devnet agreement check in CI.
- Ubuntu 24.04 pinned across workflows; `Cargo.lock` committed.
- Contribution bonds (opt-in), commit-reveal disputes, segmented commits, settlement
  maturity gating, BLS proof-of-possession on registration.
