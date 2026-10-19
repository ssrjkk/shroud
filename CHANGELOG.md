# Changelog

All notable changes. Counts live in CI — this file records behaviour, not test numbers.
No tags or releases are published yet; entries below are merge-PR scoped until the
first tagged release.

## Unreleased

### Node: the build needed a flag nobody set — CI could not compile the crate

- `alloy-signer-local` 2.5.0 calls `<[u8; 32]>::from(self.to_field_bytes())`, and the
  `From<GenericArray<T, N>> for [T; N]` impl that requires is an orphan-rule violation,
  so `generic-array` gates it behind `--cfg relaxed_coherence` and offers `Into`
  instead. The flag was set in one developer's shell on 2026-10-18 and nowhere else:
  **CI compiled with `RUSTFLAGS: "-D warnings"` only, so `cargo check --locked
  --all-features` could not build the crate at all** — the failure is a trait error
  inside a dependency that never mentions `generic-array`, which is what makes it
  hard to read.
- The flag now lives in the repository, in two places that must agree: `node/.cargo/config.toml`
  (for every local build) and the CI `RUSTFLAGS` (the environment variable *replaces*
  `build.rustflags` rather than extending it). `--check-cfg cfg(relaxed_coherence)`
  comes with it: `--cfg` for a name the crate does not declare trips `unexpected_cfgs`,
  and CI compiles with `-D warnings`.
- `infra/node/Dockerfile` needed the same fix: its dependency-cache stage copied only
  `Cargo.toml` / `Cargo.lock` / `build.rs` / `proto`, so the image build would have
  failed the same way before the real source was even copied. It now copies
  `node/.cargo` as well.
- Verified: `cargo check --locked --all-targets --all-features` and `cargo fmt --all -- --check`
  pass with the flag; without it the crate does not compile. `cargo clippy` is clean on both
  feature sets (with `--all-targets`, which the CI invocation does not lint), and the suites
  run green: 174 node tests and 14 `shroud-core` tests.

### Node: key-pin and weight checks are on by default, config fails closed at load

- `node.enforce_key_pin` and `node.strict_weights` default to **true**. A node with the
  pin check on but no `fhe.public_key_hash` / `contracts.network_params` refuses to boot
  instead of running unpinned, and an epoch whose seed weights are not a decodable
  `shroud/weights/v1` file is a hard error instead of a silent fallback to genesis zeros.
  Devnet opts out explicitly, per field.
- `Config::validate` now rejects the configurations that parse but make the node useless:
  an empty `chain.rpc_url` or `shard.da_endpoint`, a `da_endpoint` scheme nothing serves
  (`s33://`), whitespace around the endpoint, a zero `shard.max_ciphertext_bytes` /
  `stark.max_proof_bytes` / `payment.redeem_gas_limit`, and a zero `chain.poll_interval`
  or `mesh.announce_interval` (those two busy-loop instead of polling).
- A node that refuses to boot now says why. `ConfigError::Missing` carries an optional
  reason, and the two pin checks use it: with `enforce_key_pin` on by default, "missing
  required field `fhe.public_key_hash`" was a dead end — the message now names the
  opt-out (`node.enforce_key_pin = false`) as well as the two fields to set instead.
- F-08 in `docs/04-threat-model.md` is re-graded from "not mitigated" to **"mitigated at
  boot, not mid-epoch"** — the node-side check is on by default, but it still runs once,
  at startup, and the SDK half is still skipped when the caller does not pass a pin.
- Every place that still described the old behaviour was corrected to match the code:
  `README.md`, `OPERATOR_RUNBOOK.md`, `USER_GUIDE.md`, `infra/README.md`,
  `AUDIT_SCOPE.md`, `TRUST_ASSUMPTIONS.md`, `docs/01-architecture.md`,
  `docs/05-honest-limitations.md`, `bot/README.md`, and the F-08 rows of
  `web/security.html` + `web/protocol.html` (RU and EN in lockstep).
- Robustness on hot paths: the watcher drops pending logs that carry no block number
  instead of folding them as block 0 (which would reorder a commit against its
  settlement); the TFHE backend returns a typed error on a truncated header instead of
  panicking; the mesh throttle and the epoch lookup fail closed instead of `expect`ing;
  a closed shard-fetch semaphore surfaces as an error rather than a task panic.
- `hostile_headers_are_errors_never_panics` was not testing what its comment said.
  The header it builds is `b"4294967295\04294967295\0"`, and `\042` is the *octal*
  escape 0o42 (a quote) — not a NUL followed by "42" — so the decoder rejected the
  header one step earlier, on the non-digit, and the overflow the test is named after
  was never reached. Rewritten with `\x00`, which is unambiguous, and it now exercises
  the `rows × features` overflow it claims to.

### Site: mobile matrix — 7 devices, 3 real fixes

- Ran the site through emulated devices over CDP (iPhone SE/14, Pixel 7,
  Galaxy S8, 320px small, landscape, iPad — viewport, DPR, touch, mobile UA):
  49 combinations measured for document overflow, tiny tap targets, burger
  menu and section-bar visibility.
- `security.html` overflowed the document on every portrait phone: the report
  notice holds the unbreakable advisories URL (485px at 320–412px viewports).
  `.notice` now wraps long words; document width equals the viewport on all
  devices, verified by re-running the matrix.
- Footer links were 14–16px tap targets; they now have vertical padding
  (33px, above the 24px minimum), measured live.
- The section bar hid at 900px, so landscape phones lost it; the breakpoint
  is 700px now, verified shown on 844px landscape and hidden on small
  portraits.

### Contracts/SDK: VRF-committee ABI drift fixed, CI hole closed

- `packages/sdk` was failing its own gate: 2 of 60 smoke tests red
  ("CipherTask/PaymentVault ABI matches the compiled artifact"). The SDK's
  embedded ABIs predated PR #38 and missed the whole VRF dispute committee
  (`NotCommitteeMember`, `committeeSeed`, `committeeSize`, `isCommitteeEligible`).
  Nothing extraneous — a pure lag. Re-ran the repo's own
  `scripts/export-abi.cjs` (+150/−1 lines across the two JSONs, the single
  deletion is the JSON tail) and the suite is green again.
- Why CI didn't catch it: `sdk.yml` only watched `packages/sdk/**`, while the
  drift came from `packages/contracts/src/**` in #38 — and `contracts.yml`
  never runs the SDK suite. `sdk.yml` paths now include
  `packages/contracts/src/**`, so a Solidity change with a stale `src/abi/`
  snapshot fails there even when the SDK itself is untouched.
- Verified around the fix: contracts `hardhat test` 136 passing + vectors 2
  passing, bot 117/117, `cargo fmt --check` clean (compile itself still needs
  the full toolchain per `docs/05-honest-limitations.md` §8), both touched
  workflows parse as YAML.

### Site: pool shares labelled as the devnet example, not constants

- `8000 / 1500 / 500` were shown as protocol constants (home `03 / PRO`,
  protocol `pro.stxp`), but `TaskParamsLib.requireShares` only enforces that
  the three per-task shares sum to BPS — the numbers are the devnet-script and
  docs example. Both strings now say so in RU and EN; the formulas keep the
  concrete numbers, now introduced as the example.

### Site: honest lab guards and a copy fallback that always answers

- The lab's "calculate payouts" bench reported success on empty state:
  `doSettle()` is a pure function of the budget and had no guards, so clicking
  it first thing printed "matches CipherTask._settle" over zeroes. It now
  refuses with the existing `lab.m.noepoch` message until at least one epoch
  ran — same for `doProof()`, whose old `prevLanes.length` check could never
  fire (lanes are zero-initialised, never empty). Both verified live: refusal
  on empty state, success after `runAll`, refusal again after epoch reset.
- The copy button could leave the user with no feedback at all: if
  `clipboard.writeText` neither resolves nor rejects (a hanging permission),
  the label never flipped. It now races the promise against a 1.5s timer that
  falls back to the textarea + `execCommand` path. Verified with an async
  probe: label flips to the confirmation and restores itself.

### Site: menu announces the current page, theme tooltip follows the language

- The active menu item now carries `aria-current="page"`. The `active` class
  was visible to sighted users but silent to screen readers; `nav.mjs` rule 3
  asserts it sits on exactly one link per page and points at that page
  (verified against a copy with the attribute removed — fails as expected).
- The theme button's tooltip was hardcoded English (`title="Theme"`) on Russian
  pages while its `aria-label` translated fine. `app.js` now sets the title
  from the same `theme.toggle` key on load and on every language switch
  (RU "Переключить тему" / EN "Toggle theme", verified live).

### Site: the reading-mode switch is now reachable

- The site has advertised newcomer / pro modes from the start, but the buttons
  existed only inside the lab: `data-mode-btn` appeared in `playground.html` and
  nowhere else. Landing straight on the home page meant `03 / PRO` — the
  constants table — was simply unreachable, and there was no way to leave pro
  mode either. The switch now sits in the masthead of the four pages whose
  content actually changes with it (home, protocol, security, license) and
  shares the existing `shroud-mode` key in localStorage, so the choice follows
  the visitor across the site. Pipeline and practice deliberately have no
  switch: nothing on them is gated by the mode, and a dead control is worse
  than none.
- Masthead spacing tightened (segment padding 10→8px, gaps 12→10 and 6→4) so
  brand + seven menu items + theme + language + mode still fit on one row at
  1280px: measured 1084px of the 1132px available in the worst case (Russian),
  939px in English.
- `aria-label` on the language and mode groups was hardcoded English
  ("language", "mode") on Russian pages; both are translated now.
- `nav.mjs` gained the invariant that made this class of bug visible: a page with
  `only-new` / `only-pro` blocks must have a mode switch, and a page with a mode
  switch must have such blocks. Verified in both directions on a throwaway copy.

### Site: motion and small tools (no new dependencies, no build step)

- **Animations**, all of them decorative and reversible: hero elements rise in
  sequence once on load; every section header draws a short accent tick when it
  enters the viewport; the arrows in Diagram A flow along their own direction;
  the status ticker now actually scrolls (seamless, pauses on hover); cards lift
  and light up their border on hover/focus; menu underlines grow from the left.
- **Small tools**: an auto-built section bar under the masthead with a scroll-spy
  (pages with 3+ sections: home, security, protocol) — every section
  also gets a stable `id`, so `#sec-3` style deep links work and respect the
  existing `scroll-margin-top`; a copy button on every `pre.code` block (labels
  follow the language, hidden on touch devices where hover does not exist); a
  2px scroll-progress line and a "back to top" button.
- The section bar is `sticky` and sits in the flow right after the masthead
  rather than being `fixed`. Fixed positioning put it *under* the header: the
  header does not start at the top of the viewport (`.topbar` is above it) and
  it covers the bar with its own background, which left an empty frame on
  screen. Found by rendering the site and looking at the result.
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
- New `web/tests/nav.mjs` (same two places): every page present in the menu,
  identical menu order on all seven pages, exactly one `active` item pointing
  at its own page, live `#anchors`, skip link present, every page reachable
  from the home. With seven hand-copied menus this was the regression most
  likely to happen; the test was itself verified against five deliberate
  breakages (missing menu item, lost `active`, extra page, dead anchor,
  unreachable page) and caught all five.
- Section ids are numbered without gaps now, so `#sec-3` is the third section
  of the page on every page.
- `docs/shots/*.png` re-rendered from the current site: `home.png` showed the
  pre-split single-page home, `mobile.png` and `protocol.png` still had the
  five-item menu. Captured with headless Chrome at the same sizes as before
  (1440×960, 1440×2600, 1440×2400, 500×1000).

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
