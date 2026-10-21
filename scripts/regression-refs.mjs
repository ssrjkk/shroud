// scripts/regression-refs.mjs — the threat model's regression references must be real.
//
// Every finding carries the test that pins it. That reference is the whole
// point of the finding: an auditor who cannot find the test has to take the
// finding on trust, and a test that was renamed leaves a reference that points
// at nothing while looking exactly as authoritative.
//
// The check: the file a finding names must exist, and it must contain the
// quoted test name. A paraphrase is not a reference - the name is quoted
// verbatim, so it can be grepped.
//
// Run from the repository root:  node scripts/regression-refs.mjs
// No dependencies.
import { readFileSync } from "fs";
import { execFileSync } from "child_process";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MODEL = join(ROOT, "docs", "04-threat-model.md");

/** Collapse the line breaks a wrapped citation carries. */
const flat = (s) => s.replace(/\s+/g, " ").trim();

/**
 * The same comparison, ignoring how a language spells a word.
 *
 * A Rust test is named in snake_case and a JavaScript one in spaces; a citation
 * may quote either spelling, and both name the same test.
 */
const comparable = (s) => flat(s).replace(/[_\-]+/g, " ").toLowerCase();

const text = flat(readFileSync(MODEL, "utf8"));

// `Regression: `file` - *"name"*` (the dash is an em dash in the document).
const REF = /Regression:\s*`([^`]+)`\s*[—–-]\s*\*"([^"]+)"\*/g;

const tracked = new Set(
  execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" })
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
);

const problems = [];
let checked = 0;

for (const m of text.matchAll(REF)) {
  checked++;
  const file = m[1].trim();
  const name = flat(m[2]);
  if (!tracked.has(file)) {
    problems.push(`the named file does not exist: ${file}`);
    continue;
  }
  const source = comparable(readFileSync(join(ROOT, file), "utf8"));
  if (!source.includes(comparable(name))) {
    problems.push(`${file} does not contain the test "${name}"`);
  }
}

if (problems.length) {
  console.log("FAIL: the threat model's regression references are stale:");
  for (const p of problems) console.log("  " + p);
  console.log(`\n${problems.length} stale reference(s) of ${checked}.`);
  process.exit(1);
}
console.log(`REGRESSION-REFS OK: all ${checked} regression references name a test that exists`);
