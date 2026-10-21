// scripts/doc-refs.mjs — every file the documentation names must exist.
//
// A reference to a file that was renamed is a dead end for the reader who
// follows it, and a reference to a file that never existed is worse: it looks
// like evidence. The threat model's own regression references are the ones
// that matter most - an auditor who cannot find the test that pins a finding
// has to take the finding on trust.
//
// What is checked: every backtick-quoted path in the Markdown and HTML files
// that names a source file must resolve, either as a path in the tree or as a
// file name that exists somewhere in it. Runtime artifacts - files an operator
// or a release creates - are listed explicitly below, so the exception is
// visible rather than implicit.
//
// Run from the repository root:  node scripts/doc-refs.mjs
// No dependencies.
import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { dirname, join, relative, resolve, basename } from "path";
import { fileURLToPath } from "url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Directories that hold no sources worth referencing. */
const SKIP_DIRS = new Set([
  "node_modules",
  "target",
  ".git",
  "dist",
  "artifacts",
  "typechain",
  "evidence",
  "coverage",
]);

/**
 * Files that do not exist in the tree on purpose: runtime artifacts an
 * operator or a release produces. Each one is listed so the exception is
 * explicit.
 */
const RUNTIME_ARTIFACTS = new Set([
  "state/watchlist.json", // the bot's persisted watchlist
  "shroud.toml", // the node's operator-written config
  "shroud-report.json", // the evidence pack's output
  "RELEASE_NOTES.md", // the release notes the release process asks you to write
]);

/** Extensions that make a backtick-quoted token a file reference. */
const SOURCE_EXT = /\.(rs|sol|ts|js|mjs|toml|yml|yaml|json|sh|py|md)$/;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const all = walk(ROOT);
const names = new Set(all.map((p) => basename(p).toLowerCase()));
const docs = all.filter((p) => /\.(md|html)$/.test(p));

// A backtick-quoted token that names a source file.
const REF = /`([A-Za-z0-9_./-]+\.(?:rs|sol|ts|js|mjs|toml|yml|yaml|json|sh|py|md))`/g;

const missing = [];
for (const file of docs) {
  const text = readFileSync(file, "utf8");
  for (const m of text.matchAll(REF)) {
    const ref = m[1];
    if (ref.includes("*") || ref.includes("http")) continue;
    if (RUNTIME_ARTIFACTS.has(ref)) continue;
    // A path in the tree, or a file name that exists somewhere in it.
    if (existsSync(join(ROOT, ref))) continue;
    if (names.has(basename(ref).toLowerCase())) continue;
    const line = text.slice(0, m.index).split("\n").length;
    missing.push(`${relative(ROOT, file).replace(/\\/g, "/")}:${line}  ${ref}`);
  }
}

if (missing.length) {
  console.log("FAIL: the documentation names files that do not exist:");
  for (const m of missing) console.log("  " + m);
  console.log(`\n${missing.length} dead reference(s).`);
  process.exit(1);
}
console.log(
  `DOC-REFS OK: every file the ${docs.length} documentation file(s) name exists in the tree`
);
