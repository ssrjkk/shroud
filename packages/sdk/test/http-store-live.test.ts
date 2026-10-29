/**
 * Live SDK ↔ reference ShardStore integration tests.
 *
 * Everything else in the SDK suite fakes the DA with an in-memory store or a stubbed
 * `fetch`. This file is the one place the real production pair is exercised together:
 * the SDK's `HttpShardStore` client against the actual `infra/shardstore/server.mjs`.
 *
 * That pairing has to be proven rather than assumed, because the two sides set their
 * own conventions autonomously:
 *   - the reference server addresses objects by `keccak256(payload)` (server.mjs computes
 *     `cid = keccak(payload)` on PUT) and serves `Range` as 206 + `Content-Range`;
 *   - the SDK client derives the on-chain pin locally (`keccak256`), validates whatever
 *     cid the store echoes, and requires the 206 `Content-Range` envelope to trust a
 *     range answer.
 * A one-sided test cannot catch a drift between the two; each side's unit tests only
 * prove it against its own mocks. This one runs the server as a real child process and
 * drives it through the actual `HttpShardStore`, with the same auth bearer the production
 * deployment uses.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { HttpShardStore } from "../dist/index.js";

const HARNESS_DIR = dirname(fileURLToPath(import.meta.url));
// packages/sdk/test → repo root, then into infra/shardstore. `npm test` builds the SDK
// first, and CI checks out the whole repo, so the reference server source is always here.
const SERVER = join(HARNESS_DIR, "../../../infra/shardstore/server.mjs");
const PORT = 18083;
const BASE = `http://127.0.0.1:${PORT}`;
const TOKEN = "live-sdk-contract-token-1a2b3c4d";

let child: ChildProcess | null = null;

// The spawned reference server is test scaffolding, not a leftover: kill it when the
// file's tests finish so the runner can exit. Without this the suite prints 5 green
// checks and then hangs forever holding the child handle — green output, red CI.
after(() => {
  try {
    child?.kill();
  } catch {
    // Already dead: nothing to clean up.
  }
  child = null;
});

async function startServer(extra: Record<string, string> = {}): Promise<void> {
  const { AUTH_TOKEN: _drop, ...clean } = process.env;
  child = spawn("node", [SERVER], {
    env: { ...clean, PORT: String(PORT), AUTH_TOKEN: TOKEN, ...extra },
    stdio: ["ignore", "ignore", "ignore"],
  });
  // The child must not keep the test runner alive after the last assertion: `after`
  // below kills it, and `unref` is the belt-and-braces so a missed kill can never
  // wedge `npm test` (or CI) into a silent hang on a green suite.
  child.unref();
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) {
      child.kill();
      throw new Error("reference shardstore did not become healthy in time");
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

test("SDK HttpShardStore round-trips against the real reference server", async () => {
  await startServer();
  const store = new HttpShardStore(BASE, { authToken: TOKEN });
  const payload = new TextEncoder().encode(
    `live-contract-shard-${Date.now()}-${Math.random().toString(36).slice(2)}`
  );
  const expectedCid = ethers.keccak256(payload);

  // PUT: the server addresses by keccak, matches the local digest the SDK derives.
  const { cid, digest } = await store.put(payload);
  assert.equal(cid, expectedCid, "reference server addresses objects by keccak256(payload)");
  assert.equal(digest, expectedCid, "the on-chain pin is the locally derived keccak digest");

  // GET: fetch the exact bytes back by the cid the server echoed.
  const got = await store.get(cid);
  assert.deepEqual(Uint8Array.from(got), payload);

  // getVerified: the node's path — re-hash the fetched bytes against the committed digest.
  const verified = await store.getVerified(cid, digest);
  assert.deepEqual(Uint8Array.from(verified), payload);

  // getRange: the server must answer 206 + Content-Range for the window to be trusted.
  const sliced = await store.getRange(cid, 4, 3);
  assert.deepEqual(Uint8Array.from(sliced), payload.slice(4, 7));
});

test("the reference server rejects the SDK client without (or with a bad) write token", async () => {
  // Reuse the running server from the previous test when present; start one if not.
  if (!child) await startServer();

  const body = new TextEncoder().encode("unauthenticated-write-must-fail");
  const bad = new HttpShardStore(BASE, { authToken: "wrong-token" });
  await assert.rejects(() => bad.put(body), /shard store PUT failed: 401/);

  const anonymous = new HttpShardStore(BASE);
  await assert.rejects(() => anonymous.put(body), /shard store PUT failed: 401/);
});

test("a store that lacks a requested object is a hard client-side error", async () => {
  // Reads are capability-based (the cid is the capability), so an absent cid is a 404,
  // surfaced as a rejection rather than a lie about what was committed.
  const store = new HttpShardStore(BASE, { authToken: TOKEN });
  const missing = ethers.keccak256(new TextEncoder().encode("never-put-this-shard"));
  await assert.rejects(() => store.get(missing), /shard store GET failed for .*: 404/);
});

test("getVerified refuses bytes that do not match the committed digest", async () => {
  const store = new HttpShardStore(BASE, { authToken: TOKEN });
  const payload = new TextEncoder().encode("integrity-must-hold");
  const { cid } = await store.put(payload);
  const wrong = ethers.keccak256(new TextEncoder().encode("some-other-bytes"));
  await assert.rejects(
    () => store.getVerified(cid, wrong),
    /failed integrity check: expected .* computed .*/
  );
});

test("an out-of-window range is a 416 the SDK refuses, not a silent wrong slice", async () => {
  const store = new HttpShardStore(BASE, { authToken: TOKEN });
  const payload = new TextEncoder().encode("short-object");
  const { cid } = await store.put(payload);
  await assert.rejects(
    () => store.getRange(cid, payload.byteLength + 5, 3),
    /shard store range GET failed for .*: 416/
  );
});
