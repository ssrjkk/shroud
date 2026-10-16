/**
 * Alert-loop identity: dedupe and cursor behaviour.
 *
 * The scanner is at-least-once (send, then persist). Without log identities a restart
 * re-alerts on the whole last window, and a reorg below the cursor is skipped forever.
 * These tests pin `eventUid`/`dedupeEvents` and the corrected `#decode` identity fields
 * (`transactionHash`+`index` — `#decode` once read `log.hash`, which does not exist on an
 * ethers v6 `Log`, so every rendered "tx …" was `undefined`).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { dedupeEvents, eventUid, commandFromVerdict } from "../src/index.js";

test("eventUid binds a log to its transaction hash and index", () => {
  assert.equal(eventUid({ txHash: "0xabc", logIndex: 3 }), "0xabc:3");
  assert.equal(eventUid({ txHash: "0xabc", logIndex: 0 }), "0xabc:0");
});

test("eventUid is null when the log carries no identity, and such logs always surface", () => {
  assert.equal(eventUid({}), null);
  assert.equal(eventUid({ txHash: "0xabc" }), null);
  assert.equal(eventUid({ logIndex: 1 }), null);
  const seen = new Set(["0xabc:3"]);
  const fresh = dedupeEvents([{}], seen);
  assert.equal(fresh.length, 1);
  assert.equal(seen.size, 1);
});

test("dedupeEvents drops repeats and remembers everything observed", () => {
  const a = { txHash: "0xaaa", logIndex: 0 };
  const b = { txHash: "0xaaa", logIndex: 1 };
  const seen = new Set();
  assert.deepEqual(dedupeEvents([a, b], seen), [a, b]);
  assert.deepEqual(dedupeEvents([a, b], seen), []);
  // A reorged log has a different transaction hash: it is a different event.
  const aReorged = { txHash: "0xzzz", logIndex: 0 };
  assert.deepEqual(dedupeEvents([aReorged], seen), [aReorged]);
});

test("dedupeEvents is order-stable across interleaved scans", () => {
  const seen = new Set();
  const first = [{ txHash: "0x1", logIndex: 0 }, { txHash: "0x1", logIndex: 1 }];
  const second = [{ txHash: "0x1", logIndex: 1 }, { txHash: "0x1", logIndex: 2 }];
  assert.equal(dedupeEvents(first, seen).length, 2);
  const fresh = dedupeEvents(second, seen);
  assert.equal(fresh.length, 1);
  assert.equal(fresh[0].logIndex, 2);
});

test("commandFromVerdict trusts the guard's single parse over raw text", () => {
  // The guard accounted cost for `pool`; a hostile suffix in the raw text must not
  // change dispatch after the verdict is in.
  assert.deepEqual(commandFromVerdict({ action: "pass", name: "pool", args: [] }, "/pool injected args"), {
    name: "pool",
    args: [],
  });
  assert.deepEqual(
    commandFromVerdict({ action: "pass-tarpitted", name: "task", args: ["42"] }, "/task 42"),
    { name: "task", args: ["42"] }
  );
});

test("commandFromVerdict falls back to the raw parse only when the guard failed open", () => {
  assert.deepEqual(commandFromVerdict({ action: "pass" }, "/task 42"), { name: "task", args: ["42"] });
});
