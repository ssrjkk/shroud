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
import { dedupeEvents, eventUid, commandFromVerdict, sendReply, shouldDeliverAlert, loadCursor, saveCursor, redactRpcUrl, MAX_SEEN_DIGESTS, createDispatcher } from "../src/index.js";
import { emptyState, addWatch, setAlertOverride } from "../src/watchlist.js";
import os from "node:os";
import path from "node:path";
import { writeFile } from "node:fs/promises";

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

test("sendReply goes through the bounded queue, never raw sendMessage", async () => {
  const calls = [];
  const stub = {
    sendQueued: async (...a) => {
      calls.push(["queued", ...a]);
      return {};
    },
    sendMessage: async (...a) => {
      calls.push(["raw", ...a]);
      return {};
    },
  };
  assert.equal(await sendReply(stub, 7, "hi", true), true);
  assert.deepEqual(calls, [["queued", 7, "hi", { parse_mode: "HTML" }]]);
  // Shed under load is visible (false), not silent.
  const shedder = { sendQueued: async () => ({ dropped: true }) };
  assert.equal(await sendReply(shedder, 7, "hi", false), false);
  // Handler-shaped replies carry their keyboard through the same queue.
  const kb = { inline_keyboard: [] };
  const viaMarkup = { sendQueued: async (...a) => (calls.push(["queued", ...a]), {}) };
  assert.equal(await sendReply(viaMarkup, 7, { text: "hi", markup: kb }, true), true);
  assert.deepEqual(calls.at(-1), ["queued", 7, "hi", { parse_mode: "HTML", reply_markup: kb }]);
});

/**
 * Delivery routing: the matrix behind the broadcast loop.
 *
 * A wrong row here is either a missed security alert (flag logic) or spam
 * (watchlist logic), so every combination of flag source × watchlist state ×
 * alert scope is pinned rather than left to inspection.
 */
const ALL_ON = { commitMismatch: true, disputes: true, keyRotation: true };

test("shouldDeliverAlert follows the global flags by default", () => {
  const state = emptyState();
  assert.ok(shouldDeliverAlert({ key: "disp", taskId: "42" }, ALL_ON, state, 1));
  assert.ok(shouldDeliverAlert({ key: "rot", taskId: null }, ALL_ON, state, 1));
  assert.ok(!shouldDeliverAlert({ key: "disp", taskId: "42" }, { ...ALL_ON, disputes: false }, state, 1));
  // Rotation still flows when only disputes are off.
  assert.ok(shouldDeliverAlert({ key: "rot", taskId: null }, { ...ALL_ON, disputes: false }, state, 1));
});

test("shouldDeliverAlert lets a chat override the global flags either way", () => {
  const state = emptyState();
  const off = { commitMismatch: false, disputes: false, keyRotation: false };
  assert.ok(!shouldDeliverAlert({ key: "mm", taskId: "1" }, off, state, 1));
  setAlertOverride(state, 1, "mm", true);
  assert.ok(shouldDeliverAlert({ key: "mm", taskId: "1" }, off, state, 1));
  // …and lets it silence what is globally loud.
  setAlertOverride(state, 1, "disp", false);
  assert.ok(!shouldDeliverAlert({ key: "disp", taskId: "1" }, ALL_ON, state, 1));
});

test("shouldDeliverAlert filters task alerts by watchlist, never rotation", () => {
  const state = emptyState();
  addWatch(state, 1, "42");
  assert.ok(shouldDeliverAlert({ key: "disp", taskId: "42" }, ALL_ON, state, 1));
  assert.ok(!shouldDeliverAlert({ key: "disp", taskId: "43" }, ALL_ON, state, 1));
  assert.ok(!shouldDeliverAlert({ key: "mm", taskId: "43" }, ALL_ON, state, 1));
  // Rotation is global: the watchlist never gates it.
  assert.ok(shouldDeliverAlert({ key: "rot", taskId: null }, ALL_ON, state, 1));
  // Other chats keep the default everything-filter.
  assert.ok(shouldDeliverAlert({ key: "disp", taskId: "43" }, ALL_ON, state, 2));
});

test("shouldDeliverAlert drops unknown alert keys instead of broadcasting", () => {
  assert.ok(!shouldDeliverAlert({ key: "nope", taskId: "1" }, ALL_ON, emptyState(), 1));
});

/**
 * Cursor persistence, now including the mismatch-digest map.
 *
 * The regression this pins: digests lived in a static in-memory Map, so every
 * mismatch whose two commits straddled a restart was silently missed. Files
 * written before digests existed still load (empty map, not a crash).
 */
const cursorFile = () => path.join(os.tmpdir(), `cursor-test-${process.pid}-${Math.random().toString(36).slice(2)}.json`);

test("cursor round-trips digests across a restart", async () => {
  const file = cursorFile();
  const digests = new Map([["1/2/0xabc", "0xdigest1"]]);
  await saveCursor(123, new Set(["0xabc:3"]), digests, file);
  const back = await loadCursor(1000, 100, file);
  assert.equal(back.cursor, 123);
  assert.ok(back.seen.has("0xabc:3"));
  assert.equal(back.digests.get("1/2/0xabc"), "0xdigest1");
});

test("cursor loads files written before digests existed", async () => {
  const file = cursorFile();
  await writeFile(file, JSON.stringify({ cursor: 50, seen: ["0x1:0"] }));
  const back = await loadCursor(1000, 100, file);
  assert.equal(back.cursor, 50);
  assert.ok(back.digests instanceof Map);
  assert.equal(back.digests.size, 0);
});

test("cursor trims digests to the cap instead of growing without bound", async () => {
  const file = cursorFile();
  const digests = new Map(Array.from({ length: MAX_SEEN_DIGESTS + 10 }, (_, i) => [`k/${i}`, `v${i}`]));
  await saveCursor(1, new Set(), digests, file);
  const back = await loadCursor(1000, 100, file);
  assert.equal(back.digests.size, MAX_SEEN_DIGESTS);
});

test("cursor starts fresh on a missing file", async () => {
  const back = await loadCursor(1000, 200, cursorFile());
  assert.deepEqual([back.cursor, back.seen.size, back.digests.size], [800, 0, 0]);
});

/**
 * Poll-loop dispatcher: bounded concurrency with isolated failures.
 *
 * Sequential handling stalled every chat behind one slow RPC; unbounded
 * fan-out would amplify one burst into the whole RPC budget. The cap in the
 * middle is pinned here: never more than maxInFlight jobs at once, every job
 * settled, a rejection visible only to its own caller.
 */
test("dispatcher caps in-flight jobs", async () => {
  const d = createDispatcher({ maxInFlight: 2 });
  let live = 0;
  let peak = 0;
  const slow = async () => {
    live++;
    peak = Math.max(peak, live);
    await new Promise((r) => setTimeout(r, 10));
    live--;
    return live;
  };
  await Promise.all(Array.from({ length: 6 }, () => d.dispatch(slow)));
  assert.equal(peak, 2);
  assert.equal(d.inFlight, 0);
});

test("dispatcher holds the cap when jobs settle on the same tick", async () => {
  // Regression: waiters woken together by one settling job used to all pass
  // the free-slot check before any of them added theirs (TOCTOU overshoot).
  // Zero-delay jobs settle on the same microtask drain — the worst case.
  const d = createDispatcher({ maxInFlight: 2 });
  let live = 0;
  let peak = 0;
  const instant = async () => {
    live++;
    peak = Math.max(peak, live);
    await Promise.resolve();
    live--;
  };
  await Promise.all(Array.from({ length: 8 }, () => d.dispatch(instant)));
  assert.ok(peak <= 2, `cap overshot: peak ${peak}`);
  assert.equal(d.inFlight, 0);
});

test("dispatcher isolates failures and keeps serving", async () => {
  const d = createDispatcher({ maxInFlight: 2 });
  await assert.rejects(() => d.dispatch(async () => {
    throw new Error("boom");
  }), /boom/);
  assert.equal(await d.dispatch(async () => "ok"), "ok");
  assert.equal(d.inFlight, 0);
});

test("dispatcher rejects a non-positive cap", () => {
  assert.throws(() => createDispatcher({ maxInFlight: 0 }), /positive integer/);
  assert.throws(() => createDispatcher({ maxInFlight: 1.5 }), /positive integer/);
});

test("the RPC URL is never logged with its key", () => {
  // Managed RPC URLs carry the provider's API key in the path, so printing the URL as
  // it is writes the key into stdout and into whatever collects it. The endpoint stays
  // visible - the operator has to know *which* one - and only the secret is masked.
  const url = "https://eth-mainnet.g.alchemy.com/v2/SuperSecretKey123";
  const redacted = redactRpcUrl(url);
  assert.ok(!redacted.includes("SuperSecretKey123"), `the key survived: ${redacted}`);
  // Хост сравнивается целиком, а не подстрокой: «alchemy.com» может встретиться
  // где угодно внутри URL, и проверка подстрокой прошла бы и для чужого хоста
  // («https://evil.test/?x=alchemy.com»). Разбор URL сравнивает именно host.
  assert.equal(
    new URL(redacted).hostname,
    "eth-mainnet.g.alchemy.com",
    `the endpoint must stay visible: ${redacted}`,
  );
  // Nothing else leaks either.
  assert.ok(!redacted.includes("v2/SuperSecretKey123"));
  // A URL we cannot parse is not printed at all.
  assert.ok(!redactRpcUrl("not a url").includes("not a url"));
});
