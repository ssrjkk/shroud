/**
 * Per-chat watch state: toggles, overrides, routing, persistence.
 *
 * Preferences must survive restarts but must never take the bot down: every
 * test below also covers the corrupt-file and missing-file paths, because a
 * chat losing its watchlist is annoying while a chat losing the bot is an
 * outage.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { WatchStore, targetChats, ALERT_FAMILIES } from "../src/watchlist.js";

async function freshStore(seed) {
  const dir = mkdtempSync(join(tmpdir(), "shroud-watch-"));
  if (seed !== undefined) {
    writeFileSync(join(dir, "watchlist.json"), typeof seed === "string" ? seed : JSON.stringify(seed));
  }
  return WatchStore.open(dir);
}

test("toggleWatch adds, removes, sorts; garbage ids rejected", async () => {
  const s = await freshStore();
  assert.deepEqual(s.watched(1), []);
  assert.equal(await s.toggleWatch(1, "9"), true);
  assert.equal(await s.toggleWatch(1, "3"), true);
  assert.deepEqual(s.watched(1), ["3", "9"], "sorted, strings");
  assert.equal(await s.toggleWatch(1, "3"), false);
  assert.deepEqual(s.watched(1), ["9"]);
  await assert.rejects(() => s.toggleWatch(1, "abc"), /decimal integers/);
  await assert.rejects(() => s.setAlert(1, "nope", true), /unknown alert family/);
  await assert.rejects(() => s.setAlert(1, "disputes", "yes"), /true, false or null/);
});

test("overrides win, env is the default, null follows env", async () => {
  const s = await freshStore();
  const env = { commitMismatch: true, disputes: false, keyRotation: true };
  assert.equal(s.effective(7, "disputes", env.disputes), false);
  await s.setAlert(7, "disputes", true);
  assert.equal(s.effective(7, "disputes", env.disputes), true);
  await s.setAlert(7, "disputes", null);
  assert.equal(s.effective(7, "disputes", env.disputes), false);
  await s.setAlert(7, "keyRotation", false);
  assert.equal(s.effective(7, "keyRotation", env.keyRotation), false);
});

test("routing: empty watchlist is broadcast, key rotation ignores tasks", async () => {
  const s = await freshStore();
  await s.toggleWatch(1, "5");
  const env = { commitMismatch: true, disputes: true, keyRotation: true };
  // Chat 1 watches #5 only; chat 2 watches nothing.
  assert.deepEqual(
    targetChats({ allowedIds: [1, 2], store: s, env, taskId: "5", families: ["disputes"] }),
    [1, 2]
  );
  assert.deepEqual(
    targetChats({ allowedIds: [1, 2], store: s, env, taskId: "9", families: ["disputes"] }),
    [2],
    "watching chat skips unwatched tasks"
  );
  assert.deepEqual(
    targetChats({ allowedIds: [1, 2], store: s, env, taskId: null, families: ["keyRotation"] }),
    [1, 2],
    "rotations reach everyone"
  );
  await s.setAlert(2, "disputes", false);
  assert.deepEqual(
    targetChats({ allowedIds: [1, 2], store: s, env, taskId: "5", families: ["disputes"] }),
    [1],
    "per-chat override filters"
  );
});

test("corrupt and missing files degrade to an empty store", async () => {
  const bad = await freshStore("{not json");
  assert.deepEqual(bad.watched(1), []);
  const gone = await freshStore();
  assert.deepEqual(gone.snapshot(9), {
    watched: [],
    alerts: { commitMismatch: null, disputes: null, keyRotation: null },
  });
  assert.deepEqual(ALERT_FAMILIES, ["commitMismatch", "disputes", "keyRotation"]);
});

test("state survives a reopen (atomic write, tmp + rename)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "shroud-watch-"));
  const a = await WatchStore.open(dir);
  await a.toggleWatch(3, "11");
  await a.setAlert(3, "disputes", false);
  const b = await WatchStore.open(dir);
  assert.deepEqual(b.watched(3), ["11"]);
  assert.equal(b.effective(3, "disputes", true), false);
});
