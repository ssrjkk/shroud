/**
 * Per-chat watchlist and alert overrides.
 *
 * The state file is the only new disk surface in this feature. Two properties
 * matter and both are pinned here: a corrupt file never bricks the bot (it is
 * moved aside, the bot starts empty), and a save never leaves half JSON (tmp
 * file + rename, so a crash mid-write loses the update, not the file).
 */
import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { writeFile, readFile, readdir } from "node:fs/promises";
import {
  MAX_WATCHED_PER_CHAT,
  ALERT_KEYS,
  emptyState,
  normaliseState,
  loadWatchlist,
  saveWatchlist,
  createMemoryStore,
  addWatch,
  removeWatch,
  setAlertOverride,
  effectiveAlerts,
  passesWatchlist,
} from "../src/watchlist.js";

const tmpFile = () => path.join(os.tmpdir(), `watchlist-test-${process.pid}-${Math.random().toString(36).slice(2)}.json`);

test("addWatch validates, dedupes and caps", () => {
  const state = emptyState();
  assert.ok(!addWatch(state, 1, "abc").added);
  assert.ok(addWatch(state, 1, "42").added);
  assert.ok(!addWatch(state, 1, "42").added);
  assert.deepEqual(state.chats["1"].watched, ["42"]);
  assert.ok(removeWatch(state, 1, "42").removed);
  assert.ok(!removeWatch(state, 1, "42").removed);
  // Cap: the filter must stay small.
  const full = emptyState();
  for (let i = 1; i <= MAX_WATCHED_PER_CHAT; i++) addWatch(full, 1, String(i));
  const over = addWatch(full, 1, "999999");
  assert.ok(!over.added);
  assert.ok(over.reason.includes("full"));
});

test("alert overrides resolve against the global config", () => {
  const state = emptyState();
  const global = { commitMismatch: true, disputes: false, keyRotation: true };
  // Unset inherits.
  assert.deepEqual(effectiveAlerts(global, state, 1), { mm: true, disp: false, rot: true });
  setAlertOverride(state, 1, "disp", true);
  assert.equal(effectiveAlerts(global, state, 1).disp, true);
  // Clearing restores inheritance.
  setAlertOverride(state, 1, "disp", null);
  assert.equal(effectiveAlerts(global, state, 1).disp, false);
  assert.ok(!setAlertOverride(state, 1, "nope", true).ok);
  assert.ok(!setAlertOverride(state, 1, "mm", "yes").ok);
  assert.deepEqual([...ALERT_KEYS].sort(), ["disp", "mm", "rot"]);
});

test("passesWatchlist: empty means everything, otherwise only watched", () => {
  const state = emptyState();
  assert.ok(passesWatchlist(state, 1, "42"));
  assert.ok(passesWatchlist(state, 1, null)); // global alerts bypass the filter
  addWatch(state, 1, "42");
  assert.ok(passesWatchlist(state, 1, "42"));
  assert.ok(!passesWatchlist(state, 1, "43"));
  assert.ok(passesWatchlist(state, 2, "43")); // other chats unaffected
});

test("normaliseState drops garbage but keeps the good entries", () => {
  const state = normaliseState({
    chats: {
      1: { watched: ["42", "abc", 7, "42"], alerts: { mm: false, bogus: true } },
      "not-a-chat": { watched: ["1"] },
      2: null,
    },
  });
  assert.deepEqual(state.chats["1"].watched, ["42"]);
  assert.deepEqual(state.chats["1"].alerts, { mm: false });
  assert.ok(!("not-a-chat" in state.chats));
  assert.ok(!("2" in state.chats));
});

test("save/load round-trips through an atomic write", async () => {
  const file = tmpFile();
  const state = emptyState();
  addWatch(state, 7, "42");
  setAlertOverride(state, 7, "rot", false);
  await saveWatchlist(state, file);
  const back = await loadWatchlist(file);
  assert.deepEqual(back.chats["7"].watched, ["42"]);
  assert.deepEqual(back.chats["7"].alerts, { rot: false });
});

test("a corrupt file is backed up, never fatal", async () => {
  const file = tmpFile();
  await writeFile(file, "{not json");
  const back = await loadWatchlist(file);
  assert.deepEqual(back, emptyState());
  const dir = await readdir(path.dirname(file));
  assert.ok(dir.some((f) => f.startsWith(path.basename(file) + ".corrupt-")));
});

test("a missing file loads empty without touching disk", async () => {
  const back = await loadWatchlist(tmpFile());
  assert.deepEqual(back, emptyState());
});

test("memory store mirrors the file-store mutation contract", async () => {
  const store = createMemoryStore();
  assert.ok((await store.addWatch(1, "5")).added);
  assert.deepEqual(store.listWatched(1), ["5"]);
  await store.setAlert(1, "mm", false);
  assert.deepEqual(effectiveAlerts({ commitMismatch: true }, store.state(), 1).mm, false);
});
