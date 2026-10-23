/**
 * Inline keyboards and callback payloads.
 *
 * Buttons are the only new input surface in this feature: every press arrives
 * as attacker-influenced `callback_data`, so parsing is total (garbage in,
 * null out, never a throw) and every payload the bot itself emits must fit
 * Telegram's 64-byte cap.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  CALLBACK_LIMIT,
  isTaskId,
  encodeCallback,
  parseCallback,
  callbackCost,
  poolKeyboard,
  taskKeyboard,
  statusKeyboard,
  alertsKeyboard,
  taskLinkKeyboard,
  rotationKeyboard,
  prefsRow,
} from "../src/keyboards.js";

test("isTaskId accepts the same decimal shape the /task gate enforces", () => {
  assert.ok(isTaskId("42"));
  assert.ok(isTaskId("9".repeat(20)));
  assert.ok(!isTaskId(""));
  assert.ok(!isTaskId("abc"));
  assert.ok(!isTaskId("9".repeat(21)));
  assert.ok(!isTaskId("-1"));
  assert.ok(!isTaskId(42));
});

test("encode/parse round-trips every opcode", () => {
  for (const data of ["s", "h", "menu", "how", "proto", "set", "a", "lim", "help", "p:1", "p:12", "t:42", "w:7", "u:7", "a:mm", "a:disp", "a:rot", "a:tre", "a:ver", "A:mm", "A:tre", "A:ver", "m:s", "m:t:42", "m:p:2", "m:h", "m:a", "m:lim", "m:help", "m:r:buyer", "l:ru:s", "l:en:t:42", "l:ru:r:node", "l:en:lim", "r:buyer", "r:contrib", "r:node", "r:watch"]) {
    const parsed = parseCallback(data);
    assert.ok(parsed, `${data} parses`);
    assert.equal(encodeCallback(parsed.op, parsed.arg), data);
  }
});

test("parseCallback rejects garbage without throwing", () => {
  for (const bad of [
    "",
    null,
    undefined,
    42,
    "x:1",
    "p:",
    "p:0",
    "p:abc",
    "p:1001",
    "t:",
    "t:abc",
    "t:-1",
    "w:",
    "a:",
    "a:all",
    "s:1",
    "p:1:2",
    "m:",
    "m:x",
    "m:zzz",
    "l:xx",
    "l:ru",
    "l:ru:x",
    "l:en:p:0",
    "r:",
    "r:alien",
    "x".repeat(65),
  ]) {
    assert.equal(parseCallback(bad), null, JSON.stringify(bad));
  }
});

test("encodeCallback refuses payloads past Telegram's 64-byte cap", () => {
  assert.equal(encodeCallback("t", "9".repeat(100)), null);
  assert.ok(encodeCallback("t", "42").length <= CALLBACK_LIMIT);
});

test("prefsRow buttons name the target, like the language switch", () => {
  // Both buttons promise where the tap lands: "EN" from a RU chat, and
  // "mode: geek" from simple mode. Showing the current mode instead once
  // flipped users into the mode they tried to leave.
  const [modeBtn, langBtn] = prefsRow("ru", "simple", "s");
  assert.equal(modeBtn.text, "режим: гик");
  assert.equal(langBtn.text, "EN");
  const [backBtn] = prefsRow("en", "pro", "s");
  assert.equal(backBtn.text, "mode: simple");
});

test("mode/language toggles parse on long task ids", () => {
  // The old global 20-char arg cap rejected these while the task buttons
  // for the same ids parsed fine.
  const big = "9".repeat(20);
  assert.deepEqual(parseCallback(`m:t:${big}`), { op: "m", arg: `t:${big}` });
  assert.deepEqual(parseCallback(`l:en:t:${big}`), { op: "l", arg: `en:t:${big}` });
  assert.ok(parseCallback(`m:t:${big}`).arg.length + 2 <= CALLBACK_LIMIT);
});

test("callback payloads the bot emits fit the 64-byte cap", () => {
  const big = "9".repeat(20);
  for (const data of [`p:1000`, `t:${big}`, `w:${big}`, `u:${big}`, "s", "h", "a:disp", "m:t:42", "m:p:2", "l:ru:s", "l:en:t:42", "r:buyer"]) {
    assert.ok(data.length <= CALLBACK_LIMIT, data);
  }
});

test("callbackCost prices refreshes like their command equivalents", () => {
  assert.equal(callbackCost(parseCallback("p:2")), 15);
  assert.equal(callbackCost(parseCallback("t:42")), 5);
  assert.equal(callbackCost(parseCallback("s")), 4);
  assert.equal(callbackCost(parseCallback("w:1")), 5);
  assert.equal(callbackCost(parseCallback("u:1")), 5);
  assert.equal(callbackCost(parseCallback("a:mm")), 1);
  assert.equal(callbackCost(parseCallback("h")), 1);
  assert.equal(callbackCost(parseCallback("r:buyer")), 1);
  assert.equal(callbackCost(parseCallback("m:s")), 4);
  assert.equal(callbackCost(parseCallback("m:t:42")), 5);
  assert.equal(callbackCost(parseCallback("m:p:2")), 15);
  assert.equal(callbackCost(parseCallback("l:ru:s")), 4);
  assert.equal(callbackCost(parseCallback("l:en:t:42")), 5);
  assert.equal(callbackCost(parseCallback("A:mm")), 1);
  assert.equal(callbackCost(parseCallback("lim")), 1);
  assert.equal(callbackCost(parseCallback("help")), 1);
  assert.equal(callbackCost(null), 1);
});

test("poolKeyboard batches tasks four per row with a pager", () => {
  const kb = poolKeyboard(["1", "2", "3", "4", "5"], 1, 3);
  assert.equal(kb.inline_keyboard.length, 6); // tasks + nav + jumps + hub + prefs
  assert.equal(kb.inline_keyboard[0].length, 4);
  assert.deepEqual(
    kb.inline_keyboard[2].map((b) => b.text),
    ["next ›"]
  );
  const mid = poolKeyboard(["1"], 2, 3);
  const midNav = mid.inline_keyboard.find((r) => r.some((b) => b.callback_data === "p:1"));
  assert.deepEqual(
    midNav.map((b) => b.text),
    ["‹ prev", "next ›"]
  );
  const single = poolKeyboard(["1"], 1, 1);
  assert.equal(single.inline_keyboard.length, 3); // tasks + hub + prefs, no pager
  assert.ok(single.inline_keyboard.some((r) => r.some((b) => b.callback_data === "menu")));
  assert.equal(poolKeyboard([], 1, 1), undefined); // nothing to press
});

test("poolKeyboard jumps to first/last page on deep pools", () => {
  const texts = (kb) => kb.inline_keyboard.flat().map((b) => b.text);
  // Shallow pools: jumps would duplicate prev/next, so none.
  assert.ok(!texts(poolKeyboard(["1"], 2, 3)).some((x) => /[«»]/.test(x)));
  // Deep pool, first page: jump to last only.
  const first = poolKeyboard(["1"], 1, 5);
  assert.deepEqual(
    first.inline_keyboard.find((r) => r.some((b) => b.callback_data === "p:5")).map((b) => b.text),
    ["5 »"]
  );
  assert.ok(!texts(first).some((x) => x === "« 1"));
  // Deep pool, last page: jump to first only, and it fits the 64-byte cap.
  const last = poolKeyboard(["1"], 5, 5);
  const back = last.inline_keyboard.find((r) => r.some((b) => b.callback_data === "p:1"));
  assert.deepEqual(back.map((b) => b.text), ["« 1"]);
  // Middle of a deep pool: both jumps.
  const mid = poolKeyboard(["1"], 3, 5);
  assert.ok(texts(mid).includes("« 1") && texts(mid).includes("5 »"));
});

test("taskKeyboard flips the watch button and navigates", () => {
  const unwatched = taskKeyboard("42", { watched: false, prevId: "41", nextId: "43" });
  assert.ok(unwatched.inline_keyboard[0].some((b) => b.text === "☆ watch"));
  assert.ok(unwatched.inline_keyboard[0].some((b) => b.text === "⟳ refresh"));
  const watched = taskKeyboard("42", { watched: true });
  assert.ok(watched.inline_keyboard[0].some((b) => b.text === "★ unwatch"));
  assert.ok(watched.inline_keyboard[1].some((b) => b.text === "pool"));
  // Edge of the pool: no prev/next, only back to pool.
  assert.equal(watched.inline_keyboard[1].length, 1);
});

test("alertsKeyboard mirrors effective flags and links back to status", () => {
  const kb = alertsKeyboard({ mm: true, disp: false, rot: true, tre: false, ver: true });
  const labels = kb.inline_keyboard[0].map((b) => b.text);
  assert.ok(labels.some((t) => t === "✅ commit mismatch"));
  assert.ok(labels.some((t) => t === "❌ disputes"));
  assert.ok(labels.some((t) => t === "✅ rotation"));
  const second = kb.inline_keyboard[1].map((b) => b.text);
  assert.ok(second.some((t) => t.endsWith("treasury")));
  assert.ok(second.some((t) => t.endsWith("verifier")));
  assert.equal(kb.inline_keyboard[2][0].text, "status");
});

test("deep-link keyboards point at the right views", () => {
  const task = taskLinkKeyboard("42");
  assert.equal(task.inline_keyboard[0][0].callback_data, "t:42");
  const rot = rotationKeyboard();
  assert.equal(rot.inline_keyboard[0][0].callback_data, "s");
  assert.equal(statusKeyboard().inline_keyboard[0][0].callback_data, "s");
});
