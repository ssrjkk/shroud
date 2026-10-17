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
  for (const data of ["s", "p:1", "p:12", "t:42", "w:7", "u:7", "a:mm", "a:disp", "a:rot"]) {
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
    "x".repeat(65),
  ]) {
    assert.equal(parseCallback(bad), null, JSON.stringify(bad));
  }
});

test("encodeCallback refuses payloads past Telegram's 64-byte cap", () => {
  assert.equal(encodeCallback("t", "9".repeat(100)), null);
  assert.ok(encodeCallback("t", "42").length <= CALLBACK_LIMIT);
});

test("callback payloads the bot emits fit the 64-byte cap", () => {
  const big = "9".repeat(20);
  for (const data of [`p:1000`, `t:${big}`, `w:${big}`, `u:${big}`, "s", "a:disp"]) {
    assert.ok(data.length <= CALLBACK_LIMIT, data);
  }
});

test("callbackCost prices refreshes like their command equivalents", () => {
  assert.equal(callbackCost(parseCallback("p:2")), 15);
  assert.equal(callbackCost(parseCallback("t:42")), 5);
  assert.equal(callbackCost(parseCallback("s")), 4);
  assert.equal(callbackCost(parseCallback("w:1")), 1);
  assert.equal(callbackCost(parseCallback("a:mm")), 1);
  assert.equal(callbackCost(null), 1);
});

test("poolKeyboard batches tasks four per row with a pager", () => {
  const kb = poolKeyboard(["1", "2", "3", "4", "5"], 1, 3);
  assert.equal(kb.inline_keyboard.length, 3); // 4 + 1 + nav
  assert.equal(kb.inline_keyboard[0].length, 4);
  assert.deepEqual(
    kb.inline_keyboard[2].map((b) => b.text),
    ["next ›"]
  );
  const mid = poolKeyboard(["1"], 2, 3);
  assert.deepEqual(
    mid.inline_keyboard.at(-1).map((b) => b.text),
    ["‹ prev", "next ›"]
  );
  const single = poolKeyboard(["1"], 1, 1);
  assert.equal(single.inline_keyboard.length, 1); // no pager on one page
  assert.equal(poolKeyboard([], 1, 1), undefined); // nothing to press
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
  const kb = alertsKeyboard({ mm: true, disp: false, rot: true });
  const labels = kb.inline_keyboard[0].map((b) => b.text);
  assert.ok(labels.some((t) => t === "✅ mismatch"));
  assert.ok(labels.some((t) => t === "❌ disputes"));
  assert.ok(labels.some((t) => t === "✅ rotation"));
  assert.equal(kb.inline_keyboard[1][0].text, "status");
});

test("deep-link keyboards point at the right views", () => {
  const task = taskLinkKeyboard("42");
  assert.equal(task.inline_keyboard[0][0].callback_data, "t:42");
  const rot = rotationKeyboard();
  assert.equal(rot.inline_keyboard[0][0].callback_data, "s");
  assert.equal(statusKeyboard().inline_keyboard[0][0].callback_data, "s");
});
