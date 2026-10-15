/**
 * Keyboards and the callback protocol.
 *
 * Buttons are tapped, not read, so what matters is: every callback parses
 * back into a known verb, every payload fits Telegram's 64-byte cap, and
 * paging never offers a page that does not exist.
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  ALERT_KEYS,
  parseCallback,
  poolKeyboard,
  taskKeyboard,
  statusKeyboard,
  alertsKeyboard,
  openTaskKeyboard,
  openStatusKeyboard,
  watchlistKeyboard,
} from "../src/keyboards.js";

function allData(kb) {
  assert.ok(kb?.inline_keyboard?.length, "keyboard is not empty");
  return kb.inline_keyboard.flat().map((b) => b.callback_data);
}

test("every callback parses back into a verb, foreign data is rejected", () => {
  assert.deepEqual(parseCallback("p:2"), { kind: "pool", page: 2 });
  assert.deepEqual(parseCallback("t:41"), { kind: "task", id: "41" });
  assert.deepEqual(parseCallback("r:s"), { kind: "refresh", view: "s" });
  assert.deepEqual(parseCallback("r:p:0"), { kind: "refresh", view: "p:0" });
  assert.deepEqual(parseCallback("r:t:7"), { kind: "refresh", view: "t:7" });
  assert.deepEqual(parseCallback("w:7"), { kind: "watch", id: "7" });
  assert.deepEqual(parseCallback("a:m"), { kind: "alerts", key: "m" });
  for (const junk of [null, undefined, 42, "", "hello", "t:", "t:abc", "p:-1", "x:1", "t:1:2:3"]) {
    assert.equal(parseCallback(junk), null, JSON.stringify(junk));
  }
  assert.deepEqual(Object.keys(ALERT_KEYS).sort(), ["d", "k", "m"]);
});

test("pool keyboard pages without offering missing pages", () => {
  const ids = (n) => Array.from({ length: n }, (_, i) => ({ id: String(i + 1), label: "Collecting" }));
  const first = allData(poolKeyboard({ ids: ids(8), page: 0, pages: 3 }));
  assert.ok(first.includes("t:1") && first.includes("t:8"));
  assert.ok(first.includes("p:1") && first.includes("r:p:0"));
  assert.ok(!first.includes("p:-1"), "no previous on the first page");
  const last = allData(poolKeyboard({ ids: ids(8), page: 2, pages: 3 }));
  assert.ok(last.includes("p:1") && !last.includes("p:3"), "no next past the end");
  const single = allData(poolKeyboard({ ids: ids(2), page: 0, pages: 1 }));
  assert.ok(!single.some((d) => d.startsWith("p:")), "no pager for one page");
});

test("task keyboard always refreshes, never offers task 0", () => {
  const kb = allData(taskKeyboard({ id: "7", watched: false }));
  assert.ok(kb.includes("r:t:7") && kb.includes("t:6") && kb.includes("t:8"));
  assert.ok(kb.includes("w:7"));
  const first = allData(taskKeyboard({ id: "1", watched: true }));
  assert.ok(!first.includes("t:0"), "there is no task 0");
  assert.ok(first.includes("w:1"));
});

test("status, alerts, watchlist and deep-link keyboards fit the 64-byte cap", () => {
  const marks = [
    ...allData(statusKeyboard()),
    ...allData(alertsKeyboard({ m: null, d: false, k: true })),
    ...allData(watchlistKeyboard(["1", "22", "333"])),
    ...allData(openTaskKeyboard("12345678901234567890")),
    ...allData(openStatusKeyboard()),
  ];
  for (const d of marks) assert.ok(d.length <= 64, d);
  assert.equal(watchlistKeyboard([]), undefined, "empty watchlist needs no buttons");
});
