/**
 * TelegramBot transport behaviour: bounded send queue and constructor validation.
 * Network I/O itself is stubbed by hanging sendMessage — the queue mechanics must
 * hold without any real Telegram round-trip.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { TelegramBot } from "../src/telegram.js";

const silent = { warn() {}, log() {}, error() {} };

test("constructor validates its options", () => {
  assert.throws(() => new TelegramBot(""), /needs a token/);
  assert.throws(() => new TelegramBot("t", { maxQueued: 0 }), /maxQueued/);
  assert.throws(() => new TelegramBot("t", { maxQueued: 1.5 }), /maxQueued/);
  const bot = new TelegramBot("t", { log: silent });
  assert.equal(bot.droppedSends, 0);
});

test("sendQueued bounds memory: over-cap alerts drop with a counter", async () => {
  const bot = new TelegramBot("test-token", { maxQueued: 2, log: silent });
  bot.sendMessage = () => new Promise(() => {}); // hang forever: queue fills deterministically
  const p1 = bot.sendQueued(1, "a");
  const p2 = bot.sendQueued(2, "b");
  void p1;
  void p2;
  const dropped = await bot.sendQueued(3, "c");
  assert.deepEqual(dropped, { dropped: true });
  assert.equal(bot.droppedSends, 1);
  // Still bounded on repeat offenders.
  await bot.sendQueued(4, "d");
  assert.equal(bot.droppedSends, 2);
});
