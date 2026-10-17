/**
 * TelegramBot transport behaviour: bounded send queue and constructor validation.
 * Network I/O itself is stubbed by hanging sendMessage — the queue mechanics must
 * hold without any real Telegram round-trip.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { TelegramBot } from "../src/telegram.js";
import { truncateText, TELEGRAM_TEXT_LIMIT } from "../src/telegram.js";

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

test("truncateText cuts explicitly and always fits the cap", () => {
  assert.equal(truncateText("hi"), "hi");
  assert.equal(truncateText("x".repeat(TELEGRAM_TEXT_LIMIT)).length, TELEGRAM_TEXT_LIMIT);
  const cut = truncateText("y".repeat(5000));
  assert.ok(cut.length <= TELEGRAM_TEXT_LIMIT);
  assert.ok(cut.endsWith("(truncated)"));
});

/**
 * The callback API (answerCallbackQuery, editMessageText) speaks plain HTTP
 * like everything else, so `fetch` is stubbed at the transport edge: each
 * test records the method + payload Telegram would receive and answers with
 * canned JSON. No token, no network.
 */
function stubFetch(answer) {
  const calls = [];
  const restore = (() => {
    const orig = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      const payload = JSON.parse(init.body);
      calls.push({ method: url.split("/").at(-1), payload });
      return { json: async () => answer(payload) };
    };
    return () => {
      globalThis.fetch = orig;
    };
  })();
  return { calls, restore };
}

const ok = () => ({ ok: true, result: true });

test("answerCallbackQuery acks with the toast text", async () => {
  const net = stubFetch(ok);
  try {
    const bot = new TelegramBot("t", { log: silent });
    await bot.answerCallbackQuery("qid-1", "watching #42");
    assert.equal(net.calls.length, 1);
    assert.deepEqual(net.calls[0].payload, { callback_query_id: "qid-1", text: "watching #42" });
  } finally {
    net.restore();
  }
});

test("answerCallbackQuery truncates toast text to Telegram's limit", async () => {
  const net = stubFetch(ok);
  try {
    const bot = new TelegramBot("t", { log: silent });
    await bot.answerCallbackQuery("qid-1", "x".repeat(500));
    assert.ok(net.calls[0].payload.text.length <= 190);
  } finally {
    net.restore();
  }
});

test("answerCallbackQuery never throws: a failed ack must not fail the action", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("offline");
  };
  try {
    const bot = new TelegramBot("t", { log: silent });
    // Retries with backoff sleep — use a bot that fails fast by stubbing sleep? No:
    // network failure retries 3 times with 0.5/1/2s sleeps. Instead answer with
    // ok:false, which fails without retry.
    assert.equal(await bot.answerCallbackQuery("qid-1"), null);
  } finally {
    globalThis.fetch = orig;
  }
});

test("answerCallbackQuery maps a Telegram rejection to null, not a throw", async () => {
  const net = stubFetch(() => ({ ok: false, description: "query too old", error_code: 400 }));
  try {
    const bot = new TelegramBot("t", { log: silent });
    assert.equal(await bot.answerCallbackQuery("qid-old"), null);
  } finally {
    net.restore();
  }
});

test("editMessage posts chat, message id, text and markup", async () => {
  const net = stubFetch(ok);
  try {
    const bot = new TelegramBot("t", { log: silent });
    await bot.editMessage(7, 99, "hello", { parse_mode: "HTML", reply_markup: { inline_keyboard: [] } });
    assert.deepEqual(net.calls[0], {
      method: "editMessageText",
      payload: {
        chat_id: 7,
        message_id: 99,
        text: "hello",
        disable_web_page_preview: true,
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [] },
      },
    });
  } finally {
    net.restore();
  }
});

test("editMessage truncates past 4096 and maps rejection to null", async () => {
  const net = stubFetch(ok);
  try {
    const bot = new TelegramBot("t", { log: silent });
    await bot.editMessage(7, 99, "y".repeat(5000));
    assert.ok(net.calls[0].payload.text.length <= 4096);
  } finally {
    net.restore();
  }
  const bad = stubFetch(() => ({ ok: false, description: "message not modified", error_code: 400 }));
  try {
    const bot = new TelegramBot("t", { log: silent });
    // "message not modified" (identical refresh) is routine, not an error:
    // the caller falls back to a fresh message.
    assert.equal(await bot.editMessage(7, 99, "same"), null);
  } finally {
    bad.restore();
  }
});

test("getUpdates subscribes to messages and callback queries", async () => {
  const net = stubFetch(() => ({ ok: true, result: [] }));
  try {
    const bot = new TelegramBot("t", { log: silent });
    await bot.getUpdates(0, 30);
    assert.deepEqual(net.calls[0].payload.allowed_updates, ["message", "callback_query"]);
  } finally {
    net.restore();
  }
});
