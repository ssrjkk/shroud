/**
 * Callback router: every button resolves to a screen without a chain.
 *
 * The router is the one place where a typo'd callback prefix would silently
 * do nothing in production (Telegram just shows a spinner), so each verb is
 * pinned here against stub handlers and an ephemeral watch store.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createHandlers, handleCallback, POOL_PAGE_SIZE } from "../src/index.js";
import { WatchStore } from "../src/watchlist.js";

function stubChain() {
  return {
    chainId: async () => 31337,
    blockNumber: async () => 100,
    networkParams: async () => null,
    pendingRotation: async () => null,
    taskCount: async () => 20,
    task: async (id) => ({
      taskId: String(id), status: 2, statusName: "Collecting", budget: 1n, locked: 0n,
      contributors: 1, shards: 1, nextEpoch: 0, ctRoot: "0x", ctRootSet: false, params: null,
    }),
    commitsForEpoch: async () => [],
    epochWinner: async () => null,
    disputeQuorum: async () => null,
  };
}

const config = { alerts: { commitMismatch: true, disputes: true, keyRotation: true } };

async function setup() {
  const store = await WatchStore.open(mkdtempSync(join(tmpdir(), "shroud-cb-")));
  const handlers = createHandlers(stubChain(), config, store);
  return { store, handlers };
}

test("unknown buttons fail loudly, never silently", async () => {
  const { store, handlers } = await setup();
  const out = await handleCallback("zzz", { handlers, store, chatId: 1 });
  assert.ok(out.error);
});

test("pool paging converts 0-based buttons to 1-based pages", async () => {
  const { store, handlers } = await setup();
  const first = await handleCallback("p:0", { handlers, store, chatId: 1 });
  assert.ok(first.text.includes("Task pool"));
  assert.ok(first.keyboard.inline_keyboard.flat().some((b) => b.callback_data === "p:1"));
  const second = await handleCallback("p:1", { handlers, store, chatId: 1 });
  assert.ok(second.keyboard.inline_keyboard.flat().some((b) => b.callback_data === "t:12"));
  assert.equal(POOL_PAGE_SIZE, 8);
});

test("task, refresh and watch compose", async () => {
  const { store, handlers } = await setup();
  const t = await handleCallback("t:5", { handlers, store, chatId: 1 });
  assert.ok(t.text.includes("Task"));
  assert.ok(t.keyboard.inline_keyboard.flat().some((b) => b.callback_data === "w:5"));
  const w = await handleCallback("w:5", { handlers, store, chatId: 1 });
  assert.equal(w.toast, "watching #5");
  assert.deepEqual(store.watched(1), ["5"]);
  const w2 = await handleCallback("w:5", { handlers, store, chatId: 1 });
  assert.equal(w2.toast, "unwatched #5");
  const r = await handleCallback("r:s", { handlers, store, chatId: 1 });
  assert.ok(r.text.includes("Shroud"));
});

test("alert toggles cycle null → false → true → null", async () => {
  const { store, handlers } = await setup();
  const seq = [];
  for (let i = 0; i < 3; i++) {
    const out = await handleCallback("a:d", { handlers, store, chatId: 1 });
    seq.push(out.toast);
  }
  assert.deepEqual(seq, ["disputes: off", "disputes: on", "disputes: following env"]);
});

test("watch commands validate input and clear cleanly", async () => {
  const { store, handlers } = await setup();
  assert.ok((await handlers.watch([], 1)).text.includes("usage"));
  assert.ok((await handlers.unwatch([], 1)).text.includes("usage"));
  await handlers.watch(["4"], 1);
  await handlers.watch(["6"], 1);
  const list = await handlers.watchlist([], 1);
  assert.ok(list.text.includes("#4") && list.text.includes("#6"));
  const cleared = await handlers.unwatch(["all"], 1);
  assert.ok(cleared.text.includes("cleared"));
  assert.deepEqual((await handlers.watchlist([], 1)).text.includes("#4"), false);
});
