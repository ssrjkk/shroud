/**
 * Callback routing and pool paging.
 *
 * Buttons must never trigger work the equivalent command would refuse: an
 * unknown payload answers with a hint and zero RPC, and a page past the end
 * clamps instead of walking the chain. The stub chain records every call so
 * a button that fires an unexpected read fails here, not in a chat.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { poolPage, POOL_PAGE_SIZE } from "../src/chain.js";
import { parseCallback } from "../src/keyboards.js";
import { createMemoryStore } from "../src/watchlist.js";
import { createHandlers, routeCallback, replyText } from "../src/index.js";

const view = (id) => ({
  taskId: String(id),
  status: 2,
  statusName: "Collecting",
  budget: 1n,
  locked: 0n,
  contributors: 1,
  shards: 1,
  nextEpoch: 0,
  ctRoot: "0x",
  ctRootSet: false,
  params: null,
});

function stubChain(count) {
  const calls = [];
  return {
    calls,
    taskCount: async () => {
      calls.push("taskCount");
      return count;
    },
    task: async (id) => {
      calls.push(["task", id]);
      return view(id);
    },
    commitsForEpoch: async () => [],
    epochWinner: async () => null,
    disputeQuorum: async () => ({ need: 3, have: 0 }),
    chainId: async () => 31337,
    blockNumber: async () => 100,
    networkParams: async () => null,
  };
}

const toast = () => {
  const seen = [];
  return { seen, onToast: async (t) => seen.push(t) };
};

test("poolPage windows newest-first and clamps out-of-range pages", () => {
  assert.equal(POOL_PAGE_SIZE, 12);
  const first = poolPage(30, 1);
  assert.deepEqual(first, { ids: [30n, 29n, 28n, 27n, 26n, 25n, 24n, 23n, 22n, 21n, 20n, 19n], page: 1, pages: 3, total: 30 });
  const last = poolPage(30, 3);
  assert.deepEqual(last.ids[0], 6n);
  assert.equal(last.ids.length, 6);
  // Past the end clamps to the last page; garbage clamps to the first.
  assert.equal(poolPage(30, 99).page, 3);
  assert.equal(poolPage(30, "abc").page, 1);
  assert.deepEqual(poolPage(0, 5), { ids: [], page: 1, pages: 1, total: 0 });
});

test("routeCallback pages the pool without re-reading the count twice", async () => {
  const chain = stubChain(25);
  const out = await routeCallback(parseCallback("p:2"), { chain, config: {}, store: createMemoryStore(), chatId: 1 });
  assert.ok(out.text.includes("page 2/3"));
  assert.ok(out.markup.inline_keyboard.at(-1).some((b) => b.callback_data === "p:1"));
  assert.ok(out.markup.inline_keyboard.at(-1).some((b) => b.callback_data === "p:3"));
  assert.equal(chain.calls.filter((c) => c === "taskCount").length, 1);
});

test("routeCallback renders a task with its keyboard", async () => {
  const chain = stubChain(50);
  const out = await routeCallback(parseCallback("t:42"), { chain, config: {}, store: createMemoryStore(), chatId: 1 });
  assert.ok(out.text.includes("Task"));
  assert.ok(out.markup.inline_keyboard[0].some((b) => b.text === "☆ watch"));
});

test("watch/unwatch buttons flip state and toast", async () => {
  const store = createMemoryStore();
  const chain = stubChain(50);
  const t = toast();
  const watched = await routeCallback(parseCallback("w:42"), { chain, config: {}, store, chatId: 1, ...t });
  assert.ok(t.seen.some((m) => m.includes("watching #42")));
  assert.ok(watched.markup.inline_keyboard[0].some((b) => b.text === "★ unwatch"));
  const unwatched = await routeCallback(parseCallback("u:42"), { chain, config: {}, store, chatId: 1, ...t });
  assert.ok(unwatched.markup.inline_keyboard[0].some((b) => b.text === "☆ watch"));
});

test("alert toggles flip the per-chat flag and toast", async () => {
  const store = createMemoryStore();
  const chain = stubChain(0);
  const t = toast();
  const global = { commitMismatch: true, disputes: true, keyRotation: true };
  const out = await routeCallback(parseCallback("a:disp"), { chain, config: { alerts: global }, store, chatId: 1, ...t });
  assert.ok(t.seen.some((m) => m.includes("disputes off")));
  assert.ok(out.text.includes("❌ disputes"));
});

test("status refresh re-renders with a keyboard", async () => {
  const chain = stubChain(0);
  const out = await routeCallback(parseCallback("s"), { chain, config: {}, store: createMemoryStore(), chatId: 1 });
  assert.ok(out.text.includes("status") || out.text.includes("Status"));
  assert.equal(out.markup.inline_keyboard[0][0].callback_data, "s");
});

test("pool command accepts a page argument", async () => {
  const chain = stubChain(25);
  const { pool } = createHandlers(chain, {}, {});
  assert.ok(replyText(await pool([])).includes("page 1/3") || replyText(await pool([])).includes("Task pool"));
  assert.ok(replyText(await pool(["2"])).includes("page 2/3"));
});

test("watch commands validate before touching state", async () => {
  const { watch, unwatch, watchlist, alerts } = createHandlers(stubChain(0), { alerts: {} }, { store: createMemoryStore() });
  assert.ok(replyText(await watch([], { chatId: 1 })).includes("usage"));
  assert.ok(replyText(await watch(["abc"], { chatId: 1 })).includes("usage"));
  assert.ok(replyText(await watch(["7"], { chatId: 1 })).includes("watching task #7"));
  assert.ok(replyText(await watchlist([], { chatId: 1 })).includes("#7"));
  assert.ok(replyText(await unwatch(["7"], { chatId: 1 })).includes("stopped watching"));
  assert.ok(replyText(await alerts([], { chatId: 1 })).includes("Alerts for this chat"));
  // No store, no crash.
  const bare = createHandlers(stubChain(0), {}, {});
  assert.ok(replyText(await bare.watch(["7"], { chatId: 1 })).includes("unavailable"));
});
