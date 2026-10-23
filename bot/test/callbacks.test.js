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
import { parseCallback, callbackCost } from "../src/keyboards.js";
import { parseCommand, loadAbuseConfig, COMMAND_COST } from "../src/abuse.mjs";
import { createMemoryStore } from "../src/watchlist.js";
import { createHandlers, routeCallback, replyText, normalizeInput } from "../src/index.js";

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
  // The pager row sits above the mode/language row: find it by content, not position.
  const nav = out.markup.inline_keyboard.find((r) => r.some((b) => b.callback_data === "p:1"));
  assert.ok(nav && nav.some((b) => b.callback_data === "p:3"));
  // ...and the prefs row is last.
  assert.ok(out.markup.inline_keyboard.at(-1).some((b) => String(b.callback_data).startsWith("m:")));
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

test("lim/help callbacks render their screens with working toggles", async () => {
  const chain = stubChain(0);
  const store = createMemoryStore();
  const lim = await routeCallback(parseCallback("lim"), { chain, config: {}, store, chatId: 1 });
  assert.ok(lim.text.includes("Not externally audited") || lim.text.includes("Внешнего аудита"));
  // Mode/language toggles stay on the limits screen instead of jumping away.
  const limToggled = await routeCallback(parseCallback("m:lim"), { chain, config: {}, store, chatId: 1, langCode: "en" });
  assert.ok(limToggled.text.includes("Not externally audited") || limToggled.text.includes("Внешнего аудита"));
  const help = await routeCallback(parseCallback("help"), { chain, config: {}, store, chatId: 1 });
  assert.ok(help.text.includes("/limits"));
});

test("verifier toggles flip the per-chat flag with a toast", async () => {
  const store = createMemoryStore();
  const chain = stubChain(0);
  const t = toast();
  const global = { commitMismatch: true, disputes: true, keyRotation: true, treasury: true, verifierRotation: true };
  const out = await routeCallback(parseCallback("A:ver"), { chain, config: { alerts: global }, store, chatId: 1, ...t });
  assert.ok(t.seen.some((m) => m.includes("verifier off")));
  assert.ok(out.text.includes("Settings") || out.text.includes("Настройки"));
  assert.ok(out.text.includes("❌"));
});

test("settings toggles stay in settings, alerts toggles stay in alerts", async () => {
  const store = createMemoryStore();
  const chain = stubChain(0);
  const t = toast();
  const global = { commitMismatch: true, disputes: true, keyRotation: true, treasury: true };
  const ctx = { chain, config: { alerts: global }, store, chatId: 1, ...t };
  const viaSettings = await routeCallback(parseCallback("A:disp"), ctx);
  assert.ok(t.seen.some((m) => m.includes("disputes off")));
  assert.ok(viaSettings.text.includes("Settings") || viaSettings.text.includes("Настройки"));
  const viaAlerts = await routeCallback(parseCallback("a:mm"), ctx);
  assert.ok(viaAlerts.text.includes("Alerts for this chat") || viaAlerts.text.includes("Алерты этого чата"));
});

test("normalizeInput maps RU aliases, bare ids and RU role names", () => {
  assert.equal(normalizeInput("/статус"), "/status");
  assert.equal(normalizeInput("/таск 12"), "/task 12");
  assert.equal(normalizeInput("12"), "/task 12");
  assert.equal(normalizeInput("/роль покупатель"), "/role buyer");
  assert.equal(normalizeInput("/role контрибьютор"), "/role contrib");
  assert.equal(normalizeInput("/роль нода"), "/role node");
  assert.equal(normalizeInput("/роль наблюдатель"), "/role watch");
  // Unknown input passes through untouched for /help fallback.
  assert.equal(normalizeInput("/nope"), "/nope");
});

test("watchlist, unwatch and missing tasks carry a way back", async () => {
  const store = createMemoryStore();
  const chain = stubChain(0);
  const h = createHandlers(chain, { alerts: {} }, { store });
  await h.watch(["7"], { chatId: 1 });
  const list = await h.watchlist([], { chatId: 1 });
  assert.ok(list.markup.inline_keyboard.flat().some((b) => b.callback_data === "menu"));
  const unwatched = await h.unwatch(["7"], { chatId: 1 });
  assert.ok(unwatched.markup.inline_keyboard.flat().some((b) => b.callback_data === "menu"));
  const missing = createHandlers({ ...stubChain(0), task: async () => null }, {}, { store });
  const gone = await missing.task(["999"], { chatId: 1 });
  assert.ok(replyText(gone).includes("no task with id"));
  assert.ok(gone.markup.inline_keyboard.flat().some((b) => b.callback_data === "menu"));
});

test("pool command accepts a page argument", async () => {
  const chain = stubChain(25);
  const { pool } = createHandlers(chain, {}, {});
  assert.ok(replyText(await pool([])).includes("page 1/3") || replyText(await pool([])).includes("Task pool"));
  assert.ok(replyText(await pool(["2"])).includes("page 2/3"));
});

test("empty pool and help keep navigation", async () => {
  const { pool, help } = createHandlers(stubChain(0), {}, { store: createMemoryStore() });
  const empty = await pool([]);
  assert.ok(replyText(empty).includes("no tasks"));
  assert.ok(empty.markup.inline_keyboard.flat().some((b) => b.callback_data === "menu"));
  assert.ok(replyText(await help([])).includes("/статус"));
});

test("pool and task scale money by the escrow token, not hardcoded 18", async () => {
  const six = {
    ...stubChain(1),
    task: async (id) => ({ ...view(id), budget: 1_500_000_000n, locked: 250_000_000n }),
    escrowDecimals: async () => 6,
  };
  const h = createHandlers(six, {}, { store: createMemoryStore() });
  assert.ok(replyText(await h.pool([])).includes("1500"), "pool budget at 6dp");
  assert.ok(replyText(await h.task(["1"], { chatId: 1 })).includes("1500"), "task budget at 6dp");
  // No escrowDecimals on the reader (old stubs): fail-soft to 18.
  const bare = createHandlers(stubChain(1), {}, { store: createMemoryStore() });
  assert.ok(replyText(await bare.pool([])).includes("0"), "18dp default renders sub-wei dust as 0");
});

test("toasts speak the chat's language", async () => {
  const store = createMemoryStore();
  const chain = stubChain(0);
  const t = toast();
  await routeCallback(parseCallback("w:42"), { chain, config: {}, store, chatId: 1, langCode: "ru", ...t });
  assert.ok(t.seen.some((m) => m.includes("слежу за #42")), JSON.stringify(t.seen));
  const dead = await routeCallback({ op: "zzz", arg: "" }, { chain, config: {}, store, chatId: 1, langCode: "ru" });
  assert.ok(replyText(dead).includes("старого бота"));
  assert.ok(dead.markup.inline_keyboard.flat().some((b) => b.callback_data === "menu"));
});

test("pro/simple/lang confirmations and usage errors carry a way back", async () => {
  const store = createMemoryStore();
  const h = createHandlers(stubChain(0), {}, { store });
  for (const out of [
    await h.pro([], { chatId: 1 }),
    await h.simple([], { chatId: 1 }),
    await h.lang(["ru"], { chatId: 1 }),
    await h.lang(["xx"], { chatId: 1 }),
    await h.task([], { chatId: 1 }),
    await h.task(["abc"], { chatId: 1 }),
    await h.watch([], { chatId: 1 }),
    await h.unwatch(["abc"], { chatId: 1 }),
  ]) {
    assert.ok(out.markup.inline_keyboard.flat().some((b) => b.callback_data === "menu"), replyText(out).slice(0, 60));
  }
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

/**
 * Callback pricing parity: a button press is priced by the work it does.
 *
 * The price comes from `callbackCost`, and the guard charges exactly that. The two
 * lists used to drift silently - `callbackCost` was never consulted at runtime, so a
 * button could be priced by the command it *resembles* rather than by the work it
 * does. The watch buttons are the case that matters: they render the full task view,
 * which is `/task`-sized work, but they resemble the cheap `/watch` command.
 */
test("callbackCost matches the abuse-guard price of the work the button does", () => {
  const cfg = loadAbuseConfig({});
  const cases = [
    ["p:2", "/pool"],
    ["t:42", "/task 42"],
    ["w:42", "/task 42"],
    ["u:42", "/task 42"],
    ["s", "/status"],
    ["a:disp", "/alerts"],
    ["A:disp", "/alerts"],
    ["a:ver", "/alerts"],
    ["A:ver", "/alerts"],
  ];
  for (const [callback, text] of cases) {
    const parsed = parseCallback(callback);
    const guardPrice = COMMAND_COST[parseCommand(text, cfg).name];
    assert.equal(callbackCost(parsed), guardPrice, `${callback} vs ${text}`);
  }
});
