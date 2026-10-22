/**
 * Onboarding, language and depth.
 *
 * /start is the first thing a new chat sees: it must work with no stored
 * prefs, no chain reads and no watchlist — and it must leave the chat in the
 * detected language and simple mode. /pro /simple /lang flip stored prefs;
 * the m/l/r/h callbacks re-render the originating screen in place.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { t, isLang, pickLang, allKeys, LANGS } from "../src/i18n.js";
import { renderRole, isRole, ROLES } from "../src/roles.js";
import {
  createMemoryStore,
  normaliseState,
  getPrefs,
  setPref,
} from "../src/watchlist.js";
import { createHandlers, routeCallback, replyText } from "../src/index.js";
import { parseCallback, startKeyboard, roleKeyboard } from "../src/keyboards.js";

const stubChain = () => ({
  chainId: async () => 31337,
  blockNumber: async () => 100,
  taskCount: async () => 1n,
  task: async () => null,
  networkParams: async () => null,
});

test("i18n: every key exists in every language, and unknown keys shout", () => {
  assert.deepEqual([...LANGS].sort(), ["en", "ru"]);
  assert.ok(allKeys().length > 100, "dictionary is not a stub");
  for (const key of allKeys()) {
    for (const lang of LANGS) {
      const v = t(lang, key, { n: 1, x: "y", id: "1", epoch: "2", mode: "m", lang: "l", err: "e", s: "1", have: "1", need: "3", to: "t", from: "f", dropped: "d", kind: "k", proposer: "p", scheduledAt: "s", expectedHash: "h", keyVersion: "v", fhePublicKeyHash: "h", budget: "b", contributors: "c", rows: "r", w: "w", c2: "c", page: "1", pages: "1", total: "1" });
      assert.ok(!v.startsWith("!"), `${lang}.${key} is missing`);
    }
  }
  assert.equal(t("en", "no.such.key"), "!no.such.key!");
  assert.equal(t("xx", "menu.t"), t("en", "menu.t"), "unknown locale falls back to en");
  assert.ok(!isLang("xx") && isLang("ru") && isLang("en"));
  assert.equal(pickLang("ru-RU"), "ru");
  assert.equal(pickLang("en-US"), "en");
  assert.equal(pickLang(undefined), "en");
});

test("i18n: no dead keys — every key is rendered somewhere", () => {
  // A key nobody reads is a translator trap and stale copy waiting to
  // embarrass. Dynamic families (how.s1t..s7d, proto.b1t..b6d) are built by
  // template, so their prefixes whitelist them; everything else must appear
  // as a quoted literal in bot/src.
  const srcFiles = [
    "index.js", "format.js", "keyboards.js", "roles.js", "chain.js",
    "config.js", "telegram.js", "abuse.mjs", "watchlist.js", "redact.js",
    "atomic-write.js",
  ];
  const src = srcFiles
    .map((f) => readFileSync(new URL(`../src/${f}`, import.meta.url), "utf8"))
    .join("\n");
  const DYNAMIC = ["how.s", "proto.b"];
  const dead = allKeys().filter(
    (k) =>
      !DYNAMIC.some((p) => k.startsWith(p)) &&
      !src.includes(`"${k}"`) &&
      !src.includes(`'${k}'`)
  );
  assert.deepEqual(dead, [], `dead keys: ${dead.join(", ")}`);
});

test("prefs survive normalisation and round-trip through the store", async () => {
  const messy = normaliseState({ chats: { 1: { prefs: { lang: "ru", mode: "pro", nope: true }, junk: 1 } } });
  assert.deepEqual(getPrefs(messy, 1), { lang: "ru", mode: "pro" });
  // Unknown values are dropped, never stored.
  const bad = normaliseState({ chats: { 1: { prefs: { lang: "xx", mode: "turbo" } } } });
  assert.deepEqual(getPrefs(bad, 1), {});
  assert.deepEqual(getPrefs(emptyStateLike(), 999), {});
  const store = createMemoryStore();
  assert.deepEqual(store.getPrefs(7), {});
  assert.ok((await store.setPref(7, "lang", "ru")).ok);
  assert.ok(!(await store.setPref(7, "lang", "xx")).ok);
  assert.ok(!(await store.setPref(7, "zzz", "ru")).ok);
  assert.deepEqual(store.getPrefs(7), { lang: "ru" });

  function emptyStateLike() {
    return { version: 1, chats: {} };
  }
});

test("roles cover four sides in both languages", () => {
  assert.deepEqual([...ROLES].sort(), ["buyer", "contrib", "node", "watch"]);
  for (const r of ROLES) {
    assert.ok(isRole(r));
    const ru = renderRole(r, "ru");
    const en = renderRole(r, "en");
    assert.ok(ru && ru.length > 100, r);
    assert.ok(en && en.length > 100, r);
    assert.ok(!ru.includes("undefined") && !en.includes("!role."));
  }
  assert.equal(renderRole("alien", "en"), null);
});

test("/start onboards a fresh chat in its language and simple mode", async () => {
  const store = createMemoryStore();
  const { start } = createHandlers(stubChain(), {}, { store });
  const out = replyText(await start([], { chatId: 9, langCode: "ru-RU" }));
  assert.ok(out.includes("Shroud"), "brand survives translation");
  assert.ok(!out.includes("!start."), "no missing keys");
  assert.deepEqual(store.getPrefs(9), { lang: "ru", mode: "simple" });
});

test("/start never overwrites an explicit choice", async () => {
  const store = createMemoryStore();
  await store.setPref(1, "lang", "en");
  await store.setPref(1, "mode", "pro");
  const { start } = createHandlers(stubChain(), {}, { store });
  await start([], { chatId: 1, langCode: "ru" });
  assert.deepEqual(store.getPrefs(1), { lang: "en", mode: "pro" });
});

test("/pro, /simple and /lang flip stored prefs and confirm in the new language", async () => {
  const store = createMemoryStore();
  const h = createHandlers(stubChain(), {}, { store });
  let out = replyText(await h.simple([], { chatId: 3, langCode: "ru" }));
  assert.match(out, /просто/);
  assert.deepEqual(store.getPrefs(3), { mode: "simple" });
  // Stored prefs win over autodetect from here on.
  out = replyText(await h.lang([], { chatId: 3 }));
  assert.ok(out.length > 0);
  out = replyText(await h.lang(["ru"], { chatId: 3 }));
  assert.ok(out.includes("ru") || out.includes("язык"));
  assert.deepEqual(store.getPrefs(3), { mode: "simple", lang: "ru" });
  out = replyText(await h.pro([], { chatId: 3 }));
  assert.deepEqual(store.getPrefs(3).mode, "pro");
  out = replyText(await h.lang(["xx"], { chatId: 3 }));
  assert.ok(out.length > 0, "graceful hint, no throw");
  assert.deepEqual(store.getPrefs(3).lang, "ru", "garbage does not overwrite");
});

test("/role renders guides and rejects ghosts", async () => {
  const { role } = createHandlers(stubChain(), {}, { store: createMemoryStore() });
  assert.ok(replyText(await role(["buyer"], {})).includes("Buyer"));
  assert.ok(replyText(await role(["node"], { chatId: 1, langCode: "ru" })).includes("Оператор"));
  assert.ok(replyText(await role(["nope"], {})).length > 0);
});

test("start and role keyboards carry mode, language and every role", () => {
  for (const lang of ["ru", "en"]) {
    const kb = startKeyboard(lang, "simple");
    const flat = kb.inline_keyboard.flat().map((b) => b.callback_data);
    assert.ok(flat.includes("r:buyer") && flat.includes("r:watch"), lang);
    assert.ok(flat.some((c) => c === "m:h"), lang);
    assert.ok(flat.includes("l:ru:h") || flat.includes("l:en:h"), lang);
    const rk = roleKeyboard(lang, "pro", "node");
    assert.ok(rk.inline_keyboard.flat().some((b) => b.callback_data === "m:r:node"), lang);
  }
});

test("m/l/r/h callbacks re-render in place", async () => {
  const store = createMemoryStore();
  const chain = stubChain();
  const ctx = { chain, config: {}, store, chatId: 5, langCode: "ru" };
  // Fresh chat: RU autodetected, pro by default; /start would switch to simple.
  await routeCallback({ op: "h", arg: "" }, { ...ctx, langCode: "ru" });
  let out = replyText(await routeCallback({ op: "s", arg: "" }, ctx));
  assert.ok(out.includes("Цепь"), out.slice(0, 80));
  // Flip to simple through the button, not the command (fresh stored prefs
  // mean the toggle lands on simple first).
  await routeCallback(parseCallback("m:s"), ctx);
  assert.deepEqual(store.getPrefs(5).mode, "simple");
  // Flip language the same way and re-render a task-less pool.
  await routeCallback(parseCallback("l:en:s"), ctx);
  assert.deepEqual(store.getPrefs(5).lang, "en");
  out = replyText(await routeCallback(parseCallback("r:node"), ctx));
  assert.ok(out.includes("Node operator"));
  // Unknown role and stale button shapes never touch the chain.
  const dead = await routeCallback(parseCallback("r:alien") ?? { op: "x", arg: "" }, ctx);
  assert.ok(replyText(dead).length > 0);
});
