/**
 * Owner-only admin panel (/admin).
 *
 * The panel exists so the operator can check the deployment (redacted RPC,
 * chain head, contract wiring, send-queue health, watcher counts) from the
 * chat they already watch. Three properties are pinned here:
 *
 * 1. Audience of one: anyone who is not the owner gets a one-line refusal
 *    and costs the deployment zero RPC — the gate runs before any read.
 * 2. Read-only: the handler performs no writes and the bot holds no key, so
 *    there is nothing to escalate *to*; the worst a leaked owner id buys is
 *    the same diagnostics the operator could read from the logs.
 * 3. Redacted: the RPC URL carries the provider's key, so it renders through
 *    the same redactor as the logs, and a failing chain renders "unreadable",
 *    never a stack.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { loadConfig, isOwnerId } from "../src/config.js";
import { createHandlers, normalizeInput, replyText } from "../src/index.js";
import { COMMAND_COST } from "../src/abuse.mjs";
import { createMemoryStore } from "../src/watchlist.js";
import { renderAdmin } from "../src/format.js";

const ENV_KEYS = [
  "TELEGRAM_BOT_TOKEN",
  "TELEGRAM_ALLOWED_IDS",
  "TELEGRAM_OWNER_ID",
  "RPC_URL",
  "CHAIN_ID",
  "CIPHER_TASK_ADDRESS",
];

async function withEnv(vars, fn) {
  const saved = {};
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, vars);
  try {
    return await fn();
  } finally {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

const BASE = {
  TELEGRAM_BOT_TOKEN: "123456:test-token",
  TELEGRAM_ALLOWED_IDS: "397602448",
  RPC_URL: "http://127.0.0.1:8545",
  CHAIN_ID: "31337",
};

async function load(vars) {
  return withEnv(vars, async () => {
    try {
      return { ok: loadConfig(), error: null };
    } catch (e) {
      return { ok: null, error: e };
    }
  });
}

test("owner id defaults to the deployer and is validated like the allowlist", async () => {
  const { ok } = await load(BASE);
  assert.equal(ok.ownerId, 397602448);
  const over = await load({ ...BASE, TELEGRAM_OWNER_ID: "123" });
  assert.equal(over.ok.ownerId, 123);
  const bad = await load({ ...BASE, TELEGRAM_OWNER_ID: "@someone" });
  assert.equal(bad.ok, null);
  assert.match(bad.error.message, /TELEGRAM_OWNER_ID/);
});

test("isOwnerId compares numbers, not strings", () => {
  assert.ok(isOwnerId({ ownerId: 397602448 }, 397602448));
  assert.ok(!isOwnerId({ ownerId: 397602448 }, 1));
  assert.ok(!isOwnerId({ ownerId: 397602448 }, "397602448"));
  assert.ok(!isOwnerId({ ownerId: 397602448 }, undefined));
  assert.ok(!isOwnerId({}, 397602448));
  assert.ok(!isOwnerId(null, 397602448));
});

test("normalizeInput maps RU admin aliases", () => {
  assert.equal(normalizeInput("/admin"), "/admin");
  assert.equal(normalizeInput("/админ"), "/admin");
  assert.equal(normalizeInput("/админка"), "/admin");
});

test("admin is a known priced command", () => {
  assert.equal(COMMAND_COST.admin, 3);
});

function recordingChain() {
  const calls = [];
  return {
    calls,
    chainId: async () => {
      calls.push("chainId");
      return 31337;
    },
    taskCount: async () => {
      calls.push("taskCount");
      return 5n;
    },
  };
}

const OWNER_CONFIG = {
  ownerId: 397602448,
  rpcUrl: "https://provider.example/v1/SECRETKEY12345678",
  cipherTask: "0x1111111111111111111111111111111111111111",
  paymentVault: null,
  networkParams: null,
  verifier: null,
  alerts: {},
};

const OPS = { droppedSends: () => 2, queueDelayMs: () => 150 };

test("a non-owner is refused before any chain read", async () => {
  const chain = recordingChain();
  const { admin } = createHandlers(chain, OWNER_CONFIG, { store: createMemoryStore(), ...OPS });
  const out = await admin([], { chatId: 999 });
  assert.ok(replyText(out).includes("owner only") || replyText(out).includes("владельца"));
  assert.deepEqual(chain.calls, []);
  assert.ok(out.markup.inline_keyboard.flat().some((b) => b.callback_data === "menu"));
});

test("the owner gets redacted diagnostics, never the raw key", async () => {
  const chain = recordingChain();
  const store = createMemoryStore();
  const h = createHandlers(chain, OWNER_CONFIG, { store, ...OPS });
  await h.watch(["7"], { chatId: 999 });
  const out = await h.admin([], { chatId: 397602448 });
  const text = replyText(out);
  assert.ok(!text.includes("SECRETKEY12345678"), "provider key must not reach the chat");
  assert.ok(text.includes("31337"), "chain id renders");
  assert.ok(text.includes("5 tasks"), "task count renders");
  assert.ok(text.includes("CipherTask"), "contract wiring renders");
  assert.ok(text.includes("dropped 2"), "queue health renders");
  assert.ok(text.includes("1 chats"), "watcher census renders");
  assert.ok(text.includes("1 watched"), "watcher census renders");
  assert.ok(out.markup.inline_keyboard.flat().some((b) => b.callback_data === "menu"));
});

test("a dead RPC renders unreadable, not a stack", async () => {
  const dead = {
    chainId: async () => {
      throw new Error("rpc down");
    },
    taskCount: async () => {
      throw new Error("rpc down");
    },
  };
  const { admin } = createHandlers(dead, OWNER_CONFIG, {});
  const text = replyText(await admin([], { chatId: 397602448 }));
  assert.ok(text.includes("unreadable"), text.slice(0, 200));
  assert.ok(!text.includes("rpc down"), "raw error must not reach the chat");
});

test("renderAdmin is localised and key-complete", () => {
  const view = {
    chainId: 31337,
    taskCount: "5",
    rpc: "https://x.example/k",
    contracts: [{ name: "CipherTask", address: "0xabc", configured: true }],
    dropped: 0,
    maxWaitMs: 10,
    chats: 2,
    watchers: 3,
    ownerId: 397602448,
  };
  for (const lang of ["en", "ru"]) {
    const text = renderAdmin(view, lang);
    assert.ok(!text.includes("!admin."), `${lang} leaks a missing-key marker`);
  }
  assert.ok(renderAdmin(view, "ru").includes("Админ"));
});

test("help advertises /admin only to the owner", async () => {
  const store = createMemoryStore();
  const h = createHandlers(recordingChain(), OWNER_CONFIG, { store });
  const mine = replyText(await h.help([], { chatId: 397602448 }));
  assert.ok(mine.includes("/admin"), "owner sees the panel");
  const theirs = replyText(await h.help([], { chatId: 999 }));
  assert.ok(!theirs.includes("/admin"), "strangers are not handed the address");
});
