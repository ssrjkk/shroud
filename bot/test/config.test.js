/**
 * Configuration and access-control tests.
 *
 * The allowlist is the only thing standing between an open bot and a full read
 * of task budgets, operator addresses and dispute activity, so its failure mode
 * is asserted explicitly: a missing or malformed allowlist must stop the bot,
 * not silently open it up.
 *
 * `loadConfig` reads `process.env` at call time, so each test sets and restores
 * the environment it needs.
 */

import test from "node:test";
import assert from "node:assert/strict";

const ENV_KEYS = [
  "TELEGRAM_BOT_TOKEN",
  "TELEGRAM_ALLOWED_IDS",
  "RPC_URL",
  "CHAIN_ID",
  "CIPHER_TASK_ADDRESS",
  "PAYMENT_VAULT_ADDRESS",
  "NETWORK_PARAMS_ADDRESS",
  "POLL_INTERVAL_SECONDS",
  "CATCHUP_BLOCKS",
  "ALERT_COMMIT_MISMATCH",
  "ALERT_DISPUTES",
  "ALERT_KEY_ROTATION",
  "HTML_MODE",
];

async function withEnv(vars, fn) {
  const saved = {};
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, vars);
  try {
    // Awaited before the restore below: `loadConfig` reads `process.env`
    // synchronously, but the import and the assertions after it are async, and
    // restoring early would hand the callback a different environment than the
    // one it was set up with.
    return await fn();
  } finally {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

/**
 * Runs `loadConfig` against a controlled environment.
 *
 * The module is imported (and its `.env` reader executed) once, but
 * `loadConfig` reads `process.env` on every call, so per-test environments are
 * honoured without cache-busting.
 */
async function load(vars) {
  return withEnv(vars, async () => {
    const { loadConfig } = await import("../src/config.js");
    try {
      return { ok: loadConfig(), error: null };
    } catch (e) {
      return { ok: null, error: e };
    }
  });
}

const BASE = {
  TELEGRAM_BOT_TOKEN: "123456:test-token",
  TELEGRAM_ALLOWED_IDS: "111, 222",
  RPC_URL: "http://127.0.0.1:8545",
  CHAIN_ID: "31337",
};

test("a valid config loads and parses the allowlist into a Set", async () => {
  const { ok } = await load(BASE);
  assert.equal(ok.allowedChatIds.size, 2);
  assert.ok(ok.allowedChatIds.has(111));
  assert.ok(ok.allowedChatIds.has(222));
  assert.equal(ok.chainId, 31337);
});

test("a missing allowlist stops the bot", async () => {
  const { ok, error } = await load({ ...BASE, TELEGRAM_ALLOWED_IDS: "" });
  assert.equal(ok, null);
  assert.match(error.message, /TELEGRAM_ALLOWED_IDS/);
});

test("a username in the allowlist is rejected rather than ignored", async () => {
  // Silently ignoring an unmatched entry would look like it worked while the bot
  // stayed locked (or, worse, the operator adds it expecting access and never
  // gets a clear reason).
  const { ok, error } = await load({ ...BASE, TELEGRAM_ALLOWED_IDS: "@someone, 111" });
  assert.equal(ok, null);
  assert.match(error.message, /numeric Telegram ids/);
});

test("a malformed token is not silently accepted", async () => {
  const { ok, error } = await load({ ...BASE, TELEGRAM_BOT_TOKEN: "" });
  assert.equal(ok, null);
  assert.match(error.message, /TELEGRAM_BOT_TOKEN/);
});

test("an address that is not hex is rejected", async () => {
  const { ok, error } = await load({ ...BASE, CIPHER_TASK_ADDRESS: "0xNOTHEX" });
  assert.equal(ok, null);
  assert.match(error.message, /CIPHER_TASK_ADDRESS/);
});

test("a missing address becomes null, meaning 'not configured'", async () => {
  const { ok } = await load(BASE);
  assert.equal(ok.cipherTask, null);
  assert.equal(ok.paymentVault, null);
  // Not an error: the commands must be able to say "not configured" instead of
  // pretending the pool is empty.
});

test("a valid address is normalised to lowercase", async () => {
  const { ok } = await load({
    ...BASE,
    CIPHER_TASK_ADDRESS: "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
  });
  assert.equal(ok.cipherTask, "0xabcdef0123456789abcdef0123456789abcdef01");
});

test("alert flags accept only 0/1 and default sensibly", async () => {
  const off = await load({ ...BASE, ALERT_DISPUTES: "0" });
  assert.equal(off.ok.alerts.disputes, false);
  const on = await load({ ...BASE, ALERT_DISPUTES: "1" });
  assert.equal(on.ok.alerts.disputes, true);
  const bad = await load({ ...BASE, ALERT_DISPUTES: "maybe" });
  assert.equal(bad.ok, null);
  assert.match(bad.error.message, /ALERT_DISPUTES/);
});

test("a poll interval below one second is refused", async () => {
  // Sub-second polling against a devnet node will rate-limit itself into
  // uselessness and can hammer the RPC.
  const { ok, error } = await load({ ...BASE, POLL_INTERVAL_SECONDS: "0" });
  assert.equal(ok, null);
  assert.match(error.message, /POLL_INTERVAL_SECONDS/);
});

test("configuredContracts reports what is missing for /status", async () => {
  const { ok } = await load(BASE);
  const { configuredContracts } = await import("../src/config.js");
  const list = configuredContracts(ok);
  assert.equal(list.length, 3);
  assert.ok(list.every((c) => c.configured === false));
});