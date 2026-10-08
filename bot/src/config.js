/**
 * Configuration loading and validation.
 *
 * Every value here is validated once, at start-up, and the process refuses to
 * run on a bad config. That is deliberate: a bot that starts with a typo in an
 * address and then answers every question with "no tasks" is far worse than a
 * bot that refuses to start and says which line is wrong.
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = resolve(HERE, "..");

/** Minimal `.env` reader. Avoids a dependency for something this small. */
function loadDotEnv() {
  const path = resolve(ROOT, ".env");
  if (!existsSync(path)) return;
  const text = readFileSync(path, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    // A real environment variable always wins over the file: that is what makes
    // `docker run -e` and CI overrides behave the way people expect.
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

loadDotEnv();

export class ConfigError extends Error {}

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

function required(name) {
  const value = (process.env[name] ?? "").trim();
  if (!value) {
    throw new ConfigError(
      `${name} is not set. Copy bot/.env.example to bot/.env and fill it in.`
    );
  }
  return value;
}

function optionalInt(name, fallback) {
  const raw = (process.env[name] ?? "").trim();
  if (!raw) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) {
    throw new ConfigError(`${name} must be a non-negative integer, got ${JSON.stringify(raw)}`);
  }
  return n;
}

function flag(name, fallback = false) {
  const raw = (process.env[name] ?? "").trim().toLowerCase();
  if (!raw) return fallback;
  if (["1", "true", "yes", "on"].includes(raw)) return true;
  if (["0", "false", "no", "off"].includes(raw)) return false;
  throw new ConfigError(`${name} must be 0 or 1, got ${JSON.stringify(raw)}`);
}

function address(name, { required: mustBeSet = false } = {}) {
  const raw = (process.env[name] ?? "").trim();
  if (!raw) {
    if (mustBeSet) {
      throw new ConfigError(`${name} is not set. Deploy the contracts and set it in bot/.env.`);
    }
    return null;
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(raw)) {
    throw new ConfigError(`${name} is not a 20-byte hex address: ${JSON.stringify(raw)}`);
  }
  const normalized = `0x${raw.slice(2).toLowerCase()}`;
  if (normalized === ZERO_ADDRESS && mustBeSet) {
    throw new ConfigError(
      `${name} is the zero address. That is never a real deployment — deploy the contracts and set the real address.`
    );
  }
  // A zero address is *allowed* when optional: it becomes "not configured",
  // which the command layer reports honestly instead of reading as "empty".
  return normalized;
}

/**
 * Numeric Telegram ids only.
 *
 * Anything else in the allowlist is rejected loudly rather than ignored: a
 * typo'd username in a security gate should fail the deploy, not silently
 * disable it.
 */
function parseAllowedIds() {
  const raw = required("TELEGRAM_ALLOWED_IDS");
  const ids = new Set();
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    if (!/^-?\d+$/.test(trimmed)) {
      throw new ConfigError(
        `TELEGRAM_ALLOWED_IDS must be numeric Telegram ids, got ${JSON.stringify(trimmed)}. ` +
          `A @username is not an id and would never match, so it is rejected instead of ignored.`
      );
    }
    ids.add(Number(trimmed));
  }
  if (ids.size === 0) {
    throw new ConfigError("TELEGRAM_ALLOWED_IDS is set but contains no ids.");
  }
  return ids;
}

export function loadConfig() {
  const allowed = parseAllowedIds();

  const config = {
    telegramToken: required("TELEGRAM_BOT_TOKEN"),
    allowedChatIds: allowed,

    rpcUrl: (process.env.RPC_URL ?? "http://127.0.0.1:8545").trim(),
    chainId: optionalInt("CHAIN_ID", 0),

    cipherTask: address("CIPHER_TASK_ADDRESS"),
    paymentVault: address("PAYMENT_VAULT_ADDRESS"),
    networkParams: address("NETWORK_PARAMS_ADDRESS"),

    pollIntervalMs: optionalInt("POLL_INTERVAL_SECONDS", 15) * 1000,
    catchupBlocks: optionalInt("CATCHUP_BLOCKS", 2000),

    alerts: {
      commitMismatch: flag("ALERT_COMMIT_MISMATCH", true),
      disputes: flag("ALERT_DISPUTES", true),
      keyRotation: flag("ALERT_KEY_ROTATION", true),
    },

    html: flag("HTML_MODE", true),
    logLevel: (process.env.LOG_LEVEL ?? "info").trim(),
  };

  if (config.pollIntervalMs < 1000) {
    throw new ConfigError("POLL_INTERVAL_SECONDS below 1 will rate-limit the RPC into uselessness.");
  }
  if (!Number.isSafeInteger(config.chainId) || config.chainId < 0) {
    throw new ConfigError("CHAIN_ID must be a non-negative integer.");
  }

  return config;
}

/** Which contracts are configured, for /status and for gating commands. */
export function configuredContracts(config) {
  return [
    { name: "CipherTask", address: config.cipherTask },
    { name: "PaymentVault", address: config.paymentVault },
    { name: "NetworkParams", address: config.networkParams },
  ].map((c) => ({ ...c, configured: Boolean(c.address) }));
}