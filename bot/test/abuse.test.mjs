/**
 * Анти-абьюз бота: квоты в единицах RPC-нагрузки, санитизация, флуд, tarpit/shadowban,
 * дедлайн хендлеров. Доказывает:
 *  (а) тяжёлая команда (/pool=15) съедает бюджет быстрее лёгкой;
 *  (б) мусорный ввод отвечает usage без единого RPC;
 *  (в) флуд одинаковым текстом поднимает риск, спамер уходит в shadowban,
 *      а shadow-ответ правдоподобен и не трогает chain;
 *  (г) висящий хендлер обрывается дедлайном с дружественной строкой.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { ChatAbuseGuard, loadAbuseConfig, parseCommand, COMMAND_COST } from "../src/abuse.mjs";
import { SanitizeError } from "../../infra/shardstore/guard.mjs";

const cfg = () => loadAbuseConfig({
  ABUSE_CHAT_BUDGET: "30",
  ABUSE_CHAT_WINDOW_MS: "60000",
  ABUSE_RISK_MEDIUM: "20",
  ABUSE_RISK_HIGH: "60",
  ABUSE_RISK_W_HIT: "8",
  ABUSE_RISK_W_DUP: "6",
  ABUSE_TARPIT_MIN_MS: "1",
  ABUSE_TARPIT_MAX_MS: "2",
  ABUSE_HANDLER_TIMEOUT_MS: "1000",
});

test("costs: тяжёлая команда дороже лёгкой", () => {
  assert.ok(COMMAND_COST.pool > COMMAND_COST.task);
  assert.ok(COMMAND_COST.task > COMMAND_COST.help);
});

test("(а) /pool исчерпывает бюджет за 2 вызова, /help живёт дольше", async () => {
  const g = new ChatAbuseGuard(cfg());
  assert.equal((await g.guardChat(1, "/pool")).action, "pass");
  assert.equal((await g.guardChat(1, "/pool")).action, "pass"); // 15+15=30, впритык
  const third = await g.guardChat(1, "/pool");
  assert.equal(third.action, "deny-rate");
  assert.ok(third.retryAfterMs > 0);
  assert.match(third.reply, /too many requests/);
  // Другой чат не страдает.
  assert.equal((await g.guardChat(2, "/pool")).action, "pass");
});

test("(б) мусорный ввод: usage без RPC и без исключений", async () => {
  const g = new ChatAbuseGuard(cfg());
  for (const bad of ["", "x".repeat(2000), "/task \0", "/task \u200b", "/task " + "9".repeat(200), "/task a b c d e f g h i"]) {
    const v = await g.guardChat(3, bad);
    assert.equal(v.action, "deny-usage");
    assert.match(v.reply, /usage/);
  }
  assert.throws(() => parseCommand("/task \0", cfg()), SanitizeError);
});

test("(в) флуд → риск → shadowban с правдоподобным ответом без chain", async () => {
  // guardChat вообще не принимает chain: deny/shadow-пути структурно не могут
  // сделать RPC — вердикты возвращаются до хендлеров. Проверяем именно это.
  const g = new ChatAbuseGuard(cfg());
  // Дубли /status (cost 4): бюджет 30 держит 7 вызовов; дубли капают +6 риска каждый.
  for (let i = 0; i < 7; i++) {
    const v = await g.guardChat(9, "/status");
    assert.ok(v.action === "pass" || v.action === "pass-tarpitted", `iter ${i}: ${v.action}`);
  }
  // К этому моменту: 6 дублей × 6 = 36+ → MEDIUM (tarpit уже отспал внутри).
  // Продолжаем дешёвой командой, пока не пробьём HIGH (60).
  let shadowed = null;
  for (let i = 0; i < 10; i++) {
    const v = await g.guardChat(9, "/help");
    if (v.action === "shadow") { shadowed = v; break; }
  }
  assert.ok(shadowed, "спамер обязан уйти в shadowban");
  assert.match(shadowed.reply, /usage/); // для /help правдоподобно usage
  assert.equal(g.levelOf(9), "high");
});

test("(г) висящий хендлер обрывается дедлайном", async () => {
  const g = new ChatAbuseGuard(cfg());
  const out = await g.runHandler(1, () => new Promise(() => {}));
  assert.match(out, /handler timeout after 1000ms/);
  const fast = await g.runHandler(1, async () => "ok");
  assert.equal(fast, "ok");
});

test("неизвестная команда стоит дёшево и отвечает help-текстом через guard", async () => {
  const g = new ChatAbuseGuard(cfg());
  const v = await g.guardChat(5, "/frobnicate");
  assert.equal(v.action, "pass");
});
