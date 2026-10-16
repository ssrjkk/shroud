/**
 * Юнит-доказательства guard.mjs. Без сети и диска, с инжектированными часами:
 *  - отсутствие race при параллельных дублях (singleflight: fn вызван ровно 1 раз);
 *  - срабатывание троттлинга и границы скользящего окна;
 *  - экспоненциальный penalty box t*2^k с cap;
 *  - decay скоринга и bot-timing детектор;
 *  - tarpit/shadowban контракты;
 *  - TTL-eviction (нет утечки памяти);
 *  - санитайзер (null-bytes, invisible unicode, dot-segments, ranges);
 *  - Circuit Breaker Closed→Open→Half-Open→Closed;
 *  - маскирование секретов в аудите.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  loadGuardConfig, ConfigError, DEFAULTS, SlidingWindowLimiter, PenaltyBox,
  RiskEngine, RiskSignal, RiskLevel, tarpitDelayMs, honeypotPut,
  IdempotencyStore, FloodDetector, SanitizeError,
  assertCid, assertPath, parseRangeHeader, assertDeclaredLength,
  assertBearerToken, assertIdempotencyKey, Metrics, AuditLog,
  maskSecrets, CircuitBreaker, CbState, withResilience, startSweeper,
  requestContext, withRequest, currentRequestId,
} from "./guard.mjs";

function clock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

describe("config", () => {
  it("берёт дефолты и валидирует границы", () => {
    const c = loadGuardConfig({});
    assert.equal(c.writeRps, DEFAULTS.writeRps);
    assert.equal(c.penaltyFreeAttempts, 4);
    assert.throws(() => loadGuardConfig({ GUARD_WRITE_RPS: "abc" }), ConfigError);
    assert.throws(() => loadGuardConfig({ GUARD_WRITE_RPS: "0" }), ConfigError);
    assert.throws(() => loadGuardConfig({ GUARD_RISK_HIGH: "10", GUARD_RISK_MEDIUM: "30" }), ConfigError);
  });
});

describe("SlidingWindowLimiter", () => {
  it("держит burst и режет сверх лимита с Retry-After", () => {
    const c = clock();
    const l = new SlidingWindowLimiter({ limit: 3, windowMs: 1000, now: c.now });
    assert.ok(l.take("a").allowed);
    assert.ok(l.take("a").allowed);
    const third = l.take("a");
    assert.ok(third.allowed);
    assert.equal(third.remaining, 0);
    const denied = l.take("a");
    assert.equal(denied.allowed, false);
    assert.ok(denied.retryAfterMs > 0 && denied.retryAfterMs <= 1000);
    // Другой ключ не страдает.
    assert.ok(l.take("b").allowed);
  });
  it("окно именно скользящее, не фиксированный бакет", () => {
    const c = clock();
    const l = new SlidingWindowLimiter({ limit: 2, windowMs: 1000, now: c.now });
    l.take("a"); l.take("a");
    assert.equal(l.take("a").allowed, false);
    c.advance(600);
    assert.equal(l.take("a").allowed, false); // старые метки ещё внутри окна
    c.advance(500); // окно уехало: обе метки протухли
    assert.ok(l.take("a").allowed);
    assert.ok(l.take("a").allowed);
    assert.equal(l.take("a").allowed, false); // и снова полный лимит
  });
  it("cost>1 ужесточает квоту (greylisted платит больше)", () => {
    const c = clock();
    const l = new SlidingWindowLimiter({ limit: 5, windowMs: 1000, now: c.now });
    assert.ok(l.take("a", 5).allowed);
    assert.equal(l.take("a").allowed, false);
  });
  it("sweep вычищает пустые ключи (нет утечки памяти)", () => {
    const c = clock();
    const l = new SlidingWindowLimiter({ limit: 2, windowMs: 100, now: c.now });
    l.take("a"); l.take("b"); l.take("c");
    assert.equal(l.size(), 3);
    c.advance(200);
    assert.equal(l.sweep(), 3);
    assert.equal(l.size(), 0);
  });
});

describe("PenaltyBox", () => {
  it("первые N нарушений — только счёт, дальше t*2^k с cap", () => {
    const c = clock();
    const p = new PenaltyBox({ baseMs: 1000, maxMs: 8000, windowMs: 60_000, freeAttempts: 2, now: c.now });
    assert.deepEqual(p.violate("a"), { streak: 1, blockedMs: 0 });
    assert.deepEqual(p.violate("a"), { streak: 2, blockedMs: 0 });
    assert.equal(p.blockedMs("a"), 0);
    // 3-е: k=0 → ровно base; дальше ×2 до cap.
    assert.deepEqual(p.violate("a"), { streak: 3, blockedMs: 1000 });
    assert.ok(p.blockedMs("a") > 0);
    assert.deepEqual(p.violate("a"), { streak: 4, blockedMs: 2000 });
    assert.deepEqual(p.violate("a"), { streak: 5, blockedMs: 4000 });
    assert.deepEqual(p.violate("a"), { streak: 6, blockedMs: 8000 }); // cap
    assert.deepEqual(p.violate("a"), { streak: 7, blockedMs: 8000 }); // cap держится
  });
  it("серия сбрасывается после тихого окна", () => {
    const c = clock();
    const p = new PenaltyBox({ baseMs: 1000, maxMs: 8000, windowMs: 1000, freeAttempts: 0, now: c.now });
    p.violate("a");
    c.advance(5000);
    assert.deepEqual(p.violate("a"), { streak: 1, blockedMs: 1000 });
  });
});

describe("RiskEngine", () => {
  const cfg = () => loadGuardConfig({});
  it("скоринг суммируется и экспоненциально затухает", () => {
    const c = clock();
    const r = new RiskEngine(cfg(), { now: c.now });
    let s = r.add("ip", RiskSignal.AUTH_FAIL); // +10
    assert.equal(s.score, 10);
    assert.equal(s.level, RiskLevel.LOW);
    s = r.add("ip", RiskSignal.AUTH_FAIL); // 20
    s = r.add("ip", RiskSignal.AUTH_FAIL); // 30 → medium
    assert.equal(s.level, RiskLevel.MEDIUM);
    // Полураспад при λ=0.05: ln2/0.05 ≈ 13.9с. Через 60с: 30*e^-3 ≈ 1.5 → low.
    c.advance(60_000);
    assert.equal(r.levelOf("ip"), RiskLevel.LOW);
  });
  it("HIGH достигается серией и держится", () => {
    const c = clock();
    const r = new RiskEngine(cfg(), { now: c.now });
    for (let i = 0; i < 8; i++) r.add("ip", RiskSignal.AUTH_FAIL);
    assert.equal(r.levelOf("ip"), RiskLevel.HIGH);
  });
  it("bot-timing: ровные интервалы — аномалия, живые — нет", () => {
    const c = clock();
    const r = new RiskEngine(cfg(), { now: c.now });
    let last = null;
    for (let i = 0; i < 6; i++) { // каждые 500мс ровно
      c.advance(500);
      last = r.noteInterval("bot", "put");
    }
    assert.equal(last.anomaly, true);
    assert.ok(last.cv < 0.15);
    const c2 = clock();
    const r2 = new RiskEngine(cfg(), { now: c2.now });
    let res = null;
    for (const gap of [120, 890, 340, 1500, 210, 760]) {
      c2.advance(gap);
      res = r2.noteInterval("human", "put");
    }
    assert.equal(res.anomaly, false);
  });
  it("sweep удаляет затухших субъектов", () => {
    const c = clock();
    const r = new RiskEngine(cfg(), { now: c.now });
    r.add("a", RiskSignal.NOT_FOUND);
    r.add("b", RiskSignal.NOT_FOUND);
    assert.equal(r.subjectCount(), 2);
    c.advance(3_600_000);
    assert.ok(r.sweep() >= 2);
    assert.equal(r.subjectCount(), 0);
  });
});

describe("tarpit & honeypot", () => {
  it("tarpit только для MEDIUM и в границах", () => {
    const cfg = loadGuardConfig({ GUARD_TARPIT_MIN_MS: "1000", GUARD_TARPIT_MAX_MS: "3000" });
    assert.equal(tarpitDelayMs(RiskLevel.LOW, cfg), 0);
    assert.equal(tarpitDelayMs(RiskLevel.HIGH, cfg), 0);
    for (let i = 0; i < 50; i++) {
      const d = tarpitDelayMs(RiskLevel.MEDIUM, cfg);
      assert.ok(d >= 1000 && d <= 3000, `tarpit ${d} out of range`);
    }
  });
  it("honeypot правдоподобен: 201 + корректный cid", () => {
    const hp = honeypotPut(Buffer.from("evil-bytes"));
    assert.equal(hp.status, 201);
    assert.match(hp.body.cid, /^0x[0-9a-f]{64}$/);
    assert.equal(hp.body.digest, hp.body.cid);
  });
});

describe("IdempotencyStore — доказательство отсутствия race", () => {
  it("50 параллельных дублей = ровно 1 вычисление, всем один результат", async () => {
    const store = new IdempotencyStore({ ttlMs: 60_000, maxEntries: 100 });
    let calls = 0;
    const fn = async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 20)); // окно гонки широко открыто
      return { status: 201, n: calls };
    };
    const results = await Promise.all(Array.from({ length: 50 }, () => store.run("k", fn)));
    assert.equal(calls, 1);
    for (const r of results) {
      assert.deepEqual(r.result, { status: 201, n: 1 });
    }
    // Повтор после завершения — из кэша (replayed), без нового вычисления.
    const again = await store.run("k", fn);
    assert.equal(again.replayed, true);
    assert.equal(calls, 1);
  });
  it("разные ключи вычисляются независимо; TTL и cap вычищают", async () => {
    const c = clock();
    const store = new IdempotencyStore({ ttlMs: 1000, maxEntries: 2, now: c.now });
    let n = 0;
    const fn = async () => ++n;
    await store.run("a", fn);
    await store.run("b", fn);
    await store.run("c", fn); // вытесняет "a" (cap=2)
    assert.equal(store.size(), 2);
    await store.run("a", fn); // пересчёт
    assert.equal(n, 4);
    c.advance(2000);
    assert.equal(store.sweep(), 2);
  });
});

describe("Sanitizer", () => {
  it("cid строго 0x+64 hex", () => {
    assert.throws(() => assertCid("xyz"), SanitizeError);
    assert.throws(() => assertCid("0xAB"), SanitizeError);
    assert.throws(() => assertCid(`0x${"ab".repeat(32).toUpperCase()}`), SanitizeError);
    assert.equal(assertCid(`0x${"ab".repeat(32)}`), `0x${"ab".repeat(32)}`);
  });
  it("путь: null-bytes, dot-segments, %2e, invisible unicode", () => {
    assert.throws(() => assertPath("/objects/a\0b", 256), SanitizeError);
    assert.throws(() => assertPath("/objects/../x", 256), SanitizeError);
    assert.throws(() => assertPath("/objects/%2e%2e/x", 256), SanitizeError);
    assert.throws(() => assertPath("/objects/%2e", 256), SanitizeError);
    assert.throws(() => assertPath("/objects/\u200b", 256), SanitizeError);
    assert.throws(() => assertPath("/objects/%", 256), SanitizeError);
    assert.equal(assertPath("/objects/0xabc", 256), "/objects/0xabc");
  });
  it("range: single, suffix, границы, cap окна", () => {
    assert.equal(parseRangeHeader(undefined, 100), null);
    assert.deepEqual(parseRangeHeader("bytes=2-5", 100), { start: 2, end: 5 });
    assert.deepEqual(parseRangeHeader("bytes=-4", 100), { suffix: 4 });
    assert.throws(() => parseRangeHeader("bytes=-0", 100), SanitizeError); // пустое окно
    assert.throws(() => parseRangeHeader("bytes=-", 100), SanitizeError);
    assert.throws(() => parseRangeHeader("bytes=0-1,2-3", 100), SanitizeError); // multi
    assert.throws(() => parseRangeHeader("bytes=0-1000", 100), SanitizeError); // окно > cap
    assert.throws(() => parseRangeHeader("bytes=-1000", 100), SanitizeError); // суффикс > cap
    assert.throws(() => parseRangeHeader("bytes=abc", 100), SanitizeError);
  });
  it("declared length и токены", () => {
    assert.equal(assertDeclaredLength("10", 100), 10);
    assert.equal(assertDeclaredLength(undefined, 100), null);
    assert.throws(() => assertDeclaredLength("101", 100), SanitizeError);
    assert.throws(() => assertDeclaredLength("-1", 100), SanitizeError);
    assert.equal(assertBearerToken("Bearer abc123"), "abc123");
    assert.throws(() => assertBearerToken("Basic abc"), SanitizeError);
    assert.throws(() => assertBearerToken("Bearer a b"), SanitizeError);
    assert.equal(assertIdempotencyKey("key-1_2/3", 64), "key-1_2/3");
    assert.throws(() => assertIdempotencyKey("key with spaces", 64), SanitizeError);
    assert.equal(assertIdempotencyKey("", 64), null);
  });
  it("FloodDetector ловит дубли в окне K", () => {
    const f = new FloodDetector(3);
    assert.equal(f.note("ip", "h1"), false);
    assert.equal(f.note("ip", "h2"), false);
    assert.equal(f.note("ip", "h1"), true);
    f.note("ip", "h3"); f.note("ip", "h4"); f.note("ip", "h5"); // h1 вытеснен (K=3)
    assert.equal(f.note("ip", "h1"), false);
  });
});

describe("Observability", () => {
  it("маскирует секреты рекурсивно, включая вложенные", () => {
    const out = maskSecrets({
      authorization: "Bearer secret-token-xyz",
      nested: { apiKey: "k", password: "p", safe: "visible" },
      arr: [{ token: "t" }],
      safeNote: "visible-string",
    });
    assert.equal(out.authorization, "***");
    assert.equal(out.nested.apiKey, "***");
    assert.equal(out.nested.safe, "visible");
    assert.equal(out.arr[0].token, "***");
    assert.equal(out.safeNote, "visible-string");
  });
  it("request_id пробрасывается через AsyncLocalStorage", async () => {
    const { currentRequestId } = await import("./guard.mjs");
    assert.equal(currentRequestId(), null);
    await withRequest("req-1", async () => {
      assert.equal(currentRequestId(), "req-1");
      await new Promise((r) => setTimeout(r, 5));
      assert.equal(currentRequestId(), "req-1"); // переживает await
    });
    assert.equal(currentRequestId(), null);
  });
  it("метрики считают и усредняют", () => {
    const m = new Metrics();
    m.incr("a"); m.incr("a", 2);
    m.observe("t", 10); m.observe("t", 30);
    const s = m.snapshot();
    assert.equal(s.counters.a, 3);
    assert.equal(s.timings.t.count, 2);
    assert.equal(s.timings.t.avgMs, 20);
    assert.equal(s.timings.t.maxMs, 30);
  });
  it("audit пишет JSONL с requestId и маскировкой", async () => {
    const lines = [];
    const sink = { write: (s) => lines.push(s) };
    const log = new AuditLog({ sink, service: "test" });
    await withRequest("r-9", async () => {
      log.security("AUTH_FAIL", { ip: "1.2.3.4", authorization: "Bearer s3cr3t" });
    });
    const e = JSON.parse(lines[0]);
    assert.equal(e.level, "security");
    assert.equal(e.requestId, "r-9");
    assert.equal(e.authorization, "***");
    assert.equal(e.ip, "1.2.3.4");
  });
});

describe("CircuitBreaker", () => {
  it("Closed → Open после N провалов → Half-Open → Closed", async () => {
    const c = clock();
    const states = [];
    const cb = new CircuitBreaker({
      failureThreshold: 3, openMs: 1000, now: c.now, onState: (s) => states.push(s),
    });
    const fail = () => Promise.reject(new Error("down"));
    await assert.rejects(cb.exec(fail));
    await assert.rejects(cb.exec(fail));
    assert.equal(cb.state, CbState.CLOSED);
    await assert.rejects(cb.exec(fail)); // 3-й → OPEN
    assert.equal(cb.state, CbState.OPEN);
    // В OPEN — сразу fallback, без ожидания апстрима.
    let waited = false;
    await cb.exec(() => { waited = true; return "x"; }, { fallback: () => "fb" }).then((v) => {
      assert.equal(v, "fb");
    });
    assert.equal(waited, false);
    c.advance(1000);
    assert.equal(cb.state, CbState.HALF_OPEN);
    assert.equal(await cb.exec(() => Promise.resolve("ok")), "ok");
    assert.equal(cb.state, CbState.CLOSED);
    assert.deepEqual(states, [CbState.OPEN, CbState.HALF_OPEN, CbState.CLOSED]);
  });
  it("half-open: одна проба, остальные в fallback", async () => {
    const c = clock();
    const cb = new CircuitBreaker({ failureThreshold: 1, openMs: 1000, halfOpenMax: 1, now: c.now });
    await assert.rejects(cb.exec(() => Promise.reject(new Error("x"))));
    c.advance(1000);
    let release;
    const gate = new Promise((r) => { release = r; });
    const p1 = cb.exec(() => gate, { fallback: () => "fb" });
    const p2 = cb.exec(() => Promise.resolve("never"), { fallback: () => "fb" });
    assert.equal(await p2, "fb");
    release("probe-ok");
    assert.equal(await p1, "probe-ok");
    assert.equal(cb.state, CbState.CLOSED);
  });
  it("withResilience: fail-open с CRITICAL, никогда не бросает", async () => {
    const lines = [];
    const audit = new AuditLog({ sink: { write: (s) => lines.push(s) } });
    const r = await withResilience("t", async () => { throw new Error("boom"); }, { fallback: 42, audit });
    assert.deepEqual(r, { ok: false, value: 42 });
    assert.match(lines[0], /GUARD_FALLBACK/);
    const ok = await withResilience("t", async () => 7, { fallback: 0, audit });
    assert.deepEqual(ok, { ok: true, value: 7 });
  });
});
