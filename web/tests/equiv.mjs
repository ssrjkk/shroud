// web/tests/equiv.mjs — паритет математики сайта с цепочкой и SDK.
//
// Что проверяет:
//   1. keccak256: эталонные векторы (пусто, границы блоков) побайтово.
//   2. vectors.json: золотые значения всего конвейера (шарды, веса, trace,
//      proof-референсы). Любой дрейф crypto.js роняет проверку.
//   3. Инварианты: детерминизм, round-trip весов, паритет ошибок
//      (включая guard'ы расходимости и переполнения i32, как в node).
//   4. Если рядом есть ethers (npm ci в packages/*): перекрёстная сверка
//      keccak и независимая сборка trace-преимиджа по layout node/src/fhe.rs.
//
// Запуск из корня репозитория:  node web/tests/equiv.mjs
// Зависимостей нет; ethers опционален (п.4 пропускается с пометкой).
import { createRequire } from "module";
import { readFileSync, existsSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");
const require = createRequire(HERE + "/");
const C = require("../assets/crypto.js");
const V = JSON.parse(readFileSync(path.join(HERE, "vectors.json"), "utf8"));

let fails = 0;
let skipped = [];
const fail = (m) => { fails++; console.log("FAIL:", m); };
const hex = (b) => "0x" + C.hex(b);
const isHex64 = (s) => /^0x[0-9a-f]{64}$/.test(s);

// deterministc PRNG for the invariant fuzz
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// --- 1. keccak vectors ---
for (const v of V.keccak) {
  const got = hex(C.keccak256Bytes(Buffer.from(v.inHex, "hex")));
  if (got !== v.digest) fail(`keccak vector len=${Buffer.from(v.inHex, "hex").length}`);
}
console.log(`1. keccak vectors: ${V.keccak.length} ok`);

// --- 2. pipeline goldens ---
for (const p of V.pipelines) {
  const bytes = C.encodeNoopShard(p.features, p.rows, p.scale);
  const commit = C.noopRowCommitment(p.rows, p.scale);
  const cid = hex(C.keccak256Bytes(bytes));
  const flat = [];
  p.rows.forEach((r) => r.forEach((v) => flat.push(Math.round(v * p.scale))));
  const res = C.referenceStep({
    features: p.features, scale: p.scale, lrQ16: p.lrQ16, l2Q16: p.l2Q16,
    minibatch: p.minibatch, prevLanes: new Array(p.features).fill(0), shards: [flat],
  });
  const nextD = C.weightsDigest(res.lanes);
  const taskHex = hex(C.keccak256Bytes(Buffer.from("demo-task-1")));
  const input = {
    taskId: taskHex, epoch: 0, chainId: 31337,
    cipherTask: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    ctRoot: cid, prevDigest: "0x" + "00".repeat(32),
    features: p.features, scale: p.scale, lrQ16: p.lrQ16, l2Q16: p.l2Q16,
    minibatch: p.minibatch, seed: p.seed, nRows: p.rows.length,
    lossMeanQ: res.lossMeanQ, leaves: [{ index: 0, cid, ct: commit }], nextDigest: nextD,
  };
  const e = p.expect;
  const checks = [
    ["bytes", bytes.length, e.bytes],
    ["commit", commit, e.commit],
    ["cid", cid, e.cid],
    ["lanes", JSON.stringify(res.lanes), JSON.stringify(e.lanes)],
    ["loss", res.lossMeanQ, e.lossMeanQ],
    ["weightsDigest", nextD, e.weightsDigest],
    ["trace", C.traceDigest(input), e.traceDigest],
    ["proofRef", C.proofReference(C.traceDigest(input)), e.proofRef],
  ];
  for (const [k, got, want] of checks) if (got !== want) fail(`golden ${p.name}.${k}`);
}
console.log(`2. pipeline goldens: ${V.pipelines.length} presets ok`);

// --- 3. invariant fuzz (fixed seed) + guard parity ---
{
  const rnd = mulberry32(424242);
  for (let it = 0; it < 400; it++) {
    const f = 2 + Math.floor(rnd() * 5);
    const n = 1 + Math.floor(rnd() * 15);
    const rows = [];
    for (let r = 0; r < n; r++) {
      const row = [];
      for (let j = 0; j < f; j++) row.push(Math.floor(rnd() * 500) / 100);
      rows.push(row);
    }
    const bytes = C.encodeNoopShard(f, rows, 1000);
    const file = C.encodeWeights(f, rows[0].map(() => 0).slice(0, f));
    const dec = C.decodeWeights(file, f);
    if (dec.lanes.some((x) => x !== 0)) fail(`zeros round-trip it${it}`);
    const flat = [];
    rows.forEach((r) => r.forEach((v) => flat.push(Math.round(v * 1000))));
    const o = { features: f, scale: 1000, lrQ16: 327, l2Q16: 0, minibatch: 4, prevLanes: new Array(f).fill(0), shards: [flat] };
    const r1 = C.referenceStep(o);
    const r2 = C.referenceStep({ ...o, prevLanes: o.prevLanes.slice() });
    if (JSON.stringify(r1) !== JSON.stringify(r2)) fail(`nondeterministic it${it}`);
    if (!isHex64(C.weightsDigest(r1.lanes))) fail(`digest shape it${it}`);
    void bytes;
  }
  // guards must fire on exploding hyperparameters (node parity: Diverged / LaneOverflow)
  let threw = 0;
  try {
    const big = [];
    for (let i = 0; i < 40; i++) big.push(9.99);
    const fl = big.map((v) => Math.round(v * 1));
    C.referenceStep({ features: 2, scale: 1, lrQ16: 65535, l2Q16: 0, minibatch: 1, prevLanes: [0, 0], shards: [fl] });
  } catch (e) { if (/diverged|lane out of i32/.test(e.message)) threw++; }
  if (!threw) fail("divergence/overflow guard did not fire");
  console.log("3. invariants: 400 iters + guards ok");
}

// --- 4. ethers cross-check (optional) ---
{
  const candidates = [
    "packages/contracts/node_modules/ethers",
    "packages/sdk/node_modules/ethers",
  ];
  let ethers = null;
  for (const c of candidates) {
    try { ethers = require(path.join(ROOT, c)); break; } catch { /* try next */ }
  }
  if (!ethers || !ethers.keccak256) {
    skipped.push("ethers cross-check (npm ci in packages/* not done)");
  } else {
    for (const v of V.keccak) {
      const ref = ethers.keccak256("0x" + v.inHex);
      if (ref !== v.digest) fail(`ethers keccak len=${v.inHex.length / 2}`);
    }
    // independent trace preimage per node/src/fhe.rs layout
    const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
    const u64be = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
    const p = V.pipelines[0];
    // full-layout replication on the first golden (all fields from vectors)
    const g = V.pipelines[0];
    const leaves = [{ index: 0, cid: g.expect.cid, ct: g.expect.commit }];
    const pre = Buffer.concat([
      Buffer.from("SHROUD/TRACE/v1\0"),
      ethers.getBytes(hex(C.keccak256Bytes(Buffer.from("demo-task-1")))),
      u32be(0), u64be(31337),
      ethers.getBytes("0x5FbDB2315678afecb367f032d93F642f64180aa3"),
      ethers.getBytes(g.expect.cid), ethers.getBytes("0x" + "00".repeat(32)),
      u32be(g.features), u32be(g.scale), u32be(g.lrQ16), u32be(g.l2Q16), u64be(g.minibatch), u64be(g.seed),
      u64be(g.rows.length),
      (() => { const lb = Buffer.alloc(16); let L = BigInt(g.expect.lossMeanQ); for (let i = 15; i >= 0; i--) { lb[i] = Number(L & 0xffn); L >>= 8n; } return lb; })(),
      u32be(0), ethers.getBytes(leaves[0].cid), ethers.getBytes(leaves[0].ct),
      ethers.getBytes(g.expect.weightsDigest),
    ]);
    if (ethers.keccak256(pre) !== g.expect.traceDigest) fail("ethers trace layout");
    console.log("4. ethers cross-check ok");
  }
}

if (skipped.length) console.log("skipped:", skipped.join("; "));
console.log(fails === 0 ? "EQUIV OK" : `fails=${fails}`);
process.exit(fails ? 1 : 0);
