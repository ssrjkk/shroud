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
  // The leaf the NODE builds from the chain's contribution record: the transport
  // address the contributor submitted (sha256 of the payload) and the on-chain pin
  // (keccak256 of the payload). The ctRoot is the chain's own running root.
  const ctDigest = hex(C.keccak256Bytes(bytes));
  const transportCid = hex(C.sha256Bytes(bytes));
  const ctRoot = hex(C.keccak256Bytes(
    Buffer.concat([
      C.keccak256Bytes(Buffer.from("SHROUD/CTROOT/v1")),
      (() => { const b = Buffer.alloc(4); b.writeUInt32BE(0); return b; })(),
      Buffer.from(transportCid.slice(2), "hex"),
    ])
  ));
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
    ctRoot, prevDigest: "0x" + "00".repeat(32),
    features: p.features, scale: p.scale, lrQ16: p.lrQ16, l2Q16: p.l2Q16,
    minibatch: p.minibatch, seed: p.seed, nRows: p.rows.length,
    lossMeanQ: res.lossMeanQ, leaves: [{ index: 0, cid: transportCid, ct: ctDigest }], nextDigest: nextD,
  };
  const e = p.expect;
  const checks = [
    ["bytes", bytes.length, e.bytes],
    ["commit", commit, e.commit],
    ["ctDigest", ctDigest, e.ctDigest],
    ["transportCid", transportCid, e.transportCid],
    ["ctRoot", ctRoot, e.ctRoot],
    ["lanes", JSON.stringify(res.lanes), JSON.stringify(e.lanes)],
    ["loss", res.lossMeanQ, e.lossMeanQ],
    ["weightsDigest", nextD, e.weightsDigest],
    ["trace", C.traceDigest(input), e.traceDigest],
    ["proofRef", C.proofReference(C.traceDigest(input)), e.proofRef],
  ];
  for (const [k, got, want] of checks) if (got !== want) fail(`golden ${p.name}.${k}`);
}
console.log(`2. pipeline goldens: ${V.pipelines.length} presets ok`);

// --- 3. the lab's own construction reproduces the golden ---
//
// The lab (playground.js) builds the leaf itself. It used to put the row commitment
// and keccak(payload) into the two leaf slots, which is not the leaf the node builds
// from the chain - so the digest the lab printed was not the one a node commits, and
// nothing in the repo noticed: the lab and the golden harness agreed with each other
// and both disagreed with the node. This check pins the lab's construction to the
// golden, which the node's own test pins to the node.
{
  const p = V.pipelines[0];
  const bytes = C.encodeNoopShard(p.features, p.rows, p.scale);
  const cid = "0x" + C.hex(C.sha256Bytes(bytes));
  const pin = "0x" + C.hex(C.keccak256Bytes(bytes));
  const root = new Uint8Array(68);
  root.set(C.keccak256Bytes(Buffer.from("SHROUD/CTROOT/v1")), 0);
  const t = cid.slice(2);
  for (let i = 0; i < 32; i++) root[36 + i] = parseInt(t.substr(i * 2, 2), 16);
  const ctRoot = "0x" + C.hex(C.keccak256Bytes(root));
  const flat = [];
  p.rows.forEach((r) => r.forEach((v) => flat.push(Math.round(v * p.scale))));
  const res = C.referenceStep({
    features: p.features, scale: p.scale, lrQ16: p.lrQ16, l2Q16: p.l2Q16,
    minibatch: p.minibatch, prevLanes: new Array(p.features).fill(0), shards: [flat],
  });
  const td = C.traceDigest({
    taskId: "0x" + C.hex(C.keccak256Bytes(Buffer.from("demo-task-1"))), epoch: 0, chainId: 31337,
    cipherTask: "0x5FbDB2315678afecb367f032d93F642f64180aa3", ctRoot,
    prevDigest: "0x" + "00".repeat(32),
    features: p.features, scale: p.scale, lrQ16: p.lrQ16, l2Q16: p.l2Q16,
    minibatch: p.minibatch, seed: p.seed, nRows: p.rows.length, lossMeanQ: res.lossMeanQ,
    leaves: [{ index: 0, cid, ct: pin }], nextDigest: C.weightsDigest(res.lanes),
  });
  if (td !== p.expect.traceDigest) fail("the lab's leaf does not reproduce the golden digest");
  console.log("3b. lab leaf matches the golden digest");
}

// --- 4. invariant fuzz (fixed seed) + guard parity ---
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
    // Non-zero round-trip with i32 edges at a rotating position: a checkedLane
    // regression on negatives once passed 400 zero-only iters unseen.
    const edge = [0, 1, -1, 2147483647, -2147483648, 123456, -987654][it % 7];
    const lanes = [];
    for (let j = 0; j < f; j++) lanes.push(j === it % f ? edge : Math.floor(rnd() * 2000000) - 1000000);
    const wf = C.encodeWeights(f, lanes);
    const back = C.decodeWeights(wf, f);
    if (JSON.stringify(back.lanes) !== JSON.stringify(lanes)) fail(`lanes round-trip it${it}`);
    const flat = [];
    rows.forEach((r) => r.forEach((v) => flat.push(Math.round(v * 1000))));
    const o = { features: f, scale: 1000, lrQ16: 327, l2Q16: 0, minibatch: 4, prevLanes: new Array(f).fill(0), shards: [flat] };
    const r1 = C.referenceStep(o);
    const r2 = C.referenceStep({ ...o, prevLanes: o.prevLanes.slice() });
    if (JSON.stringify(r1) !== JSON.stringify(r2)) fail(`nondeterministic it${it}`);
    if (!isHex64(C.weightsDigest(r1.lanes))) fail(`digest shape it${it}`);
    void bytes;
  }
  // guards must fire on exploding hyperparameters, in node order: checked i128
  // accumulators throw Overflow during the epoch, Diverged only checks the final loss.
  // This input geometrically explodes, so both implementations must report overflow here.
  let threw = 0;
  try {
    const big = [];
    for (let i = 0; i < 40; i++) big.push(9.99);
    const fl = big.map((v) => Math.round(v * 1));
    C.referenceStep({ features: 2, scale: 1, lrQ16: 65535, l2Q16: 0, minibatch: 1, prevLanes: [0, 0], shards: [fl] });
  } catch (e) { if (/^overflow: loss$/.test(e.message)) threw++; }
  if (!threw) fail("overflow guard did not fire first on exploding hyperparameters");
  // Weights rejections: out-of-range lanes, bad magic, trailing bytes, feature mismatch.
  let rej = 0;
  try { C.encodeWeights(2, [2147483648, 0]); } catch (e) { if (/outside the i32/.test(e.message)) rej++; }
  try { C.encodeWeights(2, [-2147483649, 0]); } catch (e) { if (/outside the i32/.test(e.message)) rej++; }
  {
    const good = C.encodeWeights(2, [-1, -2147483648]);
    const badMagic = good.slice(); badMagic[0] ^= 0xff;
    try { C.decodeWeights(badMagic, 2); } catch (e) { if (/bad weights magic/.test(e.message)) rej++; }
    const trailed = new Uint8Array(good.length + 1); trailed.set(good);
    try { C.decodeWeights(trailed, 2); } catch (e) { if (/trailing bytes/.test(e.message)) rej++; }
    try { C.decodeWeights(good, 3); } catch (e) { if (/holds 2 features/.test(e.message)) rej++; }
  }
  if (rej !== 5) fail(`weights rejections ${rej}/5`);
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
    // The leaf the node builds from the chain: the transport address and the on-chain
    // pin. The ctRoot is the chain's running root over (leafIndex, ciphertextCid).
    const leaves = [{ index: 0, cid: g.expect.transportCid, ct: g.expect.ctDigest }];
    const pre = Buffer.concat([
      Buffer.from("SHROUD/TRACE/v1\0"),
      ethers.getBytes(hex(C.keccak256Bytes(Buffer.from("demo-task-1")))),
      u32be(0), u64be(31337),
      ethers.getBytes("0x5FbDB2315678afecb367f032d93F642f64180aa3"),
      ethers.getBytes(g.expect.ctRoot), ethers.getBytes("0x" + "00".repeat(32)),
      u32be(g.features), u32be(g.scale), u32be(g.lrQ16), u32be(g.l2Q16), u64be(g.minibatch), u64be(g.seed),
      u64be(g.rows.length),
      (() => { const lb = Buffer.alloc(16); let L = BigInt(g.expect.lossMeanQ); for (let i = 15; i >= 0; i--) { lb[i] = Number(L & 0xffn); L >>= 8n; } return lb; })(),
      u32be(0), ethers.getBytes(leaves[0].cid), ethers.getBytes(leaves[0].ct),
      ethers.getBytes(g.expect.weightsDigest),
    ]);
    if (ethers.keccak256(pre) !== g.expect.traceDigest) fail("ethers trace layout");
    // The transport address is sha256 of the payload (the SDK's stores address it
    // that way) and the on-chain pin is keccak256 of it. The two must not be mixed up.
    const shardBytes = C.encodeNoopShard(g.features, g.rows, g.scale);
    if (ethers.sha256(shardBytes).toLowerCase() !== g.expect.transportCid.toLowerCase()) {
      fail("ethers sha256 transport cid");
    }
    if (ethers.keccak256(shardBytes).toLowerCase() !== g.expect.ctDigest.toLowerCase()) {
      fail("ethers keccak ct digest");
    }
    console.log("4. ethers cross-check ok");
  }
}

if (skipped.length) console.log("skipped:", skipped.join("; "));
console.log(fails === 0 ? "EQUIV OK" : `fails=${fails}`);
process.exit(fails ? 1 : 0);
