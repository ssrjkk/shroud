/**
 * ChainReader reads, against a stub JSON-RPC server.
 *
 * chain.js once built `new <Interface instance>(...)` at every read site. An Interface
 * is not a constructor, so every read threw — and every read catches all errors, so the
 * bot reported empty pools and null tasks against any chain, forever, with all other
 * tests green. These tests pin the reads against canned chain data so that class of
 * failure cannot return: if construction breaks again, the reads reject or go empty
 * here instead of in production.
 *
 * The stub routes `eth_call` by full calldata and answers `eth_getLogs` with canned
 * logs; response payloads are encoded with the very same Interface objects the reader
 * decodes with, so the tests assert the reader's mapping — not ethers' codec.
 */

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { ethers } from "ethers";
import { ChainReader, makeInterfaces } from "../src/chain.js";

const TASK = "0x1111111111111111111111111111111111111111";
const VAULT = "0x2222222222222222222222222222222222222222";
const PARAMS = "0x3333333333333333333333333333333333333333";
const NODE_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NODE_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ZERO32 = "0x" + "0".repeat(64);
const STAR_PROOF = "0x53544152" + "ab".repeat(28);

/** A value of any ABI type, derived from a seed so distinct fields differ. */
function fill(param, seed) {
  const t = param.type;
  if (t.startsWith("tuple")) {
    const parts = (param.components ?? []).map((c, i) => fill(c, seed + i));
    return t.endsWith("[]") ? [parts] : parts;
  }
  if (t.endsWith("[]")) return [fill({ ...param, type: t.slice(0, -2) }, seed)];
  if (t.startsWith("uint") || t.startsWith("int")) return BigInt(seed);
  if (t === "address") return "0x" + seed.toString(16).padStart(40, "0").slice(-40);
  if (t === "bool") return seed % 2 === 0;
  if (t === "bytes32" || /^bytes\d+$/.test(t)) {
    return "0x" + seed.toString(16).padStart(64, "0").slice(-64);
  }
  if (t === "bytes") return "0x1234";
  if (t === "string") return `s${seed}`;
  throw new Error(`fill: unsupported type ${t}`);
}

/** Encode a function's outputs positionally, seeds 1000+i so values differ per field. */
function encodeResult(iface, fn, seedBase = 1000) {
  const frag = iface.getFunction(fn);
  return iface.encodeFunctionResult(
    frag,
    frag.outputs.map((o, i) => fill(o, seedBase + i))
  );
}

/** A struct return built by field NAME, so the test — not the ABI order — documents it. */
function encodeStruct(iface, fn, byName) {
  const frag = iface.getFunction(fn);
  const tuple = frag.outputs[0];
  if (!tuple || !tuple.type.startsWith("tuple")) throw new Error(`${fn} is not a struct return`);
  return iface.encodeFunctionResult(frag, [tuple.components.map((c) => byName[c.name])]);
}

function startStub() {
  const routes = { calls: new Map(), logs: [] };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const answer = (payload) => {
        if (payload.method === "eth_chainId") return "0x7a69";
        if (payload.method === "eth_call") {
          const data = payload.params?.[0]?.data ?? "";
          // Exact calldata first, bare selector as fallback.
          return routes.calls.get(data) ?? routes.calls.get(data.slice(0, 10)) ?? "0x";
        }
        if (payload.method === "eth_getLogs") {
          // Like a real node: only logs matching the requested topic filter come back.
          // (The reader always queries one event; answering everything would hide a
          // wrong-topic query and make #decode look broken instead of the stub.)
          const t0 = payload.params?.[0]?.topics?.[0];
          if (!t0) return routes.logs;
          return routes.logs.filter(
            (l) => l.topics?.[0]?.toLowerCase() === String(t0).toLowerCase()
          );
        }
        throw new Error(`stub: unhandled method ${payload.method}`);
      };
      const respond = (obj) => ({ jsonrpc: "2.0", id: obj.id ?? 1, result: answer(obj) });
      const parsed = JSON.parse(body);
      const out = Array.isArray(parsed) ? parsed.map(respond) : respond(parsed);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(out));
    });
  });
  return { server, routes };
}

async function setup(t) {
  const ifaces = makeInterfaces();
  const { server, routes } = startStub();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const provider = new ethers.JsonRpcProvider(`http://127.0.0.1:${server.address().port}`);
  const reader = new ChainReader(provider, ifaces, {
    cipherTask: TASK,
    paymentVault: VAULT,
    networkParams: PARAMS,
  });
  return { reader, routes, ifaces };
}

test("taskCount reads the view", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  routes.calls.set(
    ifaces.cipherTask.getFunction("taskCount").selector,
    ifaces.cipherTask.encodeFunctionResult("taskCount", [7n])
  );
  assert.equal(await reader.taskCount(), 7);
});

test("contributors lists the chain's set", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  routes.calls.set(
    ifaces.cipherTask.getFunction("contributorsOf").selector,
    ifaces.cipherTask.encodeFunctionResult("contributorsOf", [[NODE_A, NODE_B]])
  );
  assert.deepEqual(
    (await reader.contributors(1)).map((a) => a.toLowerCase()),
    [NODE_A, NODE_B]
  );
});

test("task maps the struct without inventing fields", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  routes.calls.set(
    ifaces.cipherTask.getFunction("tasks").selector,
    encodeResult(ifaces.cipherTask, "tasks", 100)
  );
  const got = await reader.task(1);
  assert.equal(got.taskId, "1");
  // Seeds: budget is output #1, contributors #7, params.features is component #6.
  assert.equal(String(got.budget), "101");
  assert.equal(got.contributors, 107);
  assert.equal(got.params.features, 106);
  assert.equal(typeof got.statusName, "string");
});

test("an unreadable task is null, not zeros", async (t) => {
  const { reader } = await setup(t);
  assert.equal(await reader.task(999), null);
});

test("commitsForEpoch filters zero digests and passes the proof through", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  const ct = ifaces.cipherTask;
  routes.calls.set(
    ct.getFunction("contributorsOf").selector,
    ct.encodeFunctionResult("contributorsOf", [[NODE_A, NODE_B]])
  );
  const commitOf = (proof, trace, verified, at) =>
    encodeStruct(ct, "commits", {
      proof,
      encWeightsCid: "0x" + "c".repeat(64),
      weightsDigest: "0x" + "d".repeat(64),
      metricsCid: "0x" + "e".repeat(64),
      traceDigest: trace,
      committedAt: at,
      revealNonce: 1n,
      verified,
    });
  routes.calls.set(
    ct.encodeFunctionData("commits", [1n, 0, NODE_A]),
    commitOf(STAR_PROOF, "0x" + "f".repeat(64), true, 900n)
  );
  routes.calls.set(
    ct.encodeFunctionData("commits", [1n, 0, NODE_B]),
    commitOf(ZERO32, ZERO32, false, 0n)
  );
  const commits = await reader.commitsForEpoch(1, 0);
  assert.equal(commits.length, 1);
  assert.equal(commits[0].node.toLowerCase(), NODE_A);
  assert.equal(commits[0].traceDigest, "0x" + "f".repeat(64));
  assert.equal(commits[0].verified, true);
  assert.equal(commits[0].proof, STAR_PROOF);
});

test("tasksCreated decodes logs with their block numbers", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  const frag = ifaces.cipherTask.getEvent("TaskCreated");
  const enc = ifaces.cipherTask.encodeEventLog(
    frag,
    frag.inputs.map((c, i) => fill(c, 50 + i))
  );
  routes.logs = [
    {
      address: TASK,
      topics: enc.topics,
      data: enc.data,
      blockNumber: 123,
      blockHash: "0x" + "2".repeat(64),
      transactionHash: "0x" + "1".repeat(64),
      transactionIndex: 0,
      index: 0,
      removed: false,
    },
  ];
  const got = await reader.tasksCreated(100, 200);
  assert.equal(got.length, 1);
  assert.equal(got[0].blockNumber, 123);
  assert.ok(got[0].args, "decoded args present");
});

test("networkParams maps the pin fields by name", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  routes.calls.set(
    ifaces.networkParams.getFunction("current").selector,
    encodeResult(ifaces.networkParams, "current", 200)
  );
  const np = await reader.networkParams();
  // Seeds: chainId #0, keyVersion #1, fhePublicKeyHash #2, active #10 (even seed: true).
  assert.equal(np.chainId, 200);
  assert.equal(np.keyVersion, 201);
  assert.equal(np.fhePublicKeyHash, "0x" + (202).toString(16).padStart(64, "0"));
  assert.equal(np.active, true);
});

test("disputeQuorum reports have over need, never NaN", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  routes.calls.set(
    ifaces.cipherTask.getFunction("disputeQuorum").selector,
    ifaces.cipherTask.encodeFunctionResult("disputeQuorum", [3n, 1n])
  );
  assert.deepEqual(await reader.disputeQuorum(1), { need: 3, have: 1 });
});

test("statusOf and epochWinner pass values through", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  routes.calls.set(
    ifaces.cipherTask.getFunction("statusOf").selector,
    ifaces.cipherTask.encodeFunctionResult("statusOf", [5n])
  );
  routes.calls.set(
    ifaces.cipherTask.getFunction("epochWinner").selector,
    ifaces.cipherTask.encodeFunctionResult("epochWinner", [NODE_A])
  );
  assert.equal(await reader.statusOf(1), 5);
  assert.equal((await reader.epochWinner(1, 0)).toLowerCase(), NODE_A);
});

test("rotationEvents surfaces proposals and executions with no pending queue", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  const np = ifaces.networkParams;
  const logFor = (name, seed) => {
    const frag = np.getEvent(name);
    const enc = np.encodeEventLog(
      frag,
      frag.inputs.map((c, i) => fill(c, seed + i))
    );
    return {
      address: PARAMS,
      topics: enc.topics,
      data: enc.data,
      blockNumber: 200,
      blockHash: "0x" + "2".repeat(64),
      transactionHash: "0x" + "3".repeat(64),
      transactionIndex: 0,
      index: 0,
      removed: false,
    };
  };
  routes.logs = [logFor("RotationProposed", 400), logFor("RotationExecuted", 410)];
  routes.calls.set(
    np.getFunction("rotationPending").selector,
    np.encodeFunctionResult("rotationPending", [false])
  );
  const got = await reader.rotationEvents(100, 300);
  assert.equal(got.proposed.length, 1);
  assert.equal(got.executed.length, 1);
  assert.equal(got.pending, null);
});

test("pendingRotation maps the queued rotation by name", async (t) => {
  const { reader, routes, ifaces } = await setup(t);
  const np = ifaces.networkParams;
  routes.calls.set(
    np.getFunction("rotationPending").selector,
    np.encodeFunctionResult("rotationPending", [true])
  );
  routes.calls.set(np.getFunction("pending").selector, encodeResult(np, "pending", 500));
  const got = await reader.pendingRotation();
  // Seeds: scheduledAt #0, expectedHash #1, proposer #2, approver #3.
  assert.equal(got.scheduledAt, 500);
  assert.equal(got.expectedHash, "0x" + (501).toString(16).padStart(64, "0"));
  assert.equal(got.proposer.toLowerCase(), ("0x" + (502).toString(16).padStart(40, "0")).toLowerCase());
  assert.equal(got.approver.toLowerCase(), ("0x" + (503).toString(16).padStart(40, "0")).toLowerCase());
});
