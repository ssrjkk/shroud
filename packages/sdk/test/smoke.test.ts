/**
 * SDK smoke tests.
 *
 * These do not need a live chain: they cross-check that the SDK's embedded ABI fragments
 * select the same functions as the compiled contracts, and that the EIP-712 binding is
 * deterministic. The full on-chain lifecycle is covered by the contracts Hardhat suite.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { ethers } from "ethers";

import { MemoryShardStore, HttpShardStore, assertSafeCid } from "../dist/index.js";
import { NoopEncryptor, noopRowCommitment, pinPayload } from "../dist/index.js";
import { REDEEM_TYPEHASH, domainSeparator } from "../dist/index.js";
import {
  decodeSliceSignature,
  encodeSliceSignature,
  SLICE_DEADLINE,
  SLICE_INDEX,
  SLICE_SIGNATURE_BYTES
} from "../dist/index.js";
import { NETWORK_PARAMS_ABI, taskIdFromReceipt } from "../dist/index.js";
import { ShroudSdk, type Encryptor, type Hex, type ShardStore } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));

/** The SDK's embedded ABI for a contract. */
function sdkAbi(name: string): any[] {
  return JSON.parse(readFileSync(join(here, `../src/abi/${name}.json`), "utf8"));
}

/** The freshly-compiled artifact ABI for a contract. */
function compiledAbi(rel: string): any[] {
  return JSON.parse(
    readFileSync(join(here, `../../contracts/artifacts/src/${rel}.json`), "utf8")
  ).abi;
}

function selector(abi: any[], fn: string): string {
  const iface = new ethers.Interface(abi);
  return iface.getFunction(fn)!.selector;
}

test("SDK CipherTask ABI matches the compiled artifact (no drift)", () => {
  const sdk = sdkAbi("CipherTask");
  const compiled = compiledAbi("CipherTask.sol/CipherTask");
  assert.deepEqual(sdk, compiled);
  // Sanity: ethers resolves the struct-typed createTask to the same selector solc emits.
  // (Solidity expands the tuple in the canonical signature, so the correct selector is the
  // expanded form, not `createTask(uint128,tuple)`.)
  assert.equal(selector(sdk, "createTask"), selector(compiled, "createTask"));
});

test("SDK PaymentVault ABI matches the compiled artifact (no drift)", () => {
  const sdk = sdkAbi("PaymentVault");
  const compiled = compiledAbi("payments/PaymentVault.sol/PaymentVault");
  assert.deepEqual(sdk, compiled);
  assert.equal(selector(sdk, "redeem"), selector(compiled, "redeem"));
});

test("SDK DecryptionGate ABI matches the compiled artifact (no drift)", () => {
  // The gate had an exported ABI but no client; the drift test is what keeps the new
  // `DecryptionGateClient` honest against the contract it talks to.
  const sdk = sdkAbi("DecryptionGate");
  const compiled = compiledAbi("DecryptionGate.sol/DecryptionGate");
  assert.deepEqual(sdk, compiled);
  assert.equal(selector(sdk, "revealCompleted"), selector(compiled, "revealCompleted"));
});

test("the task id comes from TaskCreated, never from a counter", () => {
  // `createTask` used to read `taskCount()` after sending, so a task another buyer created in the
  // same block made this client monitor, contribute to and fund the wrong task.
  const iface = new ethers.Interface(sdkAbi("CipherTask"));
  const created = iface.getEvent("TaskCreated")!;
  const buyer = "0x0000000000000000000000000000000000000010";
  const taskCreated = (taskId: bigint) => ({
    topics: [created.topicHash, ethers.toBeHex(taskId, 32), ethers.toBeHex(buyer, 32)],
    data: ethers.AbiCoder.defaultAbiCoder().encode(["uint128", "uint32"], [1_000_000_000n, 3]),
  });
  // A log from anything the transaction called into: same shape, unknown topic0.
  const foreign = { topics: [ethers.id("Transfer(address,address,uint256)")], data: "0x" };

  assert.equal(taskIdFromReceipt([taskCreated(7n)], iface), 7n);
  assert.equal(taskIdFromReceipt([foreign, taskCreated(42n)], iface), 42n);
  assert.equal(taskIdFromReceipt([foreign], iface), undefined);
  assert.equal(taskIdFromReceipt([], iface), undefined);
});

test("the SDK can encode a real createTask call", () => {
  const iface = new ethers.Interface(sdkAbi("CipherTask"));
  const calldata = iface.encodeFunctionData("createTask", [
    1_000_000_000n,
    {
      buyer: "0x0000000000000000000000000000000000000001",
      updateManager: "0x0000000000000000000000000000000000000002",
      epochs: 3,
      minContributors: 1,
      maxContributors: 100,
      minRowsPerShard: 100,
      features: 33,
      labelBits: 8,
      contributionWindow: 86400,
      epochDuration: 3600,
      disputeWindow: 600,
      pricePerRow: 1000,
      userShareBps: 8000,
      nodeShareBps: 1500,
      committeeShareBps: 500,
      reexecutionBps: 200,
      modelSpecCid: ethers.ZeroHash,
      shapeRoot: ethers.ZeroHash,
      updateMode: 1,
    },
  ]);
  assert.match(calldata, /^0x[0-9a-f]+$/);
});

test("REDEEM_TYPEHASH matches the PaymentVault type string", () => {
  // The vault computes `keccak256("Redeem(uint256 channelId,address streamer,address node,
  // uint128 maxCumulative,uint64 unlockAt,uint256 deadline)")`. The SDK must encode the same
  // string or slice authorisation fails at `isValidSignature`.
  assert.equal(
    REDEEM_TYPEHASH,
    ethers.id("Redeem(uint256 channelId,address streamer,address node,uint128 maxCumulative,uint64 unlockAt,uint256 deadline)")
  );
});

test("a contract-streamer slice is three big-endian words, nothing else", () => {
  // `CipherTask._decodeSliceFull` reads `bytes32(s[0:32])`, `bytes32(s[32:64])` and
  // `uint128(uint256(bytes32(s[64:96])))` and rejects any other length outright. So the blob is
  // pinned by position, not by an ABI header: this is the byte-for-byte layout both sides use, and
  // the contracts suite redeems real channels with exactly this shape.
  const blob = encodeSliceSignature(7n, 0n, 1_000_000n);
  const word = (v: bigint) => v.toString(16).padStart(64, "0");
  assert.equal(blob, `0x${word(7n)}${word(0n)}${word(1_000_000n)}`);
  assert.equal(ethers.dataLength(blob), SLICE_SIGNATURE_BYTES);
  assert.deepEqual(decodeSliceSignature(blob), { channelId: 7n, sliceIndex: 0n, amount: 1_000_000n });

  // The rules `CipherTask` enforces by truncating to uint128 have to be enforced here by refusing.
  assert.throws(() => encodeSliceSignature(7n, 0n, 1n << 128n), /uint128/);
  assert.throws(() => encodeSliceSignature(-1n, 0n, 1n), /non-negative/);
  assert.throws(() => encodeSliceSignature(0n, 0n, 1n << 256n), /uint128/);
  assert.throws(() => decodeSliceSignature(`0x${"11".repeat(95)}`), /exactly 96 bytes/);

  // A word whose amount exceeds uint128 is what a hand-built blob gets wrong silently.
  const overflowing = `0x${word(1n)}${word(0n)}${word(1n << 128n)}` as Hex;
  assert.throws(() => decodeSliceSignature(overflowing), /uint128/);
});

test("slice constants are the values CipherTask hard-codes", () => {
  // `finalizeEpoch` authorises only slice index 0 of a channel, and `_decodeSliceFull` fixes the
  // deadline at `type(uint256).max`. Both are part of the digest, so drifting either one produces
  // `InvalidSignature` on a channel the node is entitled to.
  assert.equal(SLICE_INDEX, 0n);
  assert.equal(SLICE_DEADLINE, ethers.MaxUint256);
});

test("the embedded NetworkParams fragments match the compiled contract", () => {
  // `NetworkParamsClient` is the one ABI in the SDK that is written by hand rather than exported
  // from an artifact, so it can silently drift from a contract change. Comparing the full fragment
  // rather than just the selector catches the part that actually breaks clients: the outputs. A
  // tuple-shaped `current()` has the same selector as the flattened getter solc really emits, and
  // every named field of the wrong shape reads `undefined`.
  const compiled = new ethers.Interface(compiledAbi("NetworkParams.sol/NetworkParams"));
  const sdk = new ethers.Interface(NETWORK_PARAMS_ABI as unknown as string[]);
  for (const fn of ["isCurrentKey", "current", "rotationPending"]) {
    assert.equal(sdk.getFunction(fn)!.format(), compiled.getFunction(fn)!.format(), fn);
  }
});

test("pinPayload is deterministic and content-addressed", () => {
  const a = new TextEncoder().encode("hello");
  const b = new TextEncoder().encode("hello");
  assert.deepEqual(pinPayload(a), pinPayload(b));
  assert.equal(pinPayload(a).ctDigest, ethers.keccak256(a));
});

test("MemoryShardStore round-trips by content address", async () => {
  const store = new MemoryShardStore();
  const payload = new TextEncoder().encode("shard-bytes");
  const { cid } = await store.put(payload);
  const got = await store.get(cid);
  assert.deepEqual(got, payload);
});

test("MemoryShardStore isolates callers from its internals", async () => {
  // The store is shared in-process (uploads next to node reads in dev flows). Without
  // copies both ways, whoever holds the payload reference can corrupt every later
  // read, including another party's integrity check.
  const store: ShardStore = new MemoryShardStore();
  const payload = new TextEncoder().encode("shared");
  const { cid } = await store.put(payload);
  payload[0] = 0xff;
  assert.deepEqual(await store.get(cid), new TextEncoder().encode("shared"));
  const got = await store.get(cid);
  got[0] = 0xff;
  assert.deepEqual(await store.get(cid), new TextEncoder().encode("shared"));
});

test("MemoryShardStore returns a local keccak digest, and get() can reach every put", async () => {
  // `get` being absent from the `ShardStore` interface meant a re-executing node could not fetch
  // a committed shard through the typed API at all.
  const store: ShardStore = new MemoryShardStore();
  const payload = new TextEncoder().encode("round-trip");
  const { cid, digest } = await store.put(payload);
  assert.equal(digest, ethers.keccak256(payload));
  assert.deepEqual(await store.get(cid), payload);
  await assert.rejects(() => store.get(ethers.keccak256(new Uint8Array([9]))), /not found/);
});

test("dev stores split transport cid and on-chain pin like production does", async () => {
  // Regression: both dev stores once used keccak256 for cid AND digest, so code comparing
  // `cid` against the on-chain `ctDigest` passed in dev and failed live. Now cid is sha256
  // (transport, like the reference service) and digest is keccak256 (the pin).
  for (const store of [new MemoryShardStore()] as ShardStore[]) {
    const payload = new TextEncoder().encode("split-addressing");
    const { cid, digest } = await store.put(payload);
    assert.equal(cid, ethers.sha256(payload));
    assert.equal(digest, ethers.keccak256(payload));
    assert.notEqual(cid, digest);
    assert.equal(ethers.dataLength(cid), 32);
    assert.deepEqual(await store.getVerified(cid, digest), payload);
  }
});

test("every ShardStore must verify, not just hand back bytes", async () => {
  // `getVerified` is in the interface for the same reason `get` is: re-execution is the protocol's
  // dispute mechanism, and it has to work against whichever store a deployment is pointed at. An
  // in-process store can still be handed a commit that does not match its contents.
  const store: ShardStore = new MemoryShardStore();
  const payload = new TextEncoder().encode("verified");
  const { cid } = await store.put(payload);
  assert.deepEqual(await store.getVerified(cid, ethers.keccak256(payload)), payload);
  await assert.rejects(
    () => store.getVerified(cid, ethers.id("a-different-commit")),
    /failed integrity check/
  );
});

test("relayer quantization is exact and refuses the unrepresentable", async () => {
  const { quantizeRows, relayerRowCommitment, encodeRelayerPayload, decodeRelayerPayload } = await import(
    "../dist/relayer-encryptor.js"
  );
  assert.deepEqual(quantizeRows([1.5, 2.25], 2, 10_000), [15000n, 22500n]);
  assert.deepEqual(quantizeRows(new Float64Array([0]), 1, 1), [0n]);
  for (const bad of [[-1], [NaN], [Infinity]]) {
    assert.throws(() => quantizeRows(bad as number[], 1, 10_000), /negative|finite/);
  }
  assert.throws(() => quantizeRows([1e20], 1, 10_000), /overflows uint64/);
  assert.throws(() => quantizeRows([1e308], 1, 10_000), /overflows float64 at scale/);
  assert.throws(() => quantizeRows([1, 2, 3], 2, 10_000), /not a multiple/);
  assert.throws(() => quantizeRows([1], 0, 10_000), /positive/);

  // Codec round-trips arbitrary handle sizes and rejects truncation and trailing bytes.
  const shard = {
    handles: [new Uint8Array([1, 2, 3]), new Uint8Array(32).fill(7)],
    inputProof: new Uint8Array([9, 9]),
  };
  const enc = encodeRelayerPayload(shard);
  const back = decodeRelayerPayload(enc);
  assert.deepEqual(back.handles.map((h) => Array.from(h)), [[1, 2, 3], Array(32).fill(7)]);
  assert.deepEqual(Array.from(back.inputProof), [9, 9]);
  assert.throws(() => decodeRelayerPayload(enc.slice(0, enc.length - 1)), /truncat/);
  assert.throws(
    () => decodeRelayerPayload(Buffer.concat([enc, Buffer.from([0])])),
    /trailing bytes/
  );
  assert.throws(() => decodeRelayerPayload(new Uint8Array([1, 2, 3])), /header|magic/);

  // The commitment binds the quantized integers, and changes when they do.
  const c1 = relayerRowCommitment([15000n, 22500n]);
  assert.equal(c1, relayerRowCommitment([15000n, 22500n]));
  assert.notEqual(c1, relayerRowCommitment([15001n, 22500n]));
});

test("RelayerEncryptor refuses binding-neutral proofs (no CipherTask, no commit)", async () => {
  // `createEncryptedInput(0x0, 0x0)` produces a proof bound to nothing: the same
  // handles/proof replay on any task. The contract address is therefore required —
  // fail-closed at config time, before any network call — while the user address may
  // stay neutral (zero) for callers that bind the contributor elsewhere.
  const { assertInputBinding } = await import("../dist/relayer-encryptor.js");
  const task = "0x" + "11".repeat(20);
  const user = "0x" + "22".repeat(20);
  assert.throws(() => assertInputBinding(undefined, user), /contractAddress/);
  assert.throws(() => assertInputBinding(ethers.ZeroAddress, user), /contractAddress/);
  assert.throws(() => assertInputBinding("not-an-address", user), /contractAddress/);
  assert.throws(() => assertInputBinding(task, "not-an-address"), /userAddress/);
  assert.deepEqual(assertInputBinding(task, undefined), {
    contractAddress: task,
    userAddress: ethers.ZeroAddress,
  });
  assert.deepEqual(assertInputBinding(task, user), { contractAddress: task, userAddress: user });
});

test("FileShardStore persists across instances and verifies like the memory store", async () => {
  const { FileShardStore } = await import("../dist/file-store.js");
  const dir = await fs.mkdtemp(join(os.tmpdir(), "shroud-filestore-"));
  try {
    const a: ShardStore = new FileShardStore(dir);
    const payload = new TextEncoder().encode("file-backed");
    const { cid, digest } = await a.put(payload);
    assert.equal(digest, ethers.keccak256(payload));
    assert.equal(cid, ethers.sha256(payload)); // transport vs pin, как в проде
    // A second instance over the same directory sees the object: the directory is the
    // authority, so SDK uploads and node reads stay coherent across processes.
    const b: ShardStore = new FileShardStore(dir);
    assert.deepEqual(await b.get(cid), payload);
    assert.deepEqual(await b.getVerified(cid, digest), payload);
    await assert.rejects(() => b.get(ethers.keccak256(new Uint8Array([9]))), /not found/);
    await assert.rejects(() => b.getVerified(cid, ethers.id("a-different-commit")), /failed integrity check/);
    await assert.rejects(() => b.get("../../etc/passwd"), /unsafe shard cid/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("FileShardStore survives concurrent puts and sweeps stale temps", async () => {
  // Two concurrent puts of the same content-addressed bytes share one temp path per
  // attempt: on Windows the second rename over an existing file throws even though the
  // content is identical. Crash orphans (`*.tmp`) are swept at open, never served.
  const { FileShardStore } = await import("../dist/file-store.js");
  const dir = await fs.mkdtemp(join(os.tmpdir(), "shroud-filestore-race-"));
  try {
    const a = new FileShardStore(dir);
    const payload = new TextEncoder().encode("race-me");
    const [r1, r2] = await Promise.all([a.put(payload), a.put(payload)]);
    assert.equal(r1.cid, r2.cid);
    assert.deepEqual(await a.get(r1.cid), payload);
    // An orphan is only an orphan once it is old enough: a temp file another process is
    // writing *right now* carries the same suffix, and deleting it makes that writer's
    // rename fail - the shard is then never stored and the caller sees a spurious
    // failure. So the sweep takes orphans, and leaves live temps alone.
    const orphan = join(dir, "deadbeef.12345.tmp");
    await fs.writeFile(orphan, "orphan");
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
    await fs.utimes(orphan, old, old);
    const live = join(dir, "cafebabe.67890.tmp");
    await fs.writeFile(live, "in flight");
    const b = new FileShardStore(dir);
    assert.deepEqual(await b.get(r1.cid), payload);
    const names = await fs.readdir(dir);
    assert.ok(!names.includes("deadbeef.12345.tmp"), `orphan temps left: ${names}`);
    assert.ok(names.includes("cafebabe.67890.tmp"), `a live temp was deleted: ${names}`);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("FileShardStore does not lose a shard to another process's sweep", async () => {
  // The store is documented for multi-process use ("SDK uploads next to a node reading
  // the same dir"). A second process opening the store must not delete the temp file the
  // first one is about to rename: the rename then fails, the shard is never stored, and
  // the caller sees a failure for a write the store had already accepted.
  const { FileShardStore } = await import("../dist/file-store.js");
  const dir = await fs.mkdtemp(join(os.tmpdir(), "shroud-filestore-sweep-"));
  try {
    const writer = new FileShardStore(dir);
    const payload = new TextEncoder().encode("sweep-race");
    const cid = ethers.sha256(payload);
    // The writer is mid-put: its temp exists, the rename has not happened yet. The temp
    // name is `<object-path>.<pid>.<nonce>.tmp`.
    const tempName = `${cid.slice(2)}.99999.deadbeef.tmp`;
    await fs.writeFile(join(dir, tempName), payload);
    // A second process opens the store: the sweep must leave the live temp alone.
    new FileShardStore(dir);
    const names = await fs.readdir(dir);
    assert.ok(names.includes(tempName), `the sweep deleted a temp that was still in flight: ${names}`);
    // The writer's own put still succeeds and stores the shard.
    const res = await writer.put(payload);
    assert.equal(res.cid, cid);
    assert.deepEqual(await writer.get(cid), payload);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("FileShardStore refuses an oversized planted file without buffering it", async () => {
  // The directory is shared with other processes by design, so a file can appear that
  // `put` would never have written. Serving it means buffering it first: under a 64 MiB
  // heap a 128 MiB plant crashes the reader, while a stat-first check rejects cleanly.
  const { FileShardStore } = await import("../dist/file-store.js");
  const dir = await fs.mkdtemp(join(os.tmpdir(), "shroud-filestore-oom-"));
  try {
    const probe = new FileShardStore(dir);
    assert.ok(probe, "store opens");
    const name = "ab".repeat(32);
    await fs.writeFile(join(dir, name), Buffer.alloc(128 * 1024 * 1024, 7));
    const here = dirname(fileURLToPath(import.meta.url));
    const modUrl = pathToFileURL(join(here, "..", "dist", "file-store.js")).href;
    const script = [
      `const { FileShardStore } = await import(${JSON.stringify(modUrl)});`,
      `const s = new FileShardStore(${JSON.stringify(dir)}, { maxObjectBytes: 1024 * 1024 });`,
      `try { await s.get("0x${name}"); console.error("unexpected success"); process.exit(2); }`,
      `catch (e) { console.log("rejected: " + e.message); }`,
    ].join("\n");
    let out = "";
    let code = 0;
    try {
      out = execFileSync(process.execPath, ["--max-old-space-size=64", "--input-type=module", "-e", script], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      code = e.status ?? 1;
      out = String(e.stdout ?? "") + String(e.stderr ?? "");
    }
    assert.equal(code, 0, `reader crashed instead of rejecting (exit ${code}): ${out.slice(0, 300)}`);
    assert.match(out, /byte cap/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("assertSafeCid rejects path traversal and URL injection", () => {
  // A `ciphertextCid` comes from on-chain data that any contributor controls, and it lands in a
  // request path. These are the values that would send the request somewhere else.
  for (const bad of [
    "../../admin",
    "..",
    "a/b",
    "a?b=1",
    "a#frag",
    "//evil.example/x",
    "a b",
    "",
    ".hidden",
    "x".repeat(129),
  ]) {
    assert.throws(() => assertSafeCid(bad), /unsafe shard cid/, `${bad} must be rejected`);
  }
  // Ordinary hex and base58 CIDs pass.
  assertSafeCid(ethers.keccak256(new Uint8Array([1])));
  assertSafeCid("QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o");
});

test("HttpShardStore refuses a cid that would rewrite the request path", async () => {
  const store = new HttpShardStore("http://da.invalid");
  await assert.rejects(() => store.get("../../etc/passwd"), /unsafe shard cid/);
  await assert.rejects(() => store.getRange("a/../b", 0, 10), /unsafe shard cid/);
});

test("HttpShardStore derives the on-chain digest locally instead of trusting the store", async () => {
  const payload = new TextEncoder().encode("payload");
  const realDigest = ethers.keccak256(payload);
  const original = globalThis.fetch;
  try {
    // The store lies about its digest. The returned `digest` must still be the true keccak256,
    // because that value is what gets committed on chain.
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ cid: realDigest, digest: ethers.ZeroHash }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as typeof fetch;

    const store = new HttpShardStore("http://da.invalid");
    const got = await store.put(payload);
    assert.equal(got.digest, realDigest);
    assert.notEqual(got.digest, ethers.ZeroHash);
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore rejects a store that returns an unusable cid", async () => {
  const payload = new TextEncoder().encode("payload");
  const original = globalThis.fetch;
  try {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ cid: "../escape" }), { status: 200 })) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid");
    await assert.rejects(() => store.put(payload), /unusable cid|unsafe shard cid/);
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore rejects a cid that passes the regex but not the traversal check", async () => {
  // "a.." matches CID_RE (dots are legal inside) yet must never reach a request path
  // or an on-chain commit: `get` refuses it via assertSafeCid, so `put` must too.
  const payload = new TextEncoder().encode("payload");
  const original = globalThis.fetch;
  try {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ cid: "a.." }), { status: 200 })) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid");
    await assert.rejects(() => store.put(payload), /unsafe shard cid/);
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore caps object size on both upload and download", async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = (async () => new Response(new Uint8Array(16), { status: 200 })) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid", { maxObjectBytes: 8 });

    await assert.rejects(() => store.put(new Uint8Array(64)), /refusing to upload 64 bytes/);

    const big = ethers.keccak256(new Uint8Array([1]));
    await assert.rejects(() => store.get(big), /over the 8 byte cap/);
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore stops pulling a lying stream instead of buffering it", async () => {
  // A hostile store declares 100 bytes and then streams 1 MiB. The cap must stop
  // the pull early: buffering the whole body first would let one GET eat memory
  // proportional to the attacker's stream, not to the configured cap.
  const original = globalThis.fetch;
  const cid = ethers.keccak256(new Uint8Array([1]));
  try {
    let delivered = 0;
    const CHUNKS = 64;
    const CHUNK = 16 * 1024;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (delivered >= CHUNKS) {
          controller.close();
          return;
        }
        delivered++;
        controller.enqueue(new Uint8Array(CHUNK));
      },
    });
    globalThis.fetch = (async () =>
      new Response(stream, { status: 200, headers: { "content-length": "100" } })) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid", { maxObjectBytes: 64 * 1024, maxRetries: 0 });
    await assert.rejects(() => store.get(cid), /byte cap/);
    assert.ok(delivered < CHUNKS, `buffered the whole ${delivered}-chunk stream despite the cap`);
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore retries 503s with backoff and gives up after the budget", async () => {
  // Transient overload must not fail a pull; a dead store must fail fast-ish, not hang.
  // Attempts = 1 + maxRetries; backoff is jittered, so the test only asserts counts.
  const original = globalThis.fetch;
  const cid = ethers.keccak256(new Uint8Array([1]));
  try {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      if (calls < 3) return new Response(null, { status: 503 });
      return new Response(new Uint8Array([7, 7]), { status: 200 });
    }) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid", { retryBaseMs: 1 });
    assert.deepEqual(await store.get(cid), new Uint8Array([7, 7]));
    assert.equal(calls, 3);

    calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      return new Response(null, { status: 500 });
    }) as typeof fetch;
    await assert.rejects(() => store.get(cid), /GET failed.*: 500/);
    assert.equal(calls, 4); // 1 + 3 retries, then the error surfaces

    calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      return new Response(null, { status: 404 });
    }) as typeof fetch;
    await assert.rejects(() => store.get(cid), /: 404/);
    assert.equal(calls, 1); // deliberate answers are never retried
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore.getRange refuses an oversized body without buffering it", async () => {
  // A store that ignores `Range` and streams the whole object would otherwise make the
  // client hold it - 64 MiB by default, twice that in the copy - for a window that may
  // be a kilobyte. The read is bounded by the window, so the client stops reading a
  // few bytes in.
  const original = globalThis.fetch;
  const cid = ethers.keccak256(new Uint8Array([1]));
  let pulled = 0;
  try {
    globalThis.fetch = (async () => {
      // One byte at a time, so the count of bytes the client actually took is visible.
      // The stream is finite: a client that does not bound its read must still finish.
      let sent = 0;
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (sent >= 100_000) {
            controller.close();
            return;
          }
          sent += 1;
          pulled += 1;
          controller.enqueue(new Uint8Array(1));
        },
      });
      return new Response(stream, { status: 200 });
    }) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid");
    await assert.rejects(() => store.getRange(cid, 0, 8), /ignored the Range header/);
    assert.ok(
      pulled < 10_000,
      `the client read ${pulled} bytes for an 8 byte window: the read is not bounded by the window`
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore.getRange checks that the bytes really are the requested window", async () => {
  // A 200 for a range request means the whole object arrived, and a 206 with a mismatched
  // content-range means the server answered some other window. Either way a chunked pull would
  // reassemble a shard whose length is right, whose CID resolves, and whose contents are wrong.
  const original = globalThis.fetch;
  const cid = ethers.keccak256(new Uint8Array([1]));
  try {
    globalThis.fetch = (async () => new Response(new Uint8Array(16), { status: 200 })) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid");
    await assert.rejects(() => store.getRange(cid, 0, 8), /ignored the Range header/);
    await assert.rejects(() => store.getRange(cid, 8, 8), /ignored the Range header/);
    // A whole object that fits the window from its start is a legitimate answer.
    globalThis.fetch = (async () => new Response(new Uint8Array(8), { status: 200 })) as typeof fetch;
    assert.equal((await store.getRange(cid, 0, 16)).byteLength, 8);

    globalThis.fetch = (async () =>
      new Response(new Uint8Array(8), { status: 206, headers: { "content-range": "bytes 8-15/40" } })) as typeof fetch;
    assert.equal((await store.getRange(cid, 8, 8)).byteLength, 8);

    // The final chunk of an object is short and still correct.
    globalThis.fetch = (async () =>
      new Response(new Uint8Array(4), { status: 206, headers: { "content-range": "bytes 8-11/12" } })) as typeof fetch;
    assert.equal((await store.getRange(cid, 8, 8)).byteLength, 4);

    // 206 status, but the bytes are from a different offset.
    globalThis.fetch = (async () =>
      new Response(new Uint8Array(8), { status: 206, headers: { "content-range": "bytes 0-7/40" } })) as typeof fetch;
    await assert.rejects(() => store.getRange(cid, 8, 8), /content-range/);

    // A 206 with no content-range at all is only usable if it did not overshoot the window.
    globalThis.fetch = (async () => new Response(new Uint8Array(12), { status: 206 })) as typeof fetch;
    await assert.rejects(() => store.getRange(cid, 0, 8), /without a content-range header/);

    // A short body without content-range is not an honest tail: without the header a
    // truncated honest chunk is indistinguishable from a hostile prefix served at the
    // wrong offset, so 206 always requires content-range.
    globalThis.fetch = (async () => new Response(new Uint8Array(4), { status: 206 })) as typeof fetch;
    await assert.rejects(() => store.getRange(cid, 8, 8), /content-range/);
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore.getVerified memoizes verified bytes and isolates callers", async () => {
  // A re-executing node pulls the same shard per epoch it checks: one fetch, N epochs.
  // The memo key binds cid AND digest, and cached bytes are copies — mutating a return
  // must not poison later reads, and a different digest must re-fetch, never hit.
  const original = globalThis.fetch;
  try {
    let calls = 0;
    const payload = new TextEncoder().encode("cached-shard");
    const cid = ethers.keccak256(new Uint8Array([1]));
    const digest = ethers.keccak256(payload);
    globalThis.fetch = (async () => {
      calls++;
      return new Response(payload.slice(), { status: 200 });
    }) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid");
    const first = await store.getVerified(cid, digest);
    const second = await store.getVerified(cid, digest);
    assert.deepEqual(Array.from(second), Array.from(payload));
    assert.equal(calls, 1);
    first[0] ^= 0xff; // caller mutates its copy
    const third = await store.getVerified(cid, digest);
    assert.deepEqual(Array.from(third), Array.from(payload));
    assert.equal(calls, 1);
    await assert.rejects(() => store.getVerified(cid, ethers.ZeroHash), /failed integrity check/);
    assert.equal(calls, 2);
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore.getVerified evicts oldest-first past the entry cap", async () => {
  // 257 distinct shards against the default 256-entry cap: the first stored
  // must refetch, the last must still hit. FIFO order is insertion order.
  const original = globalThis.fetch;
  try {
    const n = HttpShardStore.VERIFIED_CACHE_ENTRIES + 1;
    const payloads = Array.from({ length: n }, (_, i) => new TextEncoder().encode(`shard-${i}`));
    const cids = payloads.map((_, i) => ethers.keccak256(new Uint8Array([i & 0xff, (i >> 8) & 0xff])));
    const digests = payloads.map((p) => ethers.keccak256(p));
    const byCid = new Map(cids.map((c, i) => [c.toLowerCase(), payloads[i]]));
    let calls = 0;
    globalThis.fetch = (async (url: string | URL | Request) => {
      calls++;
      const cid = String(url).split("/").at(-1)!.toLowerCase();
      return new Response(byCid.get(cid)!.slice(), { status: 200 });
    }) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid");
    for (let i = 0; i < n; i++) await store.getVerified(cids[i], digests[i]);
    assert.equal(calls, n);
    await store.getVerified(cids[0], digests[0]); // evicted -> refetch
    assert.equal(calls, n + 1);
    await store.getVerified(cids[n - 1], digests[n - 1]); // still cached
    assert.equal(calls, n + 1);
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore.getVerified is bounded by bytes, not entries", async () => {
  // Two ~60-byte shards against a 100-byte budget: the first must refetch.
  // Without the byte budget the default 256-entry cap would pin both (~16 GiB
  // worst case at 64 MiB objects) and exhaust the node through its own cache.
  const original = globalThis.fetch;
  try {
    const payloads = [new Uint8Array(60).fill(1), new Uint8Array(60).fill(2)];
    const cids = [ethers.keccak256(new Uint8Array([10])), ethers.keccak256(new Uint8Array([11]))];
    const digests = payloads.map((p) => ethers.keccak256(p));
    const byCid = new Map(cids.map((c, i) => [c.toLowerCase(), payloads[i]]));
    let calls = 0;
    globalThis.fetch = (async (url: string | URL | Request) => {
      calls++;
      return new Response(byCid.get(String(url).split("/").at(-1)!.toLowerCase())!.slice(), {
        status: 200,
      });
    }) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid", { verifiedCacheBytes: 100 });
    await store.getVerified(cids[0], digests[0]);
    await store.getVerified(cids[1], digests[1]);
    assert.equal(calls, 2);
    await store.getVerified(cids[0], digests[0]); // over budget -> refetch
    assert.equal(calls, 3);
  } finally {
    globalThis.fetch = original;
  }
});

test("HttpShardStore.getVerified keeps a lone entry above the byte budget", async () => {
  // A single object over budget is still bounded by maxObjectBytes; evicting
  // it would turn every read into a refetch (cache thrash).
  const original = globalThis.fetch;
  try {
    const payload = new Uint8Array(60).fill(3);
    const cid = ethers.keccak256(new Uint8Array([12]));
    const digest = ethers.keccak256(payload);
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      return new Response(payload.slice(), { status: 200 });
    }) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid", { verifiedCacheBytes: 10 });
    await store.getVerified(cid, digest);
    await store.getVerified(cid, digest);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = original;
  }
});

test("getManyVerified pulls in order with bounded parallelism", async () => {
  const { MemoryShardStore, getManyVerified } = await import("../dist/index.js");
  const inner = new MemoryShardStore();
  const payloads = ["shard-a", "shard-b", "shard-c", "shard-d", "shard-e"].map((s) =>
    new TextEncoder().encode(s)
  );
  const entries = [];
  for (const p of payloads) {
    const { cid, digest } = await inner.put(p);
    entries.push({ cid, digest });
  }
  let inFlight = 0;
  let maxInFlight = 0;
  const tracking = {
    put: (p) => inner.put(p),
    get: (cid) => inner.get(cid),
    getVerified: async (cid, digest) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 10));
      try {
        return await inner.getVerified(cid, digest);
      } finally {
        inFlight--;
      }
    },
  };
  const out = await getManyVerified(tracking, entries, { concurrency: 2 });
  assert.deepEqual(
    out.map((b) => new TextDecoder().decode(b)),
    ["shard-a", "shard-b", "shard-c", "shard-d", "shard-e"]
  );
  assert.ok(maxInFlight <= 2, `parallelism escaped the cap: ${maxInFlight} in flight`);
  assert.ok(maxInFlight > 1, "batch degenerated to sequential pulls");
  await assert.rejects(() => getManyVerified(tracking, entries, { concurrency: 0 }), /concurrency/);
  await assert.rejects(
    () => getManyVerified(tracking, [{ cid: entries[0].cid, digest: ethers.ZeroHash }]),
    /failed integrity check/
  );
});

test("HttpShardStore.getVerified rejects bytes that do not match the committed digest", async () => {
  // The integrity decision must be made locally. A store that returns the wrong object has to be
  // distinguishable from an honest one, otherwise a re-executor compares digests against itself.
  const original = globalThis.fetch;
  try {
    globalThis.fetch = (async () => new Response(new TextEncoder().encode("tampered"))) as typeof fetch;
    const store = new HttpShardStore("http://da.invalid");
    const cid = ethers.keccak256(new TextEncoder().encode("tampered"));

    // Correct expectation: passes and returns the bytes.
    const ok = await store.getVerified(cid, ethers.keccak256(new TextEncoder().encode("tampered")));
    assert.equal(new TextDecoder().decode(ok), "tampered");

    // The digest a node would read from the chain for a *different* object: must fail.
    await assert.rejects(
      () => store.getVerified(cid, ethers.keccak256(new TextEncoder().encode("original"))),
      /failed integrity check/
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("NoopEncryptor returns a ciphertext and a commitment to the rows", async () => {
  const enc = new NoopEncryptor();
  const data = [1, 2, 3, 4, 5, 6]; // 2 rows x 3 features
  const shard = await enc.encryptRows(data, 3);
  assert.ok(shard.ciphertext.length > 0);
  assert.equal(pinPayload(shard.ciphertext).ctDigest.length, 66); // 0x + 32 bytes
  assert.equal(ethers.dataLength(shard.rowCommitment), 32);

  // The commitment is over the row *values*, not over the payload bytes: the same rows must commit
  // identically, and different rows with an identical payload shape must not.
  assert.equal(shard.rowCommitment, (await enc.encryptRows([...data], 3)).rowCommitment);
  const different = await enc.encryptRows([1, 2, 3, 4, 5, 7], 3);
  assert.notEqual(different.rowCommitment, shard.rowCommitment);
  assert.equal(ethers.dataLength(different.ciphertext), shard.ciphertext.length);

  // Re-deriving it the way the SDK used to (over the ciphertext bytes) is exactly the mistake this
  // interface change makes impossible.
  assert.notEqual(different.rowCommitment, pinPayload(shard.ciphertext).ctDigest);
});

test("NoopEncryptor refuses malformed inputs instead of packing them", async () => {
  const enc = new NoopEncryptor();
  await assert.rejects(() => enc.encryptRows([1, 2, 3], 0), /positive integer/);
  await assert.rejects(() => enc.encryptRows([1, 2, 3], 2), /positive multiple/);
  await assert.rejects(() => enc.encryptRows([], 3), /positive multiple/);
  await assert.rejects(() => enc.encryptRows([NaN, 2, 3], 3), /not finite/);
  await assert.rejects(() => enc.encryptRows([Infinity, 2, 3], 3), /not finite/);
});

test("NoopEncryptor declares that it does not encrypt", () => {
  // This flag is the only thing stopping a forgotten `encryptor` config from uploading a
  // contributor's plaintext rows under a CID that looks like a real ciphertext.
  assert.equal(new NoopEncryptor().providesConfidentiality, false);
});

test("a real encryptor must declare that it encrypts", () => {
  const honest = {
    providesConfidentiality: true,
    publicKeyHash: ethers.id("s_pub"),
    encryptRows: async () => ({
      ciphertext: new Uint8Array([1, 2, 3]),
      rowCommitment: noopRowCommitment(new Float64Array([1, 2, 3])),
    }),
  } satisfies Encryptor;
  assert.equal(honest.providesConfidentiality, true);
});

test("the SDK refuses an encryptor that reports a different key than it is configured with", () => {
  // The pin check is only worth anything if the key it checks is the key the bytes came from.
  // Without this, a client could verify `cfg.fhePublicKeyHash` against the chain while its
  // encryptor worked under a substituted key, which is threat F-08 with the detection step moved
  // somewhere that cannot see it.
  const sPub = ethers.id("network-key");
  const rogue = ethers.id("rogue-key");
  const encryptor: Encryptor = {
    providesConfidentiality: true,
    publicKeyHash: rogue,
    encryptRows: async () => ({ ciphertext: new Uint8Array([1]), rowCommitment: ethers.ZeroHash }),
  };

  assert.throws(
    () =>
      new ShroudSdk({
        cipherTask: "0x0000000000000000000000000000000000000001",
        paymentVault: "0x0000000000000000000000000000000000000002",
        signer: new ethers.Wallet(ethers.id("test").slice(2, 66)),
        provider: { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider,
        encryptor,
        fhePublicKeyHash: sPub,
      }),
    (e: Error) => {
      assert.match(e.message, /encrypts under/);
      assert.ok(e.message.includes(sPub) && e.message.includes(rogue), "both hashes must be named");
      return true;
    }
  );
});

test("the encryptor's declared key is enough to enable the pin check", async () => {
  // No `fhePublicKeyHash` in the config: the encryptor's own key is the value that has to be
  // pinned, so a caller cannot skip the check by simply not configuring the optional field.
  const onChain = ethers.id("network-key");
  const stub = networkParamsProvider(onChain, 1n, false);
  const rogue = ethers.id("rogue-key");
  const sdk = new ShroudSdk({
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    networkParams: "0x0000000000000000000000000000000000000003",
    signer: stub.signer,
    provider: stub.provider,
    chainId: 31337n,
    encryptor: {
      providesConfidentiality: true,
      publicKeyHash: rogue,
      encryptRows: async () => ({
        ciphertext: new Uint8Array([1]),
        rowCommitment: noopRowCommitment(new Float64Array([1])),
      }),
    },
  });

  await assert.rejects(
    () => sdk.uploadAndMonetize([1, 2, 3], 1n, { features: 3 }),
    (e: Error) => {
      assert.match(e.message, /is not the key pinned on chain/);
      assert.ok(e.message.includes(rogue), "the refusal must name the key the encryptor holds");
      return true;
    }
  );
});

test("ShroudSdk refuses to upload through an encryptor that does not encrypt", async () => {
  // No chain needed: the check must fire before any network call, so that a misconfiguration
  // cannot leak data even when the task itself turns out to be invalid.
  const sdk = new ShroudSdk({
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    signer: new ethers.Wallet(ethers.id("test").slice(2, 66)),
    provider: new ethers.JsonRpcProvider("http://127.0.0.1:0"),
  });

  await assert.rejects(
    () => sdk.uploadAndMonetize([1, 2, 3], 1n, { features: 3 }),
    /does not encrypt/
  );
});

test("ShroudSdk refuses a mismatched chainId instead of signing against the wrong chain", async () => {
  const provider = {
    getNetwork: async () => ({ chainId: 31337n }),
  } as unknown as ethers.Provider;
  const wallet = () => new ethers.Wallet(ethers.id("test").slice(2, 66));

  const build = (chainId: bigint) =>
    new ShroudSdk({
      cipherTask: "0x0000000000000000000000000000000000000001",
      paymentVault: "0x0000000000000000000000000000000000000002",
      signer: wallet(),
      provider,
      chainId,
    });

  // Matching id: the guard passes and the call proceeds (it then fails on the stub provider,
  // which is the point — it got past the chain check rather than being blocked by it).
  await assert.rejects(
    () => build(31337n).uploadAndMonetize([1, 2, 3], 1n, { features: 3, allowUnencrypted: true }),
    (e: Error) => !/refusing to sign against the wrong chain/.test(e.message)
  );

  // Mismatched id: blocked before anything is encrypted or uploaded.
  await assert.rejects(
    () => build(1n).uploadAndMonetize([1, 2, 3], 1n, { features: 3, allowUnencrypted: true }),
    /refusing to sign against the wrong chain/
  );
});

test("ShroudSdk rejects a networkParams config with nothing to compare against", () => {
  // Configuring the pin without the hash would look like the check is enabled when it is not.
  assert.throws(
    () =>
      new ShroudSdk({
        cipherTask: "0x0000000000000000000000000000000000000001",
        paymentVault: "0x0000000000000000000000000000000000000002",
        signer: new ethers.Wallet(ethers.id("test").slice(2, 66)),
        provider: new ethers.JsonRpcProvider("http://127.0.0.1:0"),
        networkParams: "0x0000000000000000000000000000000000000003",
      }),
    /without fhePublicKeyHash/
  );
});

test("the configured and the declared key are compared case-insensitively", () => {
  // Hex is case-insensitive: the same bytes32 written with EIP-55 casing is the same key.
  // The on-chain comparison goes through the ABI and does not care about case, so the local
  // one must not either - a checksum-cased hash for the key the encryptor already declares
  // is the same key, not a different one, and refusing it would be a false rejection of a
  // valid configuration.
  const declared = ethers.id("network-key");
  const upperCased = declared.toUpperCase().replace("0X", "0x");
  const stub = networkParamsProvider(declared, 1n, false);
  const encryptor = {
    providesConfidentiality: true,
    publicKeyHash: declared,
    encryptRows: async () => ({
      ciphertext: new Uint8Array([1]),
      rowCommitment: noopRowCommitment(new Float64Array([1])),
    }),
  };
  const build = (configured: Hex) =>
    new ShroudSdk({
      cipherTask: "0x0000000000000000000000000000000000000001",
      paymentVault: "0x0000000000000000000000000000000000000002",
      networkParams: "0x0000000000000000000000000000000000000003",
      signer: stub.signer,
      provider: stub.provider,
      chainId: 31337n,
      encryptor,
      fhePublicKeyHash: configured,
    });

  // The same key, differently cased: accepted.
  assert.doesNotThrow(() => build(upperCased));

  // A genuinely different key: still refused, and both hashes are named.
  assert.throws(
    () => build(ethers.id("rogue-key")),
    (e: Error) => {
      assert.match(e.message, /encrypts under/);
      return true;
    }
  );
});

/**
 * A provider that answers only the three `NetworkParams` view calls and refuses everything else.
 *
 * The pin check has to be exercised before the SDK reaches the chain, and refusing anything that is
 * not `NetworkParams` is what proves the call was blocked at the pin rather than somewhere later.
 */
function networkParamsProvider(pinned: Hex, keyVersion: bigint, rotationPending: boolean) {
  const sdkIface = new ethers.Interface(NETWORK_PARAMS_ABI as unknown as string[]);
  const currentResult = [
    31337n,
    keyVersion,
    pinned,
    ethers.id("committee"),
    2,
    3,
    48_576,
    1 << 24,
    4096,
    1_700_000_000n,
    true,
  ];
  const provider = {
    async call(tx: { to?: string | null; data?: string }) {
      // `parseTransaction` throws on a selector this ABI does not have, which is exactly the case
      // that must fall through to the sentinel below.
      const fn = (() => {
        try {
          return sdkIface.parseTransaction({ data: tx.data ?? "0x" });
        } catch {
          return undefined;
        }
      })();
      switch (fn?.name) {
        case "isCurrentKey":
          return sdkIface.encodeFunctionResult("isCurrentKey", [fn.args[0] === pinned]);
        case "current":
          return sdkIface.encodeFunctionResult("current", currentResult);
        case "rotationPending":
          return sdkIface.encodeFunctionResult("rotationPending", [rotationPending]);
        default:
          throw new Error(`SENTINEL: the upload got past the key pin (call to ${tx.to} ${tx.data})`);
      }
    },
    async getNetwork() {
      return { chainId: 31337n };
    },
    async resolveName(name: string) {
      return name;
    },
  } as unknown as ethers.Provider;
  return { provider, signer: new ethers.Wallet(ethers.id("test").slice(2, 66), provider) };
}

function pinSdk(configured: Hex, stub: { provider: ethers.Provider; signer: ethers.Wallet }) {
  return new ShroudSdk({
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    networkParams: "0x0000000000000000000000000000000000000003",
    fhePublicKeyHash: configured,
    signer: stub.signer,
    provider: stub.provider,
    chainId: 31337n,
  });
}

test("ShroudSdk refuses to upload under a key the chain has not pinned", async () => {
  // Threat model F-08: a sequencer that publishes its own public key collects the ciphertexts
  // submitted under it and decrypts them. The pin turns that from a silent confidentiality loss into
  // a client-side refusal, so the refusal has to be proven, not just implemented.
  const onChain = ethers.id("pinned-key");
  const rogue = ethers.id("rogue-key");
  const stub = networkParamsProvider(onChain, 4n, false);
  const sdk = pinSdk(rogue, stub);

  await assert.rejects(
    () => sdk.uploadAndMonetize([1, 2, 3], 1n, { features: 3, allowUnencrypted: true }),
    (e: Error) => {
      assert.match(e.message, /is not the key pinned on chain/);
      assert.ok(e.message.includes(onChain), "the error must name the key the chain actually pins");
      assert.ok(e.message.includes(rogue), "and the key this client would have used");
      assert.match(e.message, /keyVersion 4/);
      assert.doesNotMatch(e.message, /SENTINEL/, "nothing may reach the chain, not even a task read");
      return true;
    }
  );
});

test("ShroudSdk reports an imminent rotation alongside the mismatch", async () => {
  const onChain = ethers.id("pinned-key");
  const stub = networkParamsProvider(onChain, 9n, true);
  const sdk = pinSdk(ethers.id("rogue-key"), stub);

  await assert.rejects(
    () => sdk.uploadAndMonetize([1, 2, 3], 1n, { features: 3, allowUnencrypted: true }),
    /a rotation is currently pending/
  );
});

test("ShroudSdk uploads through the pin when the configured key is the pinned one", async () => {
  const onChain = ethers.id("pinned-key");
  const stub = networkParamsProvider(onChain, 1n, false);
  const sdk = pinSdk(onChain, stub);

  // The pin passes, so the next thing to fail is the task read — which the stub refuses loudly.
  // Asserting the sentinel is the point: it proves the pin did not block a legitimate upload.
  await assert.rejects(
    () => sdk.uploadAndMonetize([1, 2, 3], 1n, { features: 3, allowUnencrypted: true }),
    /SENTINEL: the upload got past the key pin/
  );
});

test("without a configured key hash the pin check is skipped, not silently failed", async () => {
  // `networkParams` without `fhePublicKeyHash` is refused at construction (test above), so the only
  // unconfigured shape is neither field — and that must not be read as "the key is fine".
  // (NoopEncryptor declares no key, so the fail-closed rule for confidential encryptors below
  // does not apply here.)
  const sdk = new ShroudSdk({
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    signer: new ethers.Wallet(ethers.id("test").slice(2, 66)),
    provider: { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider,
    chainId: 31337n,
  });
  assert.equal(sdk.networkParams, undefined);
});

test("ShroudSdk normalizes a numeric chainId instead of crying wolf", async () => {
  // `11155111 !== 11155111n`: without normalization a JavaScript caller on the right
  // chain fails the pin with a wrong-chain error. Floats and garbage fail at construction.
  const base = {
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    signer: new ethers.Wallet(ethers.id("test").slice(2, 66)),
    provider: { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider,
  };
  const sdk = new ShroudSdk({ ...base, chainId: 31337 as unknown as bigint });
  assert.equal((sdk as unknown as { configuredChainId: bigint }).configuredChainId, 31337n);
  assert.throws(() => new ShroudSdk({ ...base, chainId: 1.5 as unknown as bigint }), /integer chain id/);
  assert.throws(() => new ShroudSdk({ ...base, chainId: "abc" as unknown as bigint }), /integer chain id/);
});

test("withProvider forgets the pinned chain id", async () => {
  // The resolved chain id is pinned per client: swapping the provider without forgetting
  // it would keep signing against the old network after the swap.
  const key = ethers.id("test").slice(2, 66);
  const mkProvider = (chainId: bigint) =>
    ({
      getNetwork: async () => ({ chainId }),
      call: async () => {
        throw new Error("SENTINEL: reached the chain");
      },
      resolveName: async (name: string) => name,
    }) as unknown as ethers.Provider;
  const providerA = mkProvider(31337n);
  const sdk = new ShroudSdk({
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    signer: new ethers.Wallet(key, providerA),
    provider: providerA,
    chainId: 31337n,
  });
  await assert.rejects(
    () => sdk.uploadAndMonetize([1, 2, 3], 1n, { features: 3, allowUnencrypted: true }),
    /SENTINEL/
  );
  sdk.withProvider(mkProvider(31338n));
  await assert.rejects(
    () => sdk.uploadAndMonetize([1, 2, 3], 1n, { features: 3, allowUnencrypted: true }),
    /wrong chain/
  );
});

test("ShroudSdk rejects a fractional task id up front", async () => {
  // `1.5 > 0n` is true, so without the gate a fractional id sails past the existence
  // check and dies obscurely inside an ABI encoder. Fail with the value in hand.
  const sdk = new ShroudSdk({
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    signer: new ethers.Wallet(ethers.id("test").slice(2, 66)),
    provider: { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider,
    chainId: 31337n,
  });
  await assert.rejects(
    () => sdk.uploadAndMonetize([1, 2], 1.5 as unknown as bigint, { features: 2, allowUnencrypted: true }),
    /task id must be a positive integer/
  );
});

test("a confidential encryptor without a pin is fail-closed unless explicitly allowed", () => {
  // F-08: an encryptor producing real ciphertext under a known key, with no on-chain pin to
  // compare it to, is exactly what a key-substitution attack needs. The old default skipped
  // the check silently; construction now refuses unless the deployment pins out of band.
  const confidential: Encryptor = {
    providesConfidentiality: true,
    publicKeyHash: ethers.id("real-key"),
    encryptRows: async () => ({ ciphertext: new Uint8Array([1]), rowCommitment: ethers.id("rc") }),
  };
  const base = {
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    signer: new ethers.Wallet(ethers.id("test").slice(2, 66)),
    provider: { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider,
    encryptor: confidential,
  };
  assert.throws(() => new ShroudSdk(base), /allowUnpinnedKey/);
  const allowed = new ShroudSdk({ ...base, allowUnpinnedKey: true });
  assert.equal(allowed.networkParams, undefined);
});

test("DecryptionGateClient refuses a missing or malformed gate address", async () => {
  // A client bound to the zero address (or garbage) would sign and send reveal
  // transactions that revert on chain — or worse, against an unintended contract.
  // Fail at construction, before any key material or RPC is involved.
  const { DecryptionGateClient: Gate } = await import("../dist/gate.js");
  const stub = { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider;
  assert.throws(() => new Gate(ethers.ZeroAddress, stub), /gate address/);
  assert.throws(() => new Gate("not-an-address", stub), /gate address/);
  const ok = new Gate("0x0000000000000000000000000000000000000001", stub);
  assert.ok(ok.contract, "valid address constructs");
});

test("registerNodeWithPop validates its inputs before touching the signer", async () => {
  // A fractional task id, a malformed BLS key or a non-positive chain would otherwise die
  // obscurely — inside the ABI encoder, the contract revert, or a signature over the
  // wrong domain. Fail with the value in hand; the stub signer below is never reached.
  const { CipherTaskClient } = await import("../dist/cipher.js");
  const stubSigner = {} as unknown as ethers.Signer;
  const client = new CipherTaskClient(
    "0x0000000000000000000000000000000000000001",
    { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider
  );
  const bls = ("0x" + "ab".repeat(32)) as `0x${string}`;
  await assert.rejects(
    () => client.registerNodeWithPop(1.5 as unknown as bigint, bls, stubSigner, 31337n),
    /task id must be a positive integer/
  );
  await assert.rejects(
    () => client.registerNodeWithPop(1n, "0x1234" as `0x${string}`, stubSigner, 31337n),
    /bytes32/
  );
  await assert.rejects(() => client.registerNodeWithPop(1n, bls, stubSigner, 0n), /positive integer/);
});

test("disputeCommitment binds digest, salt and reporter exactly like the contract", async () => {
  // `CipherTask.commitDispute` expects keccak256(abi.encode(digest, salt, reporter)); the SDK
  // helper must produce byte-identical commitments or every commit would be unrevealable.
  const { CipherTaskClient } = await import("../dist/cipher.js");
  const client = new CipherTaskClient(
    "0x0000000000000000000000000000000000000001",
    { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider
  );
  const digest = ethers.id("trace");
  const salt = ethers.id("salt");
  const reporter = "0x00000000000000000000000000000000000000a1";
  assert.equal(
    client.disputeCommitment(digest, salt, reporter),
    ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "address"], [digest, salt, reporter]))
  );
});

test("domainSeparator is deterministic", () => {
  const a = domainSeparator("0x0000000000000000000000000000000000000001", 31337n);
  const b = domainSeparator("0x0000000000000000000000000000000000000001", 31337n);
  assert.equal(a, b);
});

test("the domain separator matches the vault's, byte for byte", () => {
  // The SDK recomputes the vault's EIP-712 domain separator locally and submits the
  // digest to `PaymentVault.redeem`, which checks it against the separator the vault
  // computed in its constructor. A divergence would make every slice redemption the
  // SDK submits fail with InvalidSignature - and nothing in the repo would notice,
  // because the contracts' suite computes its own separator and the SDK's only
  // checked that its own was stable. The golden is the same value the contracts'
  // suite pins from the other side.
  assert.equal(
    domainSeparator("0x0000000000000000000000000000000000000001", 31337n),
    "0x7daba0f7c50d1c8fd8026e05236fc6a200ce2bacc02f5c91de5630ce317cc423"
  );
  // A different chain id is a different domain: the separator is not chain-agnostic.
  assert.notEqual(
    domainSeparator("0x0000000000000000000000000000000000000001", 1n),
    "0x7daba0f7c50d1c8fd8026e05236fc6a200ce2bacc02f5c91de5630ce317cc423"
  );
});

test("the noop shard matches the node's shroud/noop/v1 layout byte for byte", async () => {
  // The Rust golden vector (node/src/fhe.rs `site_vectors_pin_the_digest_layout`, the
  // same one web/tests/vectors.json carries): features = 3, 8 rows. The header is
  // "shroud/noop/v1\0" + features + "\0" + rows + "\0", then the rows as f64 little-endian.
  //
  // The node decodes this layout, so a change on either side that the other does not
  // follow produces a shard that uploads cleanly and then fails in every node's decoder -
  // or worse, decodes into different rows. Nothing else in the SDK pins it.
  const { NoopEncryptor } = await import("../dist/index.js");
  const rows = [
    1.2, 3, 2.1, 1.8, 3, 2.8, 2, 2, 3, 1.1, 4, 2.4, 2.4, 3, 3.6, 1.6, 2, 2.5, 2.9, 4, 4.2, 1.4, 3, 2.3,
  ];
  const enc = await new NoopEncryptor().encryptRows(rows, 3);
  assert.equal(enc.ciphertext.length, 211, "the shard length must match the node's golden");
  assert.equal(
    ethers.keccak256(enc.ciphertext).toLowerCase(),
    "0x47ab2fcd4d844b6194bf38a90275c1c6715e73d0451576061854f3aefba6feaf",
    "the shard bytes must match the node's golden (the on-chain ctDigest)"
  );
});

test("weights files match the node's shroud/weights/v1 layout byte for byte", async () => {
  const { encodeWeights, decodeWeights, weightsDigest, zeroWeights } = await import(
    "../dist/weights.js"
  );
  // The Rust golden vector (node/src/fhe.rs `one_gradient_step_is_exact`): features = 2,
  // lanes = [60000, 30000]. Magic + u32-LE features + u32-LE count + u32-LE lanes.
  const bytes = encodeWeights(2, [60000, 30000]);
  assert.equal(
    Buffer.from(bytes).toString("hex"),
    "7368726f75642f776569676874732f763100" + "02000000" + "02000000" + "60ea0000" + "30750000"
  );
  assert.deepEqual(decodeWeights(bytes, 2), [60000, 30000]);
  assert.deepEqual(zeroWeights(3), [0, 0, 0]);

  // Signed lanes round-trip through the u32 words (the node's i32-in-u32 convention).
  assert.deepEqual(decodeWeights(encodeWeights(2, [-1, -2147483648]), 2), [-1, -2147483648]);

  // The digest commits to the lanes: deterministic and sensitive.
  const d = weightsDigest([60000, 30000]);
  assert.equal(d, weightsDigest([60000, 30000]));
  assert.notEqual(d, weightsDigest([60000, 30001]));
  assert.equal(ethers.dataLength(d), 32);

  // Refusals, not coercions.
  assert.throws(() => encodeWeights(1, [0]), />= 2/);
  assert.throws(() => encodeWeights(2, [1.5, 0]), /integer/);
  assert.throws(() => encodeWeights(2, [0, 2147483648]), /i32 lane range/);
  assert.throws(() => encodeWeights(3, [0, 0]), /3 features/);
  assert.throws(() => decodeWeights(bytes, 3), /expected 3/);
  assert.throws(() => decodeWeights(bytes.slice(0, bytes.length - 1), 2), /expected/);
  assert.throws(() => decodeWeights(new Uint8Array([9, 9, 9]), 2), /header|magic/);
  assert.throws(() => zeroWeights(1), />= 2/);
});

test("ShroudSdk publishes seed weights the node decodes", async () => {
  const { decodeWeights } = await import("../dist/weights.js");
  const sdk = new ShroudSdk({
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    signer: new ethers.Wallet(ethers.id("test").slice(2, 66)),
    provider: { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider,
    chainId: 31337n,
  });
  const { cid, weightsDigest } = await sdk.publishWeights(2, [60000, 30000]);
  // The CID addresses the file (transport, sha256), the digest pins the lanes (keccak):
  // the pair openEpoch needs. `getVerified` proves they belong together.
  const stored = await sdk.shardStore.get(cid);
  assert.equal(cid, ethers.sha256(stored));
  assert.deepEqual(await sdk.shardStore.getVerified(cid, pinPayload(stored).ctDigest), stored);
  assert.deepEqual(decodeWeights(stored, 2), [60000, 30000]);
  assert.equal(weightsDigest.length, 66);
  await assert.rejects(() => sdk.publishWeights(2, [1.5, 0]), /integer/);
});

test("uploadAndMonetize omits the shape proof as empty bytes when none is required", async () => {
  // Full upload path against a fetch-stubbed RPC: task view, contribution view,
  // shapeProofsRequired=false, then a real signed submitContribution whose calldata
  // is decoded back. Without the `?? "0x"` default this dies in the ABI encoder.
  const cipherTask = "0x00000000000000000000000000000000000000c1";
  const vault = "0x00000000000000000000000000000000000000c2";
  const wallet = new ethers.Wallet(ethers.id("upload-test").slice(2, 66));
  const me = await wallet.getAddress();
  const iface = new ethers.Interface(sdkAbi("CipherTask"));
  const sel = (sig: string) => iface.getFunction(sig)!.selector;

  const taskTuple = [
    [
      me, // buyer
      ethers.ZeroAddress, // updateManager
      3, 1, 100, 1, 2, 8, 86400, 3600, 600, 1000, 8000, 1500, 500, 200,
      ethers.ZeroHash, ethers.ZeroHash, 1,
    ],
    1_000_000_000n, 0n, 0n, 0n, 0n, 0n, 0, 0, 0,
    ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash, 1, false,
  ];
  // Note: the stored Contribution keeps `shapeProof` as a bytes32 *digest* of the
  // submitted bytes (the contract hashes on submit), so this fixture uses ZeroHash.
  const emptyContribution = [
    ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash, 0, 0, 0, 0, false, false,
  ];
  let submitted: string | undefined;
  // The provider's transport is stubbed at the FetchRequest layer: ethers v6 never
  // calls global fetch for RPC (it uses its own getUrl), so mocking globalThis.fetch
  // would silently let everything through to the real network.
  const fr = new ethers.FetchRequest("http://stub.invalid");
  fr.getUrlFunc = (async (req: { body?: Uint8Array }) => {
    const serveOne = (payload: { id?: unknown; method: string; params: any[] }): unknown => {
      switch (payload.method) {
        case "eth_chainId":
          return "0x7a69";
        case "eth_blockNumber":
          return "0x2";
        case "eth_getTransactionCount":
          return "0x0";
        case "eth_maxPriorityFeePerGas":
        case "eth_gasPrice":
          return "0x1";
        case "eth_getBlockByNumber":
          return {
            number: "0x2", hash: ethers.ZeroHash, parentHash: ethers.ZeroHash,
            timestamp: "0x1", nonce: "0x0000000000000000", difficulty: "0x0",
            gasLimit: "0xffffffffff", gasUsed: "0x0", miner: ethers.ZeroAddress,
            extraData: "0x", baseFeePerGas: "0x1", receiptsRoot: ethers.ZeroHash,
            stateRoot: ethers.ZeroHash, transactionsRoot: ethers.ZeroHash,
            sha3Uncles: ethers.ZeroHash, logsBloom: "0x" + "0".repeat(512),
            mixHash: ethers.ZeroHash, size: "0x1", totalDifficulty: "0x1",
            uncles: [], transactions: [],
          };
        case "eth_estimateGas":
          return "0x200000";
        case "eth_call": {
          const data: string = payload.params[0].data;
          if (data.startsWith(sel("taskCount"))) return iface.encodeFunctionResult("taskCount", [1n]);
          if (data.startsWith(sel("tasks"))) return iface.encodeFunctionResult("tasks", [taskTuple]);
          if (data.startsWith(sel("contributions"))) {
            return iface.encodeFunctionResult("contributions", [emptyContribution]);
          }
          if (data.startsWith(sel("shapeProofsRequired"))) {
            return iface.encodeFunctionResult("shapeProofsRequired", [false]);
          }
          if (data.startsWith(sel("contributionBondRequired"))) {
            return iface.encodeFunctionResult("contributionBondRequired", [0n]);
          }
          // TOCTOU dry-run: the SDK simulates submitContribution before sending it.
          // Empty returndata is a successful simulation of a state-changing call.
          if (data.startsWith(sel("submitContribution"))) return "0x";
          throw new Error(`stub: unexpected eth_call ${data.slice(0, 10)}`);
        }
        case "eth_sendRawTransaction":
          submitted = payload.params[0];
          return ethers.keccak256(submitted);
        case "eth_getTransactionReceipt":
          return {
            status: "0x1", blockNumber: "0x1", transactionHash: ethers.id("sent-tx"),
            index: "0x0", transactionIndex: "0x0", blockHash: ethers.ZeroHash,
            gasUsed: "0x100000", cumulativeGasUsed: "0x100000",
            logs: [], logsBloom: "0x" + "0".repeat(512),
            contractAddress: null, type: "0x2",
          };
        case "eth_getTransactionByHash":
          return {
            hash: payload.params[0], blockNumber: "0x1", transactionIndex: "0x0",
            from: me, to: cipherTask, value: "0x0", nonce: "0x0", data: "0x",
            gasLimit: "0x200000", maxFeePerGas: "0x1", maxPriorityFeePerGas: "0x1",
            chainId: "0x7a69", type: "0x2", v: "0x0", r: ethers.ZeroHash, s: ethers.ZeroHash,
          };
        default:
          throw new Error(`stub: unhandled method ${payload.method}`);
      }
    };
    const envelope = (id: unknown, result: unknown) => ({
      statusCode: 200,
      statusMessage: "OK",
      headers: {},
      body: ethers.toUtf8Bytes(JSON.stringify({ jsonrpc: "2.0", id: id ?? 1, result })),
    });
    const parsed = JSON.parse(ethers.toUtf8String(req.body ?? new Uint8Array()));
    if (Array.isArray(parsed)) {
      const parts = parsed.map((p) => ({ jsonrpc: "2.0", id: p.id ?? 1, result: serveOne(p) }));
      return {
        statusCode: 200,
        statusMessage: "OK",
        headers: {},
        body: ethers.toUtf8Bytes(JSON.stringify(parts)),
      };
    }
    return envelope(parsed.id, serveOne(parsed));
  }) as unknown as (req: never) => Promise<never>;

  {
    const provider = new ethers.JsonRpcProvider(fr);
    const sdk = new ShroudSdk({
      cipherTask,
      paymentVault: vault,
      signer: new ethers.Wallet(wallet.privateKey, provider),
      provider,
      chainId: 31337n,
    });
    const out = await sdk.uploadAndMonetize([1, 2, 3, 4, 5, 6], 1n, {
      features: 3,
      allowUnencrypted: true,
    });
    assert.ok(submitted, "a transaction was sent");
    const calldata = ethers.Transaction.from(submitted!).data;
    const parsed = iface.parseTransaction({ data: calldata });
    assert.equal(parsed?.args.shapeProof, "0x");
    assert.match(out.contributionTx, /^0x[0-9a-f]{64}$/);
  }
});

test("uploadAndMonetize approves a missing contribution bond before submitting", async () => {
  // Bonded task: the SDK must approve exactly the requirement up front (never a max
  // approval) instead of burning gas on a BondInsufficient revert. The stub serves the
  // bond views plus a minimal ERC-20 and records every transaction in order.
  const cipherTask = "0x00000000000000000000000000000000000000c1";
  const vault = "0x00000000000000000000000000000000000000c2";
  const token = "0x00000000000000000000000000000000000000c3";
  const wallet = new ethers.Wallet(ethers.id("upload-bond-test").slice(2, 66));
  const me = await wallet.getAddress();
  const iface = new ethers.Interface(sdkAbi("CipherTask"));
  const erc20 = new ethers.Interface([
    "function approve(address spender, uint256 amount) returns (bool)",
    "function increaseAllowance(address spender, uint256 addedValue) returns (bool)",
    "function allowance(address owner, address spender) view returns (uint256)",
    "function balanceOf(address account) view returns (uint256)",
  ]);
  const sel = (sig: string) => iface.getFunction(sig)!.selector;
  const taskTuple = [
    [
      me, ethers.ZeroAddress, 3, 1, 100, 1, 2, 8, 86400, 3600, 600, 1000,
      8000, 1500, 500, 200, ethers.ZeroHash, ethers.ZeroHash, 1,
    ],
    1_000_000_000n, 0n, 0n, 0n, 0n, 0n, 0, 0, 0,
    ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash, 1, false,
  ];
  const emptyContribution = [
    ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash, 0, 0, 0, 0, false, false,
  ];
  const sent: { to: string; data: string }[] = [];
  const fr = new ethers.FetchRequest("http://stub.invalid");
  fr.getUrlFunc = (async (req: { body?: Uint8Array }) => {
    const serveOne = (payload: { id?: unknown; method: string; params: any[] }): unknown => {
      switch (payload.method) {
        case "eth_chainId":
          return "0x7a69";
        case "eth_blockNumber":
          return "0x2";
        case "eth_getTransactionCount":
          return "0x0";
        case "eth_maxPriorityFeePerGas":
        case "eth_gasPrice":
          return "0x1";
        case "eth_getBlockByNumber":
          return {
            number: "0x2", hash: ethers.ZeroHash, parentHash: ethers.ZeroHash,
            timestamp: "0x1", nonce: "0x0000000000000000", difficulty: "0x0",
            gasLimit: "0xffffffffff", gasUsed: "0x0", miner: ethers.ZeroAddress,
            extraData: "0x", baseFeePerGas: "0x1", receiptsRoot: ethers.ZeroHash,
            stateRoot: ethers.ZeroHash, transactionsRoot: ethers.ZeroHash,
            sha3Uncles: ethers.ZeroHash, logsBloom: "0x" + "0".repeat(512),
            mixHash: ethers.ZeroHash, size: "0x1", totalDifficulty: "0x1",
            uncles: [], transactions: [],
          };
        case "eth_estimateGas":
          return "0x200000";
        case "eth_call": {
          const to = String(payload.params[0].to).toLowerCase();
          const data: string = payload.params[0].data;
          if (to === cipherTask.toLowerCase()) {
            if (data.startsWith(sel("taskCount"))) return iface.encodeFunctionResult("taskCount", [1n]);
            if (data.startsWith(sel("tasks"))) return iface.encodeFunctionResult("tasks", [taskTuple]);
            if (data.startsWith(sel("contributions"))) {
              return iface.encodeFunctionResult("contributions", [emptyContribution]);
            }
            if (data.startsWith(sel("shapeProofsRequired"))) {
              return iface.encodeFunctionResult("shapeProofsRequired", [false]);
            }
            if (data.startsWith(sel("contributionBondRequired"))) {
              return iface.encodeFunctionResult("contributionBondRequired", [1_000_000n]);
            }
            if (data.startsWith(sel("contributionBondOf"))) {
              return iface.encodeFunctionResult("contributionBondOf", [0n]);
            }
            if (data.startsWith(sel("escrowToken"))) {
              return iface.encodeFunctionResult("escrowToken", [token]);
            }
            // TOCTOU dry-run: the SDK simulates submitContribution before sending it.
            // Empty returndata is a successful simulation of a state-changing call.
            if (data.startsWith(sel("submitContribution"))) return "0x";
          }
          if (to === token.toLowerCase()) {
            if (data.startsWith(erc20.getFunction("balanceOf")!.selector)) {
              return erc20.encodeFunctionResult("balanceOf", [2_000_000n]);
            }
            if (data.startsWith(erc20.getFunction("allowance")!.selector)) {
              return erc20.encodeFunctionResult("allowance", [0n]);
            }
          }
          throw new Error(`stub: unexpected eth_call to=${to} ${data.slice(0, 10)}`);
        }
        case "eth_sendRawTransaction": {
          const raw: string = payload.params[0];
          const parsed = ethers.Transaction.from(raw);
          sent.push({ to: String(parsed.to).toLowerCase(), data: String(parsed.data) });
          return ethers.keccak256(raw);
        }
        case "eth_getTransactionReceipt":
          return {
            status: "0x1", blockNumber: "0x1", transactionHash: ethers.id("sent-tx"),
            index: "0x0", transactionIndex: "0x0", blockHash: ethers.ZeroHash,
            gasUsed: "0x100000", cumulativeGasUsed: "0x100000",
            logs: [], logsBloom: "0x" + "0".repeat(512),
            contractAddress: null, type: "0x2",
          };
        case "eth_getTransactionByHash":
          return {
            hash: payload.params[0], blockNumber: "0x1", transactionIndex: "0x0",
            from: me, to: cipherTask, value: "0x0", nonce: "0x0", data: "0x",
            gasLimit: "0x200000", maxFeePerGas: "0x1", maxPriorityFeePerGas: "0x1",
            chainId: "0x7a69", type: "0x2", v: "0x0", r: ethers.ZeroHash, s: ethers.ZeroHash,
          };
        default:
          throw new Error(`stub: unhandled method ${payload.method}`);
      }
    };
    const envelope = (id: unknown, result: unknown) => ({
      statusCode: 200,
      statusMessage: "OK",
      headers: {},
      body: ethers.toUtf8Bytes(JSON.stringify({ jsonrpc: "2.0", id: id ?? 1, result })),
    });
    const parsed = JSON.parse(ethers.toUtf8String(req.body ?? new Uint8Array()));
    if (Array.isArray(parsed)) {
      const parts = parsed.map((p) => ({ jsonrpc: "2.0", id: p.id ?? 1, result: serveOne(p) }));
      return {
        statusCode: 200,
        statusMessage: "OK",
        headers: {},
        body: ethers.toUtf8Bytes(JSON.stringify(parts)),
      };
    }
    return envelope(parsed.id, serveOne(parsed));
  }) as unknown as (req: never) => Promise<never>;

  {
    const provider = new ethers.JsonRpcProvider(fr);
    const sdk = new ShroudSdk({
      cipherTask,
      paymentVault: vault,
      signer: new ethers.Wallet(wallet.privateKey, provider),
      provider,
      chainId: 31337n,
    });
    const out = await sdk.uploadAndMonetize([1, 2, 3, 4, 5, 6], 1n, {
      features: 3,
      allowUnencrypted: true,
    });
    // Approve first (exact requirement, spender = the task), submit second.
    // The SDK prefers increaseAllowance (USDT-style tokens revert non-zero-to-nonzero
    // approve), falling back to approve only for tokens without the method.
    assert.equal(sent.length, 2);
    const approval = erc20.parseTransaction({ data: sent[0].data });
    assert.equal(sent[0].to, token.toLowerCase());
    assert.equal(approval?.name, "increaseAllowance");
    assert.equal(approval?.args.spender.toLowerCase(), cipherTask.toLowerCase());
    assert.equal(approval?.args.addedValue, 1_000_000n);
    const submission = iface.parseTransaction({ data: sent[1].data });
    assert.equal(sent[1].to, cipherTask.toLowerCase());
    assert.equal(submission?.name, "submitContribution");
    assert.match(out.contributionTx, /^0x[0-9a-f]{64}$/);
  }
});
