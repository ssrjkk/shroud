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
import * as fs from "node:fs/promises";
import * as os from "node:os";
import { fileURLToPath } from "node:url";
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

test("FileShardStore persists across instances and verifies like the memory store", async () => {
  const { FileShardStore } = await import("../dist/file-store.js");
  const dir = await fs.mkdtemp(join(os.tmpdir(), "shroud-filestore-"));
  try {
    const a: ShardStore = new FileShardStore(dir);
    const payload = new TextEncoder().encode("file-backed");
    const { cid, digest } = await a.put(payload);
    assert.equal(digest, ethers.keccak256(payload));
    // A second instance over the same directory sees the object: the directory is the
    // authority, so SDK uploads and node reads stay coherent across processes.
    const b: ShardStore = new FileShardStore(dir);
    assert.deepEqual(await b.get(cid), payload);
    assert.deepEqual(await b.getVerified(cid, digest), payload);
    await assert.rejects(() => b.get(ethers.keccak256(new Uint8Array([9]))), /not found/);
    await assert.rejects(() => b.getVerified(cid, ethers.id("a-different-commit")), /failed integrity check/);
    await assert.rejects(() => b.get("../../etc/passwd"), /unsafe shard digest/);
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
    await assert.rejects(() => store.put(payload), /unusable cid/);
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
  } finally {
    globalThis.fetch = original;
  }
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
  const sdk = new ShroudSdk({
    cipherTask: "0x0000000000000000000000000000000000000001",
    paymentVault: "0x0000000000000000000000000000000000000002",
    signer: new ethers.Wallet(ethers.id("test").slice(2, 66)),
    provider: { getNetwork: async () => ({ chainId: 31337n }) } as unknown as ethers.Provider,
    chainId: 31337n,
  });
  assert.equal(sdk.networkParams, undefined);
});

test("domainSeparator is deterministic", () => {
  const a = domainSeparator("0x0000000000000000000000000000000000000001", 31337n);
  const b = domainSeparator("0x0000000000000000000000000000000000000001", 31337n);
  assert.equal(a, b);
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
  // The CID pins the file, the digest pins the lanes: the pair openEpoch needs.
  const stored = await sdk.shardStore.get(cid);
  assert.equal(ethers.keccak256(stored), cid);
  assert.deepEqual(decodeWeights(stored, 2), [60000, 30000]);
  assert.equal(weightsDigest.length, 66);
  await assert.rejects(() => sdk.publishWeights(2, [1.5, 0]), /integer/);
});
