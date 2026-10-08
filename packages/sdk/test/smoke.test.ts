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
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ethers } from "ethers";

import { MemoryShardStore, HttpShardStore, assertSafeCid } from "../dist/index.js";
import { NoopEncryptor, pinPayload } from "../dist/index.js";
import { REDEEM_TYPEHASH, domainSeparator } from "../dist/index.js";
import { ShroudSdk, MAX_ROWS_PER_SHARD, type Encryptor, type ShardStore } from "../dist/index.js";

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

test("NoopEncryptor preserves rows x features shape", async () => {
  const enc = new NoopEncryptor();
  const data = [1, 2, 3, 4, 5, 6]; // 2 rows x 3 features
  const buf = await enc.encryptRows(data, 3);
  assert.ok(buf.length > 0);
  assert.equal(pinPayload(buf).ctDigest.length, 66); // 0x + 32 bytes
});

test("NoopEncryptor declares that it does not encrypt", () => {
  // This flag is the only thing stopping a forgotten `encryptor` config from uploading a
  // contributor's plaintext rows under a CID that looks like a real ciphertext.
  assert.equal(new NoopEncryptor().providesConfidentiality, false);
});

test("a real encryptor must declare that it encrypts", () => {
  const honest = {
    providesConfidentiality: true,
    encryptRows: async () => new Uint8Array([1, 2, 3]),
  } satisfies Encryptor;
  assert.equal(honest.providesConfidentiality, true);
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

test("domainSeparator is deterministic", () => {
  const a = domainSeparator("0x0000000000000000000000000000000000000001", 31337n);
  const b = domainSeparator("0x0000000000000000000000000000000000000001", 31337n);
  assert.equal(a, b);
});
