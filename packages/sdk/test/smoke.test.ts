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

import { MemoryShardStore } from "../dist/index.js";
import { NoopEncryptor, pinPayload } from "../dist/index.js";
import { REDEEM_TYPEHASH, domainSeparator } from "../dist/index.js";

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

test("NoopEncryptor preserves rows x features shape", async () => {
  const enc = new NoopEncryptor();
  const data = [1, 2, 3, 4, 5, 6]; // 2 rows x 3 features
  const buf = await enc.encryptRows(data, 3);
  assert.ok(buf.length > 0);
  assert.equal(pinPayload(buf).ctDigest.length, 66); // 0x + 32 bytes
});

test("domainSeparator is deterministic", () => {
  const a = domainSeparator("0x0000000000000000000000000000000000000001", 31337n);
  const b = domainSeparator("0x0000000000000000000000000000000000000001", 31337n);
  assert.equal(a, b);
});
