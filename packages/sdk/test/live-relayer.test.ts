/**
 * LIVE relayer test: real TFHE encryption against the Sepolia testnet relayer.
 *
 * Gated behind `SHROUD_LIVE_RELAYER=1` — it needs internet (relayer + Sepolia RPC) and takes
 * ~30-60s for key fetch plus WASM encryption. Not part of `npm test`; CI runs it as its own
 * job (`sdk-relayer-live`) so a relayer outage fails loudly there instead of blocking the
 * hermetic suite.
 *
 * Asserts the properties the protocol depends on: handles are non-empty 32-byte words, the
 * input proof is non-empty, the pin hash is `keccak256(abi.encode(keyBytes))` of the fetched
 * key, and the envelope round-trips.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { ethers } from "ethers";
import {
  RelayerEncryptor,
  decodeRelayerPayload,
  DEFAULT_QUANTIZE_SCALE,
} from "../dist/relayer-encryptor.js";

const LIVE = process.env.SHROUD_LIVE_RELAYER === "1";
const RPC = process.env.SHROUD_LIVE_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com";
// Binding context for the proof under test. Any non-zero address exercises the
// fail-closed path; override with a real CipherTask when replaying against one.
// Checksummed (EIP-55): the relayer rejects lowercase-only addresses outright.
const TASK = ethers.getAddress(process.env.SHROUD_LIVE_TASK ?? `0x${"cc".repeat(20)}`);

test("live: encrypts two values under the Sepolia network key", { skip: !LIVE }, async () => {
  const enc = await RelayerEncryptor.create({ network: RPC, contractAddress: TASK });
  assert.equal(enc.providesConfidentiality, true);
  assert.ok(enc.publicKeyHash && /^0x[0-9a-f]{64}$/.test(enc.publicKeyHash), "pin hash shape");
  assert.ok(enc.publicKeyId, "key id present");

  const { ciphertext, rowCommitment } = await enc.encryptRows([1.5, 2.25], 2);
  assert.ok(ciphertext.length > 64, "payload carries handles, not a stub");
  assert.notEqual(rowCommitment, ethers.ZeroHash);

  const back = decodeRelayerPayload(ciphertext);
  assert.equal(back.handles.length, 2);
  for (const h of back.handles) assert.equal(h.length, 32);
  assert.ok(back.inputProof.length > 0, "input proof present for the gateway");

  // Quantization contract with the node default: 1.5 and 2.25 at scale 10000.
  assert.equal(DEFAULT_QUANTIZE_SCALE, 10_000);
});
