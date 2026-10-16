/**
 * Weight-vector files (`shroud/weights/v1`): the buyer-side half of the execution handshake.
 *
 * The Rust node (`node/src/fhe.rs`, `Weights::{encode, decode, digest}`) reads the seed
 * weights `openEpoch` pins and writes every epoch's updated weights in exactly this layout,
 * so this module mirrors it byte for byte:
 *
 * ```
 * "shroud/weights/v1\0" | features u32-LE | lane count u32-LE | lanes… u32-LE
 * ```
 *
 * Lanes are `i32` two's complement in `u32` words (linear models legitimately go negative).
 * This module accepts lane values in the signed `[-2^31, 2^31 - 1]` range — the range a
 * fixed-point model actually produces — and stores the bit pattern. Anything else
 * (fractions, out-of-range integers, non-numbers) throws: a silently wrapped lane would
 * train every node on a different model while pinning the same digest shape.
 *
 * `weightsDigest` is `keccak256` over the lane words only — the `weightsDigest`
 * `commitEpoch` stores and the next epoch binds as `lastWeightsDigest`. The DA object id
 * (`encWeightsCid`) is whatever the shard store addresses the file under (sha256 for the
 * development stores, the service's sha3-256 in production) — an opaque transport address,
 * never the pin. `publishWeights` returns both, from the store and from `weightsDigest`.
 */
import { ethers } from "ethers";
import type { Hex } from "./types.js";

/** Envelope magic, byte-for-byte what the node expects. */
export const WEIGHTS_MAGIC = "shroud/weights/v1\0";

/** Genesis weights: all-zero lanes. Valid whenever the task pins no seed of its own. */
export function zeroWeights(features: number): number[] {
  if (!Number.isInteger(features) || features < 2) {
    throw new Error(`features must be an integer >= 2, got ${features}`);
  }
  return new Array<number>(features).fill(0);
}

function checkedLane(v: number, index: number): number {
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new Error(`lane ${index} is not an integer (${String(v)})`);
  }
  if (v < -2_147_483_648 || v > 2_147_483_647) {
    throw new Error(`lane ${index} value ${v} is outside the i32 lane range`);
  }
  return v >>> 0;
}

/**
 * Encode `lanes` (length `features`) into a `shroud/weights/v1` file.
 *
 * `features` must equal `lanes.length` and be >= 2 (at least one input plus the bias):
 * the node rejects anything else as a shape error, so this refuses first, without I/O.
 */
export function encodeWeights(features: number, lanes: number[] | Int32Array): Uint8Array {
  if (!Number.isInteger(features) || features < 2) {
    throw new Error(`features must be an integer >= 2, got ${features}`);
  }
  const list = Array.from(lanes);
  if (list.length !== features) {
    throw new Error(`got ${list.length} lanes for ${features} features`);
  }
  const head = new TextEncoder().encode(WEIGHTS_MAGIC);
  const out = new Uint8Array(head.length + 8 + list.length * 4);
  out.set(head, 0);
  const w = new DataView(out.buffer, out.byteOffset);
  w.setUint32(head.length, features, true);
  w.setUint32(head.length + 4, list.length, true);
  for (let i = 0; i < list.length; i++) {
    w.setUint32(head.length + 8 + i * 4, checkedLane(list[i], i), true);
  }
  return out;
}

/** Decode and validate a weight file. Mirrors the node's `Weights::decode`. */
export function decodeWeights(bytes: Uint8Array, expectedFeatures: number): number[] {
  const fail = (why: string): never => {
    throw new Error(`invalid weights file: ${why}`);
  };
  const head = new TextEncoder().encode(WEIGHTS_MAGIC);
  if (bytes.length < head.length + 8) fail(`shorter than the header (${bytes.length} bytes)`);
  for (let i = 0; i < head.length; i++) {
    if (bytes[i] !== head[i]) fail("bad magic");
  }
  const r = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const features = r.getUint32(head.length, true);
  const count = r.getUint32(head.length + 4, true);
  if (features !== expectedFeatures) {
    fail(`holds ${features} features, expected ${expectedFeatures}`);
  }
  if (count !== features) fail(`holds ${count} lanes for ${features} features`);
  if (bytes.length !== head.length + 8 + count * 4) {
    fail(`is ${bytes.length} bytes, expected ${head.length + 8 + count * 4} for ${count} lanes`);
  }
  const lanes: number[] = [];
  for (let i = 0; i < count; i++) {
    // Unsigned word back to the signed lane: the node's i32 in u32 clothing.
    lanes.push((r.getUint32(head.length + 8 + i * 4, true) | 0));
  }
  return lanes;
}

/**
 * `keccak256` over the lane words, little-endian — the `weightsDigest` for `openEpoch`
 * (seed) and the value `commitEpoch` stores. The file CID (`encWeightsCid`) is the hash
 * of the whole file instead; do not confuse the two.
 */
export function weightsDigest(lanes: number[] | Int32Array): Hex {
  const list = Array.from(lanes);
  const buf = new Uint8Array(list.length * 4);
  const w = new DataView(buf.buffer);
  for (let i = 0; i < list.length; i++) w.setUint32(i * 4, checkedLane(list[i], i), true);
  return ethers.keccak256(buf) as Hex;
}
