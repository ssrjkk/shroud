/**
 * Local FHE encryption abstraction.
 *
 * Production builds use FHEWasm in the browser or `@zama-fhe/relayer-sdk` on a server so that
 * plaintext never leaves the client. The SDK only ever ships the opaque ciphertext bytes.
 *
 * `NoopEncryptor` exists so the orchestration path is runnable end-to-end in tests without a
 * coprocessor. It is NOT encryption: it serialises the plaintext. It declares
 * `providesConfidentiality = false` so `ShroudSdk` will refuse to submit its output unless the
 * caller explicitly opts in, which is the only thing standing between a forgotten config and a
 * cleartext upload.
 *
 * An encryptor returns the `rowCommitment` as well as the ciphertext bytes. That is deliberate:
 * the commitment is over the contributor's *plaintext* rows, so no code that only ever sees the
 * ciphertext — including this SDK — can compute it honestly.
 */
import { ethers } from "ethers";
import type { EncryptedShard, Encryptor, Hex } from "./types.js";

export class NoopEncryptor implements Encryptor {
  // Loud, not silent: this is the flag `ShroudSdk` checks before it will submit a shard.
  readonly providesConfidentiality = false;

  async encryptRows(data: Float64Array | number[], features: number): Promise<EncryptedShard> {
    // Validate like the confidential path does: a malformed header (Infinity row count,
    // fractional rows, NaN payload) would otherwise upload successfully and fail only at
    // the node's decoder — or worse, decode differently there than here.
    if (!Number.isInteger(features) || features <= 0) {
      throw new Error(`features must be a positive integer, got ${features}`);
    }
    const arr = data instanceof Float64Array ? data : new Float64Array(data);
    if (arr.length === 0 || arr.length % features !== 0) {
      throw new Error(`data length ${arr.length} is not a positive multiple of features ${features}`);
    }
    for (let i = 0; i < arr.length; i++) {
      if (!Number.isFinite(arr[i])) throw new Error(`row value at index ${i} is not finite`);
    }
    const n = arr.length / features;
    const head = new TextEncoder().encode(`shroud/noop/v1\0${features}\0${n}\0`);
    const buf = new Uint8Array(head.length + arr.length * 8);
    buf.set(head, 0);
    for (let i = 0; i < arr.length; i++) {
      new DataView(buf.buffer, head.length + i * 8, 8).setFloat64(0, arr[i], true);
    }
    return { ciphertext: buf, rowCommitment: noopRowCommitment(arr) };
  }
}

/**
 * The `rowCommitment` the noop path reports.
 *
 * It is a `keccak256` over the row matrix, which is *not* the Pedersen/label commitment the
 * Groth16 membership proof binds, and it cannot be: the real commitment hides the labels. It is
 * deterministic and it commits to exactly the rows that were uploaded, which is all the development
 * path needs - a real `Encryptor` replaces it, and nothing that verifies a shape proof may use this.
 */
export function noopRowCommitment(rows: Float64Array): Hex {
  const tag = new TextEncoder().encode("shroud/noop-row/v1\0");
  const matrix = new Uint8Array(rows.buffer, rows.byteOffset, rows.byteLength);
  return ethers.keccak256(ethers.concat([tag, matrix])) as Hex;
}

/** The on-chain `ctDigest` for a DA payload: keccak256 of the exact bytes that were uploaded. */
export function pinPayload(payload: Uint8Array): { ctDigest: Hex } {
  return { ctDigest: ethers.keccak256(payload) as Hex };
}
