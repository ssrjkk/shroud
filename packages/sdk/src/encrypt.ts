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
 */
import { ethers } from "ethers";
import type { Encryptor } from "./types.js";

export class NoopEncryptor implements Encryptor {
  // Loud, not silent: this is the flag `ShroudSdk` checks before it will submit a shard.
  readonly providesConfidentiality = false;

  async encryptRows(data: Float64Array | number[], features: number): Promise<Uint8Array> {
    const arr = data instanceof Float64Array ? data : new Float64Array(data);
    const n = arr.length / features;
    const head = new TextEncoder().encode(`shroud/noop/v1\0${features}\0${n}\0`);
    const buf = new Uint8Array(head.length + arr.length * 8);
    buf.set(head, 0);
    for (let i = 0; i < arr.length; i++) {
      new DataView(buf.buffer, head.length + i * 8, 8).setFloat64(0, arr[i], true);
    }
    return buf;
  }
}

/** Derive the on-chain `PreparedShard` from a payload, mirroring `CipherTask._appendLeaf`. */
export function pinPayload(payload: Uint8Array): { ctDigest: string; rowCommitment: string } {
  // ctDigest pins the exact DA object bytes.
  const ctDigest = ethers.keccak256(payload);
  // rowCommitment is a commitment over the decrypted row structure; for the noop path we bind
  // it to the plaintext digest so a re-execution can still check the structure.
  const rowCommitment = ethers.keccak256(ethers.concat([payload, ctDigest]));
  return { ctDigest, rowCommitment };
}
