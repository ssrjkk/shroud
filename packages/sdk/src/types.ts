/**
 * Shared types for @shroud/sdk.
 *
 * These mirror the on-chain structs in `packages/contracts/src/interfaces/ICipherTask.sol`
 * and `PaymentVault.sol`. Keep them in lockstep with the Solidity definitions.
 */

/** A hex string, e.g. `0x...`. */
export type Hex = string;

/** On-chain task parameters, mirroring `ICipherTask.TaskParams`. */
export interface TaskParams {
  buyer: string;
  updateManager: string;
  epochs: number;
  minContributors: number;
  maxContributors: number;
  minRowsPerShard: number;
  features: number;
  labelBits: 8 | 16;
  contributionWindow: number;
  epochDuration: number;
  disputeWindow: number;
  pricePerRow: number;
  userShareBps: number;
  nodeShareBps: number;
  committeeShareBps: number;
  reexecutionBps: number;
  modelSpecCid: Hex;
  shapeRoot: Hex;
  updateMode: number;
}

/** A single encrypted shard ready to be uploaded and committed. */
export interface PreparedShard {
  /** Content-addressed object the ciphertext will be uploaded under. */
  ciphertextCid: Hex;
  /** keccak256 of the DA object bytes - pins the payload. */
  ctDigest: Hex;
  /** Groth16 proof that the decrypted shard holds >= minRowsPerShard rows. */
  shapeProof: Hex;
  /** Commitment to the row Merkle root. */
  rowCommitment: Hex;
  /** Row count the client claims. */
  rows: number;
}

/** The content-addressed store abstraction (ShardStore / DA). */
export interface ShardStore {
  /** PUT `payload`, returning the content-address (CID) of the object. */
  put(payload: Uint8Array): Promise<{ cid: Hex; digest: Hex }>;
}

/** The local FHE encryption abstraction (FHEWasm / relayer in production). */
export interface Encryptor {
  /**
   * Encrypt `rows` of `features` floats into an on-chain-representable ciphertext blob.
   *
   * The bytes are opaque to the SDK; they are committed to the DA and pinned by their digest.
   * In production this is FHEWasm (browser) or `@zama-fhe/relayer-sdk` (server). The default
   * `NoopEncryptor` is for local development / tests only - it must never be used with real data.
   */
  encryptRows(data: Float64Array | number[], features: number): Promise<Uint8Array>;
}

/** Result of `uploadAndMonetize`. */
export interface UploadResult {
  taskId: bigint;
  ciphertextCid: Hex;
  ctDigest: Hex;
  rows: number;
  /** Transaction hash of the `submitContribution` call. */
  contributionTx: string;
}

/** EIP-712 slice data for the PaymentVault redeem binding. */
export interface RedeemSlice {
  channelId: bigint;
  streamer: string;
  node: string;
  maxCumulative: bigint;
  unlockAt: bigint;
  deadline: bigint;
}
