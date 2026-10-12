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
  /**
   * GET the bytes for `cid`.
   *
   * Part of the interface rather than an optional extra because a re-executing node cannot do its
   * job without it: it has to fetch the committed ciphertext to recompute the epoch and compare
   * digests. It was previously missing from the interface entirely, so the typed API could not
   * express the one operation the protocol exists to support.
   *
   * Throws if the object is absent. `digest` is always the locally computed keccak256 of the
   * payload, which is the value committed on chain — never a digest echoed by the store.
   */
  get(cid: Hex): Promise<Uint8Array>;

  /**
   * GET `cid` and refuse bytes that are not the object `expectedCtDigest` pins.
   *
   * In the interface rather than an extra on one implementation, because re-execution — the
   * protocol's core dispute mechanism — cannot be written against a store that might hand back
   * different bytes under the same address. `expectedCtDigest` is the on-chain `ctDigest`, i.e.
   * keccak256 of the exact payload that was committed; implementations must recompute it locally
   * and throw on a mismatch instead of trusting their own addressing.
   */
  getVerified(cid: Hex, expectedCtDigest: Hex): Promise<Uint8Array>;
}

/** The local FHE encryption abstraction (FHEWasm / relayer in production). */
export interface Encryptor {
  /**
   * Whether this encryptor actually produces ciphertext.
   *
   * Required rather than optional on purpose. `NoopEncryptor` writes the plaintext `f64`s into
   * the payload, which is fine for tests and catastrophic for real data: nothing in the payload
   * marks it as unencrypted, so a client that forgot to pass an encryptor would upload a
   * contributor's rows in cleartext and the chain would record a perfectly normal-looking
   * ciphertext CID for it. Making every implementer state this explicitly lets the SDK refuse the
   * dangerous combination instead of trusting a default.
   */
  readonly providesConfidentiality: boolean;

  /**
   * `keccak256(abi.encode(s_pub))` for the network public key this encryptor encrypts under.
   *
   * Declared by the encryptor rather than the caller, because the encryptor is the only component
   * that knows which key it holds: a client can be configured to check the on-chain pin while
   * encrypting under a completely different key, and comparing a config string to the chain would
   * then prove nothing at all. This is what makes the F-08 key-substitution check bite.
   *
   * Optional only because `NoopEncryptor` has no key at all.
   */
  readonly publicKeyHash?: Hex;

  /**
   * Encrypt `rows` of `features` floats into an on-chain-representable shard.
   *
   * In production this is FHEWasm (browser) or `@zama-fhe` (server). The default `NoopEncryptor`
   * is for local development / tests only - it must never be used with real data.
   */
  encryptRows(data: Float64Array | number[], features: number): Promise<EncryptedShard>;
}

/**
 * What `encryptRows` returns: the bytes to upload, plus the one value only the encryptor can know.
 */
export interface EncryptedShard {
  /**
   * The opaque ciphertext bytes. These go to the DA and are pinned on chain by their
   * `keccak256`, which the SDK computes itself (see `pinPayload`).
   */
  ciphertext: Uint8Array;

  /**
   * Commitment to the contributor's row structure, as the shape proof defines it.
   *
   * The SDK cannot compute this. `CipherTask` stores it as a required `bytes32` and a re-execution
   * decrypts the shard, rebuilds the row root and compares — so the value has to be produced from
   * the *plaintext* rows, by whoever holds them, and it has to be the same commitment the Groth16
   * membership proof binds (`docs/01-architecture.md`, threat A1). Deriving it from the ciphertext
   * bytes instead, which is what this used to do, yields a commitment no honest re-execution can
   * reproduce and no proof can be written against, while still looking perfectly valid on chain.
   */
  rowCommitment: Hex;
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
