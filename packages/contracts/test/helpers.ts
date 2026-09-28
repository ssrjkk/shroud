import { ethers, fhevm } from "hardhat";

/** "STAR" — the magic prefix `MockStarkVerifier` requires on every accepted proof blob. */
export const STARK_MAGIC = "0x53544152";

/** Deterministic 32-byte value from a small integer or label, for readable test fixtures. */
export function bytes32Of(n: number | bigint | string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(`Shroud/test/${n}`));
}

/** A syntactically valid `bytes` blob carrying the STARK magic prefix. */
export function proofFor(n: number | bigint, words = 64): string {
  const body = "11".repeat(words);
  return `${STARK_MAGIC}${body}${ethers.zeroPadValue(ethers.toBeHex(n), 32).slice(2)}`.slice(0, 2 + 2 + words * 2);
}

/**
 * The 32-byte proof *reference* `CipherTask.commitEpoch` takes.
 *
 * A single-segment STARK is far larger than 32 bytes, so the contract never accepts the proof
 * itself — it accepts a fixed-size reference (a STARK digest, or the Merkle root over the
 * segment proofs of a segmented proof) and lets the verifier resolve it. The magic prefix is
 * kept in the high bytes so `MockStarkVerifier`, which checks for it, still accepts the value.
 */
export function proofRef(n: number | bigint): string {
  const tail = ethers.zeroPadValue(ethers.toBeHex(n), 28).slice(2); // 28 bytes after the 4-byte magic
  return `${STARK_MAGIC}${tail}`;
}

export function encState(n: number | bigint): string {
  return bytes32Of(n);
}

/**
 * Mint a genuine fhEVM `externalEuint64` for `contractAddress`, owned by `userAddress`.
 *
 * `CipherTask.openEpoch` forwards this pair into `FHE.fromExternal`, and the coprocessor
 * ACL-checks the handle: a fabricated `bytes32` is rejected outright. The handle therefore has to
 * be produced by the input verifier, which is exactly what `createEncryptedInput` drives. Mock
 * mode keeps this fully in-process, so no relayer key material is involved in tests.
 */
export async function externalUint64(contractAddress: string, userAddress: string, value: bigint) {
  const input = fhevm.createEncryptedInput(contractAddress, userAddress);
  input.add64(value);
  const { handles, inputProof } = await input.encrypt();
  return { handle: handles[0], proof: inputProof };
}

/** A `bytes4` abort reason from a human-readable label. */
export function reason4(label: string): string {
  return ethers.id(label).slice(0, 10);
}

/** The domain separator of `PaymentVault`, needed to sign epoch reward slices off-chain. */
export function sliceDomain(vaultAddress: string, chainId: number | bigint) {
  const domainTypehash = ethers.keccak256(ethers.toUtf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
  const name = ethers.keccak256(ethers.toUtf8Bytes("ShroudPaymentVault"));
  const version = ethers.keccak256(ethers.toUtf8Bytes("1"));
  return {
    name: "ShroudPaymentVault",
    version: "1",
    chainId,
    verifyingContract: vaultAddress,
    domainSeparator: ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "bytes32", "uint256", "address"], [domainTypehash, name, version, chainId, vaultAddress])
    ),
  };
}

export const REDEEM_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes("Redeem(uint256 channelId,address streamer,address node,uint128 maxCumulative,uint64 unlockAt,uint256 deadline)")
);

/** The digest `PaymentVault.redeem` will check for a slice. */
export function redeemDigest(args: {
  domainSeparator: string;
  channelId: bigint;
  streamer: string;
  node: string;
  maxCumulative: bigint;
  unlockAt: bigint;
  deadline: bigint;
}): string {
  const structHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "address", "address", "uint128", "uint64", "uint256"],
      [REDEEM_TYPEHASH, args.channelId, args.streamer, args.node, args.maxCumulative, args.unlockAt, args.deadline]
    )
  );
  return ethers.keccak256(ethers.concat([ethers.toUtf8Bytes("\x19\x01"), args.domainSeparator, structHash]));
}

/** Default task parameters. Shares: 80% users, 15% nodes, 5% committee. */
export function params(buyer: string, overrides: Partial<Record<string, unknown>> = {}) {
  return {
    buyer,
    updateManager: ethers.ZeroAddress,
    epochs: 3,
    minContributors: 1,
    maxContributors: 100,
    minRowsPerShard: 100,
    features: 33,
    labelBits: 8,
    contributionWindow: 86_400,
    epochDuration: 3600,
    disputeWindow: 600,
    pricePerRow: 1_000,
    userShareBps: 8_000,
    nodeShareBps: 1_500,
    committeeShareBps: 500,
    reexecutionBps: 200,
    modelSpecCid: bytes32Of("model-spec"),
    shapeRoot: bytes32Of("shape-root"),
    updateMode: 1, // MiniBatch
    ...overrides
  };
}
