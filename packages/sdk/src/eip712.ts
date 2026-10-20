/**
 * EIP-712 helpers for the Shroud PaymentVault slice redemption.
 *
 * The Solidity side computes:
 *   REDEEM_TYPEHASH = keccak256("Redeem(uint256 channelId,address streamer,address node,uint128
 *                                maxCumulative,uint64 unlockAt,uint256 deadline)")
 *   digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
 *
 * `redeemDigest` must produce byte-for-byte the same digest the contract checks, otherwise an
 * ERC-1271 authorisation (`isValidSignature`) will reject the slice.
 *
 * The second half of this module encodes the *other* half of that authorisation: a contract
 * streamer (`CipherTask`, the standard deployment) is authenticated by the 96-byte slice blob it
 * accepts in `isValidSignature`, not by an ECDSA signature. See `encodeSliceSignature`.
 */
import { ethers, type Signer } from "ethers";
import type { Hex, RedeemSlice } from "./types.js";

export const REDEEM_TYPEHASH = ethers.id(
  "Redeem(uint256 channelId,address streamer,address node,uint128 maxCumulative,uint64 unlockAt,uint256 deadline)"
);
const DOMAIN_TYPEHASH = ethers.id(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

export const VAULT_DOMAIN_NAME = "ShroudPaymentVault";
export const VAULT_DOMAIN_VERSION = "1";

/** The full EIP-712 domain used by `PaymentVault`. */
export function vaultDomain(vaultAddress: string, chainId: bigint) {
  return {
    name: VAULT_DOMAIN_NAME,
    version: VAULT_DOMAIN_VERSION,
    chainId,
    verifyingContract: vaultAddress,
  };
}

/** The typed-struct hash for a redeem slice. */
export function redeemStructHash(slice: RedeemSlice): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "address", "address", "uint128", "uint64", "uint256"],
      [
        REDEEM_TYPEHASH,
        slice.channelId,
        slice.streamer,
        slice.node,
        slice.maxCumulative,
        slice.unlockAt,
        slice.deadline,
      ]
    )
  );
}

/** The full EIP-712 digest the vault will accept for a slice. */
export function redeemDigest(slice: RedeemSlice, domainSeparator: Hex): string {
  return ethers.keccak256(
    ethers.concat([ethers.toUtf8Bytes("\x19\x01"), domainSeparator, redeemStructHash(slice)])
  );
}

/** Compute the domain separator for a given chain id + verifying contract. */
export function domainSeparator(vaultAddress: string, chainId: bigint): Hex {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        DOMAIN_TYPEHASH,
        ethers.id(VAULT_DOMAIN_NAME),
        ethers.id(VAULT_DOMAIN_VERSION),
        chainId,
        vaultAddress,
      ]
    )
  );
}

/**
 * Sign a redeem slice for an EOA streamer.
 *
 * This is the *only* path that produces a signature the vault accepts from a wallet: when the
 * channel's `streamer` has no code, `PaymentVault._authorize` `ecrecover`s a 65-byte ECDSA
 * signature and compares it to the streamer. When the streamer is a contract — which is the
 * standard deployment, where `CipherTask` opens every node reward channel — the vault instead
 * calls `isValidSignature` on it, and a wallet signature is useless there because the contract
 * streamer has no key: it only authorises the slice blob it recorded in `finalizeEpoch`.
 * Use `encodeSliceSignature` for that case.
 */
export async function signRedeemSlice(
  streamer: Signer,
  slice: RedeemSlice,
  vaultAddress: string,
  chainId: bigint
): Promise<Hex> {
  const domain = vaultDomain(vaultAddress, chainId);
  const types = {
    Redeem: [
      { name: "channelId", type: "uint256" },
      { name: "streamer", type: "address" },
      { name: "node", type: "address" },
      { name: "maxCumulative", type: "uint128" },
      { name: "unlockAt", type: "uint64" },
      { name: "deadline", type: "uint256" },
    ],
  };
  const value = {
    channelId: slice.channelId,
    streamer: slice.streamer,
    node: slice.node,
    maxCumulative: slice.maxCumulative,
    unlockAt: slice.unlockAt,
    deadline: slice.deadline,
  };
  const signature = await streamer.signTypedData(domain, types, value);
  return signature as Hex;
}

/* ================================================================== */
/*                    Node registration proof-of-possession             */
/* ================================================================== */

/**
 * The message a node's proof-of-possession signature covers.
 *
 * `CipherTask.registerNodeWithPop` recomputes it as
 * `keccak256(abi.encode(taskId, blsPubKey, node, chainId, cipherTask))` and checks
 * the EIP-191 personal-signature over it. The BLS key is otherwise self-declared:
 * binding it to the node's own key proves one live signer per identity and makes
 * key theft repudiable.
 *
 * It is exported so the exact bytes can be pinned - the same string is written down
 * in the contract, in the contracts' suite and here, and a change to one of them
 * alone would make every registration the SDK submits fail.
 */
export function popDigest(
  taskId: bigint,
  blsPubKey: Hex,
  node: string,
  chainId: bigint,
  cipherTask: string
): Hex {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "bytes32", "address", "uint256", "address"],
      [taskId, blsPubKey, node, chainId, cipherTask]
    )
  ) as Hex;
}

/* ================================================================== */
/*                    ERC-1271 slice authorisation                     */
/* ================================================================== */

/**
 * Length of the blob `CipherTask.isValidSignature` accepts, in bytes.
 *
 * Three left-aligned 32-byte words (`channelId`, `sliceIndex`, `amount`); anything else is
 * rejected with `0xffffffff` before it is even decoded.
 */
export const SLICE_SIGNATURE_BYTES = 96;

/**
 * The deadline a contract-streamer slice must carry.
 *
 * `CipherTask._decodeSliceFull` fixes it at `type(uint256).max` — authorised slices deliberately
 * never expire — so the digest it recomputes, and therefore the digest the vault computes, uses
 * exactly this value. A node that passes any other deadline gets `InvalidSignature`.
 */
export const SLICE_DEADLINE: bigint = ethers.MaxUint256;

/** The slice index `CipherTask` authorises: `finalizeEpoch` writes only index 0. */
export const SLICE_INDEX: bigint = 0n;

const MAX_UINT256 = ethers.MaxUint256;
const MAX_UINT128 = (1n << 128n) - 1n;

/**
 * The `signature` argument `redeem` must carry when the streamer is `CipherTask`.
 *
 * This is not a signature in the ECDSA sense: `PaymentVault._authorize` hands these bytes to the
 * streamer contract's `isValidSignature`, and `CipherTask` checks them against the slice it
 * recorded in `finalizeEpoch`, then re-derives the vault's EIP-712 digest from them. The encoding
 * is `abi.encode(uint256 channelId, uint256 sliceIndex, uint128 amount)`, which for three static
 * types is exactly 96 raw bytes — identical to the word-sliced form the contract reads.
 */
export function encodeSliceSignature(channelId: bigint, sliceIndex: bigint, amount: bigint): Hex {
  // Out-of-range values are refused rather than wrapped: `CipherTask` reads these words with
  // `uint128(uint256(...))`, so an amount above the uint128 would silently authorise a *different*
  // slice than the one the caller meant to redeem.
  if (typeof channelId !== "bigint" || channelId < 0n || channelId > MAX_UINT256) {
    throw new Error(`channelId must be a non-negative uint256, got ${channelId}`);
  }
  if (typeof sliceIndex !== "bigint" || sliceIndex < 0n || sliceIndex > MAX_UINT256) {
    throw new Error(`sliceIndex must be a non-negative uint256, got ${sliceIndex}`);
  }
  if (typeof amount !== "bigint" || amount < 0n || amount > MAX_UINT128) {
    throw new Error(`amount ${amount} does not fit the uint128 the contract decodes`);
  }
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "uint256", "uint128"],
    [channelId, sliceIndex, amount]
  ) as Hex;
}

/** Inverse of `encodeSliceSignature`, reading the words the Solidity side reads. */
export function decodeSliceSignature(signature: Hex): {
  channelId: bigint;
  sliceIndex: bigint;
  amount: bigint;
} {
  const bytes = ethers.getBytes(signature);
  if (bytes.length !== SLICE_SIGNATURE_BYTES) {
    throw new Error(
      `a contract-streamer slice signature is exactly ${SLICE_SIGNATURE_BYTES} bytes, got ${bytes.length}`
    );
  }
  const word = (offset: number): bigint => {
    let value = 0n;
    for (let i = offset; i < offset + 32; i++) value = (value << 8n) | BigInt(bytes[i]);
    return value;
  };
  const channelId = word(0);
  const sliceIndex = word(32);
  const amount = word(64);
  if (amount > MAX_UINT128) {
    throw new Error(`slice amount ${amount} does not fit the uint128 the contract decodes`);
  }
  return { channelId, sliceIndex, amount };
}
