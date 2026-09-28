/**
 * EIP-712 helpers for the CipherMesh PaymentVault slice redemption.
 *
 * The Solidity side computes:
 *   REDEEM_TYPEHASH = keccak256("Redeem(uint256 channelId,address streamer,address node,uint128
 *                                maxCumulative,uint64 unlockAt,uint256 deadline)")
 *   digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
 *
 * `sliceDigest` must produce byte-for-byte the same digest the contract checks, otherwise an
 * ERC-1271 authorisation (`isValidSignature`) will reject the slice.
 */
import { ethers, type Signer } from "ethers";
import type { Hex, RedeemSlice } from "./types.js";

export const REDEEM_TYPEHASH = ethers.id(
  "Redeem(uint256 channelId,address streamer,address node,uint128 maxCumulative,uint64 unlockAt,uint256 deadline)"
);
const DOMAIN_TYPEHASH = ethers.id(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

export const VAULT_DOMAIN_NAME = "CipherMeshPaymentVault";
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

/** Sign a redeem slice for the streamer, producing the EIP-712 signature. */
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
