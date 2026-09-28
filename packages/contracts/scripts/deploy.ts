/**
 * Deploy the Shroud devnet contracts and write their addresses to
 * `infra/devnet/addresses.json` so the sequencer, SDK and Rust nodes can find them.
 *
 * Run against the hardhat network:
 *   npx hardhat run scripts/deploy.ts
 *
 * The devnet uses the in-process FHE mock coprocessor (the `@fhevm/hardhat-plugin` devnet), so
 * no external KMS is required. In production the same bytecode runs against the Zama coprocessor
 * with a KMS back end.
 */
import { ethers } from "hardhat";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const OUT = join(__dirname, "../../../infra/devnet/addresses.json");

function h(s: string): string {
  return ethers.id(`Shroud/devnet/${s}`);
}

async function main() {
  const [owner, buyer, committee, treasury] = await ethers.getSigners();

  const token = await ethers.deployContract("TestToken");
  const vault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
  const verifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
  const bls = await ethers.deployContract("MockBLS");
  const gate = await ethers.deployContract("DecryptionGate", [await bls.getAddress(), h("bls-agg"), 1]);
  const net = await ethers.deployContract("NetworkParams", [owner.address]);
  const task = await ethers.deployContract("CipherTask", [
    await token.getAddress(),
    await vault.getAddress(),
    await verifier.getAddress(),
    await gate.getAddress(),
    treasury.address,
    true,
  ]);

  await vault.setTaskManager(await task.getAddress());
  await gate.setCipherTask(await task.getAddress());
  await gate.initialize(committee.address, [committee.address]);

  await net.initialize({
    chainId: 0,
    keyVersion: 1,
    fhePublicKeyHash: h("s_pub-v1"),
    committeeAggregateKey: h("bls-agg"),
    committeeThreshold: 1,
    committeeSize: 7,
    maxProofBytes: 48_576,
    maxCiphertextBytes: 1 << 20,
    maxFeatures: 512,
    activatedAt: 0,
    active: true,
  });

  const chainId = (await ethers.provider.getNetwork()).chainId;
  const addresses = {
    chainId: Number(chainId),
    token: await token.getAddress(),
    vault: await vault.getAddress(),
    verifier: await verifier.getAddress(),
    bls: await bls.getAddress(),
    gate: await gate.getAddress(),
    networkParams: await net.getAddress(),
    cipherTask: await task.getAddress(),
    owner: owner.address,
    buyer: buyer.address,
    committee: committee.address,
    treasury: treasury.address,
  };

  mkdirSync(join(__dirname, "../../../infra/devnet"), { recursive: true });
  writeFileSync(OUT, JSON.stringify(addresses, null, 2));
  console.log(`deployed Shroud devnet contracts; addresses written to ${OUT}`);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
