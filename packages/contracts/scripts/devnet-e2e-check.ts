import { ethers } from "hardhat";
import { readFileSync } from "fs";
import { join } from "path";

function bytes32Of(n: number | string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(`Shroud/test/${n}`));
}
function proofRef(n: number | bigint): string {
  const tail = ethers.zeroPadValue(ethers.toBeHex(n), 28).slice(2);
  return `0x53544152${tail}`;
}

async function main() {
  const addrs = JSON.parse(readFileSync(join(__dirname, "../../../infra/devnet/addresses.json"), "utf8"));
  const [buyer, alice, bob, node] = await ethers.getSigners();
  const token = await ethers.getContractAt("TestToken", addrs.token);
  const task = await ethers.getContractAt("CipherTask", addrs.cipherTask);
  const vault = await ethers.getContractAt("PaymentVault", addrs.vault);

  const escrow = 1_000_000_000n;
  await (await token.mint(buyer.address, escrow)).wait();
  await (await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256)).wait();
  const bond: bigint = await vault.REGISTRATION_BOND();
  await (await token.mint(node.address, bond)).wait();
  await (await token.connect(node).approve(await vault.getAddress(), ethers.MaxUint256)).wait();

  await (
    await task.connect(buyer).createTask(escrow, {
      buyer: buyer.address,
      updateManager: ethers.ZeroAddress,
      epochs: 1,
      minContributors: 1,
      maxContributors: 100,
      minRowsPerShard: 100,
      features: 33,
      labelBits: 8,
      contributionWindow: 86400,
      epochDuration: 3600,
      disputeWindow: 600,
      pricePerRow: 1000,
      userShareBps: 8000,
      nodeShareBps: 1500,
      committeeShareBps: 500,
      reexecutionBps: 200,
      modelSpecCid: bytes32Of("model-spec"),
      shapeRoot: bytes32Of("shape-root"),
      updateMode: 1,
    })
  ).wait();
  const id = await task.taskCount();
  console.log("task", id.toString(), "created");

  await (
    await task
      .connect(alice)
      .submitContribution(id, bytes32Of(1), bytes32Of(11), "0x53544152" + "11".repeat(64), bytes32Of(7), 1000)
  ).wait();
  await (await task.connect(buyer).sealTask(id)).wait();
  console.log("sealed, ctRoot", await task.ctRootOf(id));

  await (await task.connect(node).registerNode(id, bytes32Of("devnet-node"))).wait();
  console.log("node registered, bond", (await vault.nodeBond(id, node.address)).toString());

  console.log("DEVNET E2E OK");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
