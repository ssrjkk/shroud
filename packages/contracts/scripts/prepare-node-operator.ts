/**
 * Fund the Rust node's devnet operator (hardhat#1) with its registration bond and approve the
 * vault to pull it, so the live-node CI job can assert a real `registerNode` round trip.
 *
 * Idempotent: tops up only the shortfall and approves only when short, so reruns converge
 * instead of double-spending. Run after `deploy:devnet` against the same chain:
 *
 *   npx hardhat run scripts/prepare-node-operator.ts --network localhost
 */
import { ethers } from "hardhat";
import { readFileSync } from "fs";
import { join } from "path";

const OUT = join(__dirname, "../../../infra/devnet/addresses.json");
// hardhat#1: the address compose passes as CM_OPERATOR_KEY.
const OPERATOR_KEY =
  process.env.CM_OPERATOR_KEY ??
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

async function main() {
  const addrs = JSON.parse(readFileSync(OUT, "utf8"));
  const provider = ethers.provider;
  const operator = new ethers.Wallet(OPERATOR_KEY, provider);
  const operatorAddr = await operator.getAddress();

  const token = await ethers.getContractAt("TestToken", addrs.token, operator);
  const vault = await ethers.getContractAt("PaymentVault", addrs.vault);
  const bond: bigint = await vault.REGISTRATION_BOND();

  const have: bigint = await token.balanceOf(operatorAddr);
  if (have < bond) {
    await (await token.mint(operatorAddr, bond - have)).wait();
  }
  const allowed: bigint = await token.allowance(operatorAddr, addrs.vault);
  if (allowed < bond) {
    await (await token.approve(addrs.vault, ethers.MaxUint256)).wait();
  }
  console.log(`operator ${operatorAddr} funded with bond ${bond}`);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
