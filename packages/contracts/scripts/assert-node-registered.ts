/**
 * Assert the live Rust node registered itself for the devnet task and posted its bond.
 *
 * Run after the node has had time to backfill, see the seal and register (the CI job sleeps
 * first): exits 0 with a summary line, non-zero with the observed state otherwise.
 *
 *   npx hardhat run scripts/assert-node-registered.ts --network localhost
 */
import { ethers } from "hardhat";
import { readFileSync } from "fs";
import { join } from "path";

const OUT = join(__dirname, "../../../infra/devnet/addresses.json");
const TASK_ID = BigInt(process.env.CI_NODE_TASK_ID ?? "1");
const OPERATOR = (
  process.env.CM_OPERATOR_KEY ??
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
).toLowerCase();
const EXPECTED_BOND = 10_000_000n;

async function main() {
  const addrs = JSON.parse(readFileSync(OUT, "utf8"));
  const task = await ethers.getContractAt("CipherTask", addrs.cipherTask);
  const vault = await ethers.getContractAt("PaymentVault", addrs.vault);

  // The operator key is a secret; the address is derived, never pasted.
  const operatorAddr = ethers.computeAddress(OPERATOR).toLowerCase();
  const registered: boolean = await task.nodeRegistered(TASK_ID, operatorAddr);
  const bond: bigint = await vault.nodeBond(TASK_ID, operatorAddr);
  console.log(`task ${TASK_ID} operator ${operatorAddr}: registered=${registered} bond=${bond}`);
  if (!registered) throw new Error("node did not register");
  if (bond !== EXPECTED_BOND) throw new Error(`expected bond ${EXPECTED_BOND}, got ${bond}`);
  console.log("DEVNET NODE E2E OK");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
