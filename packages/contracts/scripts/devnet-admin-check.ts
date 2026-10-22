import { artifacts, ethers } from "hardhat";
import { readFileSync } from "fs";
import { join } from "path";
import assert from "node:assert/strict";

/**
 * Owner controls on a live devnet deployment.
 *
 * The unit suite proves the treasury rotation and the shape-proof ratchet against the
 * contract in isolation. This proves the same behaviour through the real deployment:
 * the artifact that actually lands on chain, the address book the SDK and the bot read,
 * and a chain that mines blocks. "The interface works in a fixture" and "the deployed
 * thing works" have disagreed in this repository before.
 *
 * It runs after the deploy and before the SDK check, moves the treasury to a fresh
 * address and leaves the proof requirement on — which is what a hardened deployment
 * looks like anyway.
 */
async function main() {
  const addrs = JSON.parse(readFileSync(join(__dirname, "../../../infra/devnet/addresses.json"), "utf8"));
  const signers = await ethers.getSigners();
  const owner = signers[0];
  const outsider = signers[6];
  const task = await ethers.getContractAt("CipherTask", addrs.cipherTask);

  const parse = (logs: readonly { topics: readonly string[]; data: string }[]) =>
    logs
      .map((log) => {
        try {
          return task.interface.parseLog({ topics: [...log.topics], data: log.data });
        } catch {
          return null; // a log from another contract in the same transaction
        }
      })
      .filter((log) => log !== null);

  const before = await task.treasury();
  assert.notEqual(before, ethers.ZeroAddress, "devnet deployed without a treasury");

  // --- the proposal queues the change, it does not move the money -----------
  const proposeTx = await (await task.connect(owner).proposeTreasury(outsider.address)).wait();
  assert.ok(proposeTx, "proposeTreasury produced no receipt");
  const proposed = parse(proposeTx.logs).find((log) => log.name === "TreasuryProposed");
  assert.ok(proposed, "proposeTreasury emitted no TreasuryProposed");
  const eta = proposed.args.eta as bigint;
  assert.ok(eta > BigInt(0), "the announcement carried no executable time");
  assert.equal(await task.treasury(), before, "the treasury moved on the proposal");
  console.log("treasury proposed:", outsider.address, "- executable at", eta.toString());

  // --- an early execute is refused -------------------------------------------
  // Compare selectors, not names: a standalone node does not always decode a
  // custom error into its name (CI reports only the raw return data), so
  // matching on the string "TreasuryNotReady" would pass locally and fail on
  // the runner. Both shapes carry the four-byte selector.
  const notReady = task.interface.getError("TreasuryNotReady");
  assert.ok(notReady, "TreasuryNotReady is not in the ABI");
  let revertText = "";
  try {
    await task.connect(outsider).executeTreasury.staticCall();
  } catch (e) {
    const raw = (e as { data?: unknown })?.data;
    revertText = `${typeof raw === "string" ? raw : ""} ${String(e)}`;
  }
  const refused =
    revertText.toLowerCase().includes(notReady.selector.toLowerCase()) || revertText.includes("TreasuryNotReady");
  assert.ok(refused, `early execute was not refused with TreasuryNotReady: ${revertText.slice(0, 160)}`);
  assert.equal(await task.treasury(), before, "an early execute still moved the treasury");
  console.log("early execute refused, as it should be");

  // --- anyone may execute once the window has passed -------------------------
  await ethers.provider.send("evm_increaseTime", [Number(await task.TREASURY_DELAY()) + 1]);
  await ethers.provider.send("evm_mine", []);
  const executeTx = await (await task.connect(outsider).executeTreasury()).wait();
  assert.ok(executeTx, "executeTreasury produced no receipt");
  const executed = parse(executeTx.logs).find((log) => log.name === "TreasuryChanged");
  assert.ok(executed, "executeTreasury emitted no TreasuryChanged");
  assert.equal(executed.args.from, before);
  assert.equal(executed.args.to, outsider.address);
  assert.equal(await task.treasury(), outsider.address, "the treasury did not move");
  console.log("treasury moved to", outsider.address, "- executed by a non-owner");

  // --- the shape-proof requirement is a ratchet, not a switch ----------------
  await (await task.connect(owner).requireShapeProofs()).wait();
  assert.equal(await task.shapeProofsRequired(), true, "the requirement did not hold");
  const names = (await artifacts.readArtifact("CipherTask")).abi
    .filter((f) => f.type === "function")
    .map((f) => f.name);
  assert.ok(!names.includes("setShapeProofsRequired"), "a switch that weakens the requirement came back");
  console.log("shape-proof requirement: on, and there is no switch that turns it off");

  console.log("DEVNET ADMIN OK");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
