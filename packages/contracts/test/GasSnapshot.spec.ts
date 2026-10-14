import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import type { ContractTransactionResponse } from "ethers";
import { ethers } from "hardhat";

import { deployLinked } from "../scripts/libraries";
import { bytes32Of, externalUint64, params, proofFor, proofRef } from "./helpers";

/**
 * Gas snapshot for one full single-epoch lifecycle.
 *
 * Not a regression gate with tight bounds (optimizer settings and compiler versions
 * move numbers): it prints the table so operator economics stay visible, and asserts
 * loose ceilings (order-of-magnitude tripwires, not budgets). The case the ceilings
 * protect is the documented one — settlement paging (`SETTLE_PAGE_SIZE = 200`): if a
 * step ever approaches the 30M block limit the way the contributor-cap analysis in
 * the README describes, this fails loudly instead of surprising an operator.
 */
describe("GasSnapshot", () => {
  it("reports one lifecycle", async function () {
    this.timeout(300_000);
    const [owner, buyer, alice, bob, node, node2, treasury] = await ethers.getSigners();
    void owner;
    const token = await ethers.deployContract("TestToken");
    const vault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
    const verifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
    const bls = await ethers.deployContract("MockBLS");
    const gate = await ethers.deployContract("DecryptionGate", [
      await bls.getAddress(),
      bytes32Of("bls-agg"),
      1,
    ]);
    const task = await deployLinked("CipherTask", [
      await token.getAddress(),
      await vault.getAddress(),
      await verifier.getAddress(),
      await gate.getAddress(),
      treasury.address,
      true,
    ]);
    await vault.setTaskManager(await task.getAddress());

    const gas: Record<string, bigint> = {};
    const track = async (name: string, tx: Promise<ContractTransactionResponse>) => {
      const receipt = await (await tx).wait();
      if (!receipt) throw new Error(`no receipt for ${name}`);
      gas[name] = receipt.gasUsed;
    };

    const escrow = 1_000_000_000n;
    await token.mint(buyer.address, escrow);
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);
    const bond = await vault.REGISTRATION_BOND();
    for (const n of [node, node2]) {
      await token.mint(n.address, bond);
      await token.connect(n).approve(await vault.getAddress(), ethers.MaxUint256);
    }

    const p = params(buyer.address, {
      epochs: 1,
      minContributors: 2,
      maxContributors: 100,
      minRowsPerShard: 100,
      features: 33,
      epochDuration: 600,
      disputeWindow: 120,
    });
    await track("createTask", task.connect(buyer).createTask(escrow, p));
    const id = await task.taskCount();
    await track(
      "submitContribution",
      task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), proofFor(1), bytes32Of(7), 1_000)
    );
    await track(
      "submitContribution#2",
      task.connect(bob).submitContribution(id, bytes32Of(2), bytes32Of(12), proofFor(2), bytes32Of(8), 1_000)
    );
    await track("sealTask", task.connect(buyer).sealTask(id));
    await track("registerNode", task.connect(node).registerNode(id, bytes32Of(1001)));
    await track("registerNode#2", task.connect(node2).registerNode(id, bytes32Of(1002)));
    const st = await externalUint64(await task.getAddress(), buyer.address, 0n);
    await track(
      "openEpoch",
      task.connect(buyer).openEpoch(id, bytes32Of(100), bytes32Of(101), st.handle, st.proof)
    );
    await track(
      "commitEpoch",
      task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(300), bytes32Of(401), bytes32Of(501), bytes32Of(999))
    );
    await track(
      "commitEpoch#2",
      task.connect(node2).commitEpoch(id, 0, proofRef(2), bytes32Of(301), bytes32Of(402), bytes32Of(502), bytes32Of(998))
    );
    await time.increase(600 + 120 + 1);
    await track("finalizeEpoch", task.finalizeEpoch(id, 0));
    await track("settle", task.settle(id));
    await track("releaseBond", vault.releaseBond(id, node.address));

    console.log(
      "gas snapshot (2 contributors, 1 epoch):\n" +
        Object.entries(gas)
          .map(([k, v]) => `  ${k.padEnd(20)} ${v.toString().padStart(10)}`)
          .join("\n")
    );

    // Order-of-magnitude tripwires, not budgets: every step must stay two orders of
    // magnitude below the 30M block limit on this tiny task. If settlement paging ever
    // regresses toward the contributor-cap blowup, this is where it shows first.
    for (const [k, v] of Object.entries(gas)) {
      expect(v, `${k} gas`).to.be.lessThan(3_000_000n);
    }
  });
});
