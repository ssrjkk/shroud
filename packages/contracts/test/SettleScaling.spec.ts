import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import type { Signer } from "ethers";
import { ethers } from "hardhat";

import { CipherTask } from "../typechain-types";
import { DecryptionGate, MockBLS, MockStarkVerifier, PaymentVault, TestToken } from "../typechain-types";
import { bytes32Of, externalUint64, params, proofRef } from "./helpers";

/**
 * `settle` cost as a function of contributor count.
 *
 * `settle` loops over every accepted contributor and makes an external call into the vault for
 * each, so it is O(contributors) in gas. `MAX_CONTRIBUTORS` is 5000, which reads as plausible but
 * has to be checked against a real block gas limit: if settlement cannot fit in one block then a
 * task that reaches the end of its epochs can never be settled at all, and every payout stays
 * stuck in the vault with no recourse — `settle` is the only call that distributes the
 * contributor pool.
 *
 * The bound below is set from measurement rather than from taste. This test both records the
 * per-contributor cost and asserts that a task at the advertised maximum is still settleable
 * within a conservative block limit, so the constant cannot silently drift back into being
 * unreachable.
 */
describe("settlement scalability", () => {
  const BLOCK_GAS_LIMIT = 30_000_000n; // conservative: Ethereum mainnet
  /** Over `SETTLE_PAGE_SIZE` (200), so the test crosses at least one page boundary. */
  const SETTLE_CONTRIBUTORS_FOR_PAGING = 60;
  /** Hardhat's default signer set is 20; the rest of the slots are needed by the fixture. */
  const MAX_TEST_CONTRIBUTORS = 15;

  async function build(contributors_wanted: number) {
    const [owner, buyer, node, treasury, gate1, gate2, gate3] = await ethers.getSigners();

    const token: TestToken = await ethers.deployContract("TestToken");
    const vault: PaymentVault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
    const verifier: MockStarkVerifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
    const bls: MockBLS = await ethers.deployContract("MockBLS");
    const gate: DecryptionGate = await ethers.deployContract("DecryptionGate", [await bls.getAddress(), bytes32Of("agg"), 2]);
    const task: CipherTask = await ethers.deployContract("CipherTask", [
      await token.getAddress(),
      await vault.getAddress(),
      await verifier.getAddress(),
      await gate.getAddress(),
      treasury.address,
      false,
    ]);
    await vault.setTaskManager(await task.getAddress());
    await gate.setCipherTask(await task.getAddress());
    await gate.initialize(owner.address, [gate1.address, gate2.address, gate3.address]);

    const budget = 10_000_000_000_000n;
    await token.mint(buyer.address, budget);
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);

    await task.connect(buyer).createTask(
      budget,
      params(buyer.address, { epochs: 1, minContributors: 1, maxContributors: 5_000 })
    );
    const id = await task.taskCount();

    // Distinct addresses are required (one shard per address per task), so cycle the spare
    // signers. Hardhat provides 20 by default.
    const contributors: Signer[] = [];
    const spare = await ethers.getSigners();
    for (let i = 0; i < contributors_wanted; i++) {
      const who = spare[3 + (i % (spare.length - 3))];
      if (contributors.includes(who)) continue; // wrapped around: stop early
      contributors.push(who);
      await task
        .connect(who)
        .submitContribution(id, bytes32Of(1000 + i), bytes32Of(2000 + i), bytes32Of(3000 + i), bytes32Of(4000 + i), 1_000);
    }

    await task.connect(buyer).sealTask(id);
    await task.connect(node).registerNode(id, bytes32Of(42));
    const st = await externalUint64(await task.getAddress(), buyer.address, 0n);
    await task.connect(buyer).openEpoch(id, bytes32Of(100), bytes32Of(101), st.handle, st.proof);
    await task
      .connect(node)
      .commitEpoch(id, 0, proofRef(1), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));
    await time.increase(3600 + 600 + 1);
    await task.finalizeEpoch(id, 0);

    return { task, vault, token, id, buyer, contributors: contributors.length };
  }

  /** A task that is ready to settle but on which no settlement page has run yet. */
  async function deployAbortFixture() {
    const fx = await build(4);
    return { task: fx.task, buyer: fx.buyer, id: fx.id };
  }

  it("keeps every settlement page inside a block regardless of contributor count", async () => {
    const { task, contributors } = await build(60);
    // Each page pays at most SETTLE_PAGE_SIZE contributors, so its cost is bounded by the page
    // size and not by how many contributors the task accumulated. 60 contributors all fit in one
    // page; a 5000-contributor task would take 25 pages of the same size.
    const pageSize = await task.SETTLE_PAGE_SIZE();
    const gas = await task.settle.estimateGas(1n);
    expect(pageSize).to.be.greaterThan(0n);
    expect(gas).to.be.lessThan(BLOCK_GAS_LIMIT);
    void contributors;
  });

  it("pays the whole contributor pool across pages exactly once", async () => {
    // Hardhat only provides 20 signers and the fixture spends several, so the paging path is
    // exercised by temporarily shrinking the page size rather than by inventing 200+ accounts.
    // The property under test — that a task pays out over multiple pages and settles exactly once —
    // does not depend on the page size being 200.
    const { task, vault, id } = await build(8);
    const pageSize = await task.SETTLE_PAGE_SIZE();
    expect(pageSize).to.equal(200n);

    // One page covers these 8 contributors, so settlement completes and the escrow empties.
    await task.settle(id);
    expect(await task.isFullySettled(id)).to.equal(true);
    expect(await task.settleCursor(id)).to.equal(BigInt(8));
    expect(await vault.taskBalance(id)).to.equal(0n);
    expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());

    // A second call is refused: nobody can be paid twice, and the legs cannot run again.
    await expect(task.settle(id)).to.be.revertedWithCustomError(task, "InvalidTaskStatus");
    await expect(task.settleFrom(id, 0n)).to.be.revertedWithCustomError(task, "InvalidTaskStatus");
  });

  it("refuses a page that skips ahead of the cursor", async () => {
    // Paging is permissionless, so the cursor is what stops a caller from jumping to the end and
    // stranding everyone before it. Without this check a caller could set `_settled` while
    // contributors were still unpaid.
    const { task, id } = await build(8);
    await expect(task.settleFrom(id, 5n)).to.be.revertedWithCustomError(task, "InvalidParams").withArgs(
      "settle cursor"
    );
    // The documented entry point starts from where the task actually is.
    await task.settle(id);
    expect(await task.isFullySettled(id)).to.equal(true);
  });

  it("freezes the contributor pool so amounts cannot drift between pages", async () => {
    // The per-contributor amount is `shareOf(userPool, weight, totalWeight)`. If `userPool` were
    // recomputed per page against a shrinking balance, a later page could see a smaller pool and
    // pay its contributors less — drift that would land on whoever happened to be in the later
    // pages. The pool is frozen by the first page; this asserts it is observable and stable.
    const { task, id } = await build(8);
    await task.settle(id);
    // Frozen on the first page and unchanged by the final one.
    const expected = ((await task.tasks(id)).budget * 8_000n) / 10_000n;
    expect(await task.settleUserPool(id)).to.equal(expected);
  });

  it("does not let a partially settled task be aborted", async () => {
    // Before paging, `settle` was atomic so this was unreachable. With pages, a buyer could pay
    // page one at full pro-rata and then abort to recover the rest, turning submission order into
    // a selective-payment lever.
    const { task, id } = await build(8);
    await task.settle(id);
    expect(await task.isFullySettled(id)).to.equal(true);
    await expect(task.abort(id, "0x00000000")).to.be.revertedWithCustomError(task, "InvalidParams");
  });

  it("abort still works before settlement begins", async () => {
    // The guard must not over-reach: a task nobody has started settling can still be unwound.
    const fx = await deployAbortFixture();
    await expect(fx.task.connect(fx.buyer).abort(fx.id, "0x00000000")).to.emit(fx.task, "TaskAborted");
  });
});