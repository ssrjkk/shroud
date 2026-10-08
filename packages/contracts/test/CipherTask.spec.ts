import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import type { Signer } from "ethers";
import { ethers } from "hardhat";

import { CipherTask } from "../typechain-types";
import { DecryptionGate, MockBLS, MockStarkVerifier, NetworkParams, PaymentVault, TestToken } from "../typechain-types";
import { bytes32Of, externalUint64, params, proofFor, proofRef, reason4, redeemDigest, sliceDomain } from "./helpers";

/**
 * End-to-end lifecycle test of the Shroud orchestrator.
 *
 * Covers the money path (escrow -> reward channel -> settlement), the proof path (STARK
 * binding, replay, dispute quorum) and the reveal path (BLS gate, output allowlist).
 */
describe("CipherTask", () => {
  type Fx = Awaited<ReturnType<typeof deployFixture>>;

  async function deployFixture() {
    const [owner, buyer, alice, bob, carol, node, node2, node3, node4, committee, outsider, treasury] = await ethers.getSigners();

    // `ethers.deployContract` returns the typechain-generated type directly, unlike
    // `getContractFactory(...).deploy()` which needs a cast through `unknown`.
    const token: TestToken = await ethers.deployContract("TestToken");
    const vault: PaymentVault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
    const verifier: MockStarkVerifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
    const bls: MockBLS = await ethers.deployContract("MockBLS");
    const gate: DecryptionGate = await ethers.deployContract("DecryptionGate", [
      await bls.getAddress(),
      bytes32Of("bls-agg"),
      1
    ]);

    const task: CipherTask = await ethers.deployContract("CipherTask", [
      await token.getAddress(),
      await vault.getAddress(),
      await verifier.getAddress(),
      await gate.getAddress(),
      treasury.address,
      true
    ]);

    await vault.setTaskManager(await task.getAddress());
    await gate.setCipherTask(await task.getAddress());
    await gate.initialize(committee.address, [committee.address]);

    const net: NetworkParams = await ethers.deployContract("NetworkParams", [owner.address]);
    await net.initialize({
      chainId: 0,
      keyVersion: 1,
      fhePublicKeyHash: bytes32Of("s_pub-v1"),
      committeeAggregateKey: bytes32Of("bls-agg"),
      committeeThreshold: 1,
      committeeSize: 7,
      maxProofBytes: 48_576,
      maxCiphertextBytes: 1 << 20,
      maxFeatures: 512,
      activatedAt: 0,
      active: true
    });

    const escrow = 1_000_000_000n; // 1000 CMUSD, 6 dp
    await token.mint(buyer.address, escrow);
    // A max allowance keeps the fixture usable for tests that create more than one task: ERC-20
    // `approve` replaces rather than adds, so a bounded allowance would block the second escrow.
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);

    return { token, vault, verifier, bls, gate, task, net, escrow, owner, buyer, alice, bob, carol, node, node2, node3, node4, committee, outsider, treasury };
  }

  /** Create a sealed task with two contributions and `node` registered. */
  async function sealed(fx: Fx, opts: { epochs?: number; aRows?: number; bRows?: number; nodes?: typeof fx.node[]; budget?: bigint } = {}) {
    const { task, buyer, alice, bob } = fx;
    const nodes = opts.nodes ?? [fx.node];
    const p = params(buyer.address, { minContributors: 2, epochs: opts.epochs ?? 3 });
    await task.connect(buyer).createTask(opts.budget ?? fx.escrow, p);
    const id = await task.taskCount();
    await task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), proofFor(1), bytes32Of(7), opts.aRows ?? 1_000);
    await task.connect(bob).submitContribution(id, bytes32Of(2), bytes32Of(12), proofFor(2), bytes32Of(8), opts.bRows ?? 1_000);
    await task.connect(buyer).sealTask(id);
    for (const n of nodes) await task.connect(n).registerNode(id, bytes32Of(42));
    return id;
  }

  /**
   * Buyer publishes an epoch: encrypted-weights pins plus a real external encrypted state.
   *
   * The state handle must come from the input verifier (see `externalUint64`), otherwise the
   * coprocessor rejects it inside `FHE.fromExternal` before any CipherTask logic runs.
   */
  async function openEpochAs(fx: Fx, id: bigint, signer: Signer, cid: string, digest: string, state = 0n) {
    const st = await externalUint64(await fx.task.getAddress(), await signer.getAddress(), state);
    return fx.task.connect(signer).openEpoch(id, cid, digest, st.handle, st.proof);
  }

  /** Run one full epoch: open, commit by `node`, wait out the dispute window, finalize. */
  async function runEpoch(fx: Fx, id: bigint, epoch: number, node: Signer, traceDigest = bytes32Of(999)) {
    const { task, buyer, verifier } = fx;
    await openEpochAs(fx, id, buyer, bytes32Of(100 + Number(epoch)), bytes32Of(200 + Number(epoch)), BigInt(epoch));
    const transcript = await task.proofTranscript(id, epoch, traceDigest);
    if (await verifier.consumed(transcript)) {
      // Reusing a transcript across tests is a bug in the fixture, not in the contract.
      throw new Error("fixture reused a proof transcript");
    }
    await task.connect(node).commitEpoch(id, epoch, proofRef(epoch), bytes32Of(300 + Number(epoch)), bytes32Of(400 + Number(epoch)), bytes32Of(500 + Number(epoch)), traceDigest);
    await time.increase(3600 + 600);
    await task.finalizeEpoch(id, epoch);
  }

  /* ---------------------------------------------------------------- */

  describe("task creation and escrow", () => {
    it("escrows exactly the buyer's named budget and pins the params", async () => {
      const { task, token, vault, buyer, escrow } = await deployFixture();

      await expect(task.connect(buyer).createTask(escrow, params(buyer.address))).to.emit(task, "TaskCreated");

      const id = await task.taskCount();
      const t = await task.tasks(id);
      expect(t.budget).to.equal(escrow);
      expect(t.params.epochs).to.equal(3n);
      expect(t.status).to.equal(1n); // Opening (TaskStatus.None == 0)
      expect(await vault.taskBalance(id)).to.equal(escrow);
      // Only the named budget is pulled; the fixture minted exactly that, so the wallet is empty.
      expect(await token.balanceOf(buyer.address)).to.equal(0n);
      expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
    });

    it("only escrows the named budget, leaving the rest of the allowance untouched", async () => {
      const { task, token, vault, buyer, escrow } = await deployFixture();
      const budget = 250_000_000n;
      await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);

      await task.connect(buyer).createTask(budget, params(buyer.address));
      const id = await task.taskCount();
      expect((await task.tasks(id)).budget).to.equal(budget);
      expect(await vault.taskBalance(id)).to.equal(budget);
      // The buyer named a budget smaller than their balance: only that amount is pulled.
      expect(await token.balanceOf(buyer.address)).to.equal(escrow - budget);
    });

    it("rejects a zero budget", async () => {
      const { task, buyer } = await deployFixture();
      await expect(task.connect(buyer).createTask(0n, params(buyer.address))).to.be.revertedWithCustomError(task, "BudgetTooSmall");
    });

    it("rejects shares that do not sum to 100%", async () => {
      const { task, buyer, escrow } = await deployFixture();
      const p = params(buyer.address, { userShareBps: 5_000, nodeShareBps: 1_000, committeeShareBps: 1_000 });
      await expect(task.connect(buyer).createTask(escrow, p)).to.be.revertedWithCustomError(task, "InvalidShares");
    });

    it("rejects a buyer field that is not msg.sender", async () => {
      const { task, alice, buyer, escrow } = await deployFixture();
      await expect(task.connect(alice).createTask(escrow, params(buyer.address))).to.be.revertedWithCustomError(task, "BuyerMustBeCaller");
    });

    it("enforces parameter bounds", async () => {
      const { task, buyer, escrow } = await deployFixture();
      await expect(task.connect(buyer).createTask(escrow, params(buyer.address, { contributionWindow: 60 }))).to.be.revertedWithCustomError(task, "InvalidParams");
      await expect(task.connect(buyer).createTask(escrow, params(buyer.address, { epochs: 0 }))).to.be.revertedWithCustomError(task, "InvalidParams");
      await expect(task.connect(buyer).createTask(escrow, params(buyer.address, { features: 0 }))).to.be.revertedWithCustomError(task, "InvalidParams");
    });
  });

  describe("encrypted contributions", () => {
    it("accepts shards, assigns ordered leaves, and grows the ctRoot", async () => {
      const fx = await deployFixture();
      const { task, buyer, alice, bob } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address));
      const id = await task.taskCount();

      await task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), proofFor(1), bytes32Of(7), 1_000);
      await task.connect(bob).submitContribution(id, bytes32Of(2), bytes32Of(12), proofFor(2), bytes32Of(8), 500);

      const t = await task.tasks(id);
      expect(t.shards).to.equal(2n);
      expect(t.contributors).to.equal(2n);
      expect(t.status).to.equal(2n); // Collecting
      expect(await task.contributionOf(id, 0)).to.equal(alice.address);
      expect(await task.contributionOf(id, 1)).to.equal(bob.address);
      expect(t.ctRoot).to.not.equal(bytes32Of(0));

      const a = await task.contributions(id, alice.address);
      const b = await task.contributions(id, bob.address);
      expect(a.weightQ16).to.be.greaterThan(b.weightQ16);
      // sqrt damping: 2x the rows must not be 2x the weight.
      expect(a.weightQ16).to.be.lessThan(b.weightQ16 * 2n);
    });

    it("enforces one shard per address, minimum rows and proof presence", async () => {
      const fx = await deployFixture();
      const { task, buyer, alice } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address));
      const id = await task.taskCount();

      await expect(
        task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), proofFor(1), bytes32Of(7), 10)
      ).to.be.revertedWithCustomError(task, "ShardTooSmall");

      // `shapeProof` is now `bytes`, so "absent" is an empty blob rather than a zero hash.
      await expect(
        task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), "0x", bytes32Of(7), 1_000)
      ).to.be.revertedWithCustomError(task, "ShapeProofInvalid");

      await task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), proofFor(1), bytes32Of(7), 1_000);
      await expect(
        task.connect(alice).submitContribution(id, bytes32Of(2), bytes32Of(12), proofFor(2), bytes32Of(8), 1_000)
      ).to.be.revertedWithCustomError(task, "AlreadyContributed");
    });

    it("seals only at or after the min-contributor count", async () => {
      const fx = await deployFixture();
      const { task, buyer, alice, bob } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 2 }));
      const id = await task.taskCount();

      await task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), proofFor(1), bytes32Of(7), 1_000);
      await expect(task.connect(buyer).sealTask(id)).to.be.revertedWithCustomError(task, "CapReached");

      await task.connect(bob).submitContribution(id, bytes32Of(2), bytes32Of(12), proofFor(2), bytes32Of(8), 1_000);
      await expect(task.connect(buyer).sealTask(id)).to.emit(task, "TaskSealed");
      expect((await task.tasks(id)).isSealed).to.equal(true);
    });

    it("lets anyone seal once the window expires, but not before", async () => {
      const fx = await deployFixture();
      const { task, buyer, alice, bob, carol } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 2, contributionWindow: 3600 }));
      const id = await task.taskCount();
      await task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), proofFor(1), bytes32Of(7), 1_000);
      await task.connect(bob).submitContribution(id, bytes32Of(2), bytes32Of(12), proofFor(2), bytes32Of(8), 1_000);

      await expect(task.connect(carol).sealTask(id)).to.be.revertedWithCustomError(task, "NotUpdateManagerOrOwner");
      await time.increase(3601);
      await expect(task.connect(carol).sealTask(id)).to.emit(task, "TaskSealed");
    });
  });

  describe("epoch orchestration", () => {
    it("locks the per-epoch amount and freezes the dataset root", async () => {
      const fx = await deployFixture();
      const { task, buyer } = fx;
      const id = await sealed(fx, { epochs: 3 });
      const rootAtSeal = (await task.tasks(id)).ctRoot;

      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      const t = await task.tasks(id);
      // All amounts are in CMUSD base units (6 dp). budget 1e9 * nodeShareBps 1500 / 10000
      // / 3 epochs = 5e7.
      expect(t.locked).to.equal(50_000_000n);
      expect(t.status).to.equal(4n); // EpochOpen
      // The dataset root cannot move once sealed.
      await expect(
        task.connect(buyer).sealTask(id)
      ).to.be.reverted;
      expect((await task.tasks(id)).ctRoot).to.equal(rootAtSeal);
    });

    it("refuses to open a second epoch while one is locked", async () => {
      const fx = await deployFixture();
      const { task, buyer } = fx;
      const id = await sealed(fx, { epochs: 3 });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await expect(
        openEpochAs(fx, id, buyer, bytes32Of(102), bytes32Of(103))
      ).to.be.revertedWithCustomError(task, "InvalidParams");
    });

    it("rejects a proof that is not a STARK, and one whose transcript was already consumed", async () => {
      const fx = await deployFixture();
      const { task, buyer, node, verifier } = fx;
      const id = await sealed(fx);
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));

      await expect(
        task.connect(node).commitEpoch(id, 0, bytes32Of("not-a-stark"), bytes32Of(1), bytes32Of(2), bytes32Of(3), bytes32Of(999))
      ).to.be.revertedWithCustomError(task, "ProofRejected");

      // Consuming the transcript simulates the verifier having accepted it before, i.e. a replay.
      await verifier.consume(await task.proofTranscript(id, 0, bytes32Of(999)));
      await expect(
        task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(1), bytes32Of(2), bytes32Of(3), bytes32Of(999))
      ).to.be.revertedWithCustomError(task, "ProofRejected");
    });

    it("binds the proof to the task id", async () => {
      const fx = await deployFixture();
      const { task, token, buyer, escrow } = fx;
      // `createTask` escrows the buyer's whole approved balance, so a second task in the same
      // fixture needs a second tranche minted after the first is spent. (This is the behaviour
      // the explicit-budget redesign removes.)
      const idA = await sealed(fx);
      await token.mint(buyer.address, escrow);
      const idB = await sealed(fx);
      expect(await task.proofTranscript(idA, 0, bytes32Of(5))).to.not.equal(await task.proofTranscript(idB, 0, bytes32Of(5)));
    });

    it("rejects commits from unregistered nodes, missing proof references, and late commits", async () => {
      const fx = await deployFixture();
      const { task, buyer, node, node2 } = fx;
      const id = await sealed(fx, { nodes: [node] });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));

      await expect(
        task.connect(node2).commitEpoch(id, 0, proofRef(1), bytes32Of(1), bytes32Of(2), bytes32Of(3), bytes32Of(9))
      ).to.be.revertedWithCustomError(task, "NodeNotRegistered");

      // A zero reference is "no proof", which is distinct from an oversized proof: the committed
      // field is a fixed 32-byte reference, so `ProofTooLarge` cannot be reached from `commitEpoch`
      // and is enforced inside `ProofVerifier` against the real proof bytes instead.
      await expect(
        task.connect(node).commitEpoch(id, 0, ethers.ZeroHash, bytes32Of(1), bytes32Of(2), bytes32Of(3), bytes32Of(9))
      ).to.be.revertedWithCustomError(task, "ProofReferenceMissing");

      await time.increase(3601);
      await expect(
        task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(1), bytes32Of(2), bytes32Of(3), bytes32Of(9))
      ).to.be.revertedWithCustomError(task, "InvalidParams");
    });

    it("rejects a duplicate commit from the same node", async () => {
      const fx = await deployFixture();
      const { task, buyer, node } = fx;
      const id = await sealed(fx);
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(1), bytes32Of(2), bytes32Of(3), bytes32Of(9));
      await expect(
        task.connect(node).commitEpoch(id, 0, proofRef(2), bytes32Of(1), bytes32Of(2), bytes32Of(3), bytes32Of(10))
      ).to.be.revertedWithCustomError(task, "DuplicateCommit");
    });
  });

  describe("dispute quorum", () => {
    async function committing() {
      const fx = await deployFixture();
      const { task, buyer, node, node2, node3, node4 } = fx;
      const id = await sealed(fx, { epochs: 2, nodes: [node, node2, node3, node4] });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));
      return { fx, id };
    }

    it("a lone report does not shorten the dispute window", async () => {
      const { fx, id } = await committing();
      await fx.task.connect(fx.node2).reportDispute(id, 0, bytes32Of(1234));
      await expect(fx.task.finalizeEpoch(id, 0)).to.be.revertedWithCustomError(fx.task, "DisputeBelowQuorum");
    });

    it("quorum rejects the epoch and pays reporters from the lock", async () => {
      const { fx, id } = await committing();
      const { task, vault, node2, node3, node4 } = fx;
      await task.connect(node2).reportDispute(id, 0, bytes32Of(1234));
      await task.connect(node3).reportDispute(id, 0, bytes32Of(1235));
      await task.connect(node4).reportDispute(id, 0, bytes32Of(1236));

      const [need, have] = await task.disputeQuorum(id);
      expect(need).to.equal(3n);
      expect(have).to.equal(3n);

      await expect(task.finalizeEpoch(id, 0)).to.emit(task, "TaskAborted");
      expect((await task.tasks(id)).nextEpoch).to.equal(1n);
      // The disputed epoch's lock went to the reporters, not to a node winner.
      expect(await task.epochChannel(id, 0)).to.equal(0n);
      // Escrow is reduced by the reporter bounty (reexecutionBps=200 of lock 7.5e7 = 1.5e6)
      // but contributor + committee pools remain for settle.
      const balanceAfter = await vault.taskBalance(id);
      expect(balanceAfter).to.be.greaterThan(0n);
    });

    it("pays reporters a bounty from the disputed lock, and nobody is paid as winner", async () => {
      const fx = await deployFixture();
      const { task, vault, token, buyer, node, node2, node3, node4 } = fx;
      const id = await sealed(fx, { epochs: 2, nodes: [node, node2, node3, node4] });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));

      await task.connect(node2).reportDispute(id, 0, bytes32Of(1234));
      await task.connect(node3).reportDispute(id, 0, bytes32Of(1235));
      await task.connect(node4).reportDispute(id, 0, bytes32Of(1236));
      await task.finalizeEpoch(id, 0);

      // lock = 1e9 * 1500 / 10000 / 2 = 7.5e7; bounty = lock * 200 / 10000 = 1.5e6;
      // 1.5e6 / 3 = 5e5 each, remainder 0.
      const expectedEach = 500_000n;
      const subBalanceBefore = await vault.taskBalance(id);

      // Each reporter can redeem its slice over ERC-1271, exactly like a winner. The channels are
      // opened in report order, so channel 1/2/3 belong to node2/node3/node4.
      for (const [i, reporter] of [node2, node3, node4].entries()) {
        const ch = await vault.channelInfo(BigInt(i + 1));
        expect(ch.node).to.equal(reporter.address);
        expect(ch.maxCumulative).to.equal(expectedEach);
        const sig = ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint256", "uint256", "uint128"],
          [BigInt(i + 1), 0, ch.maxCumulative]
        );
        const digest = await vault.redeemDigest(
          BigInt(i + 1), await task.getAddress(), reporter.address, ch.maxCumulative, ch.unlockAt, ethers.MaxUint256
        );
        expect(await task.isValidSignature(digest, sig)).to.equal("0x1626ba7e");
        await vault.connect(reporter).redeem(BigInt(i + 1), 0, ch.maxCumulative, ethers.MaxUint256, sig);
        expect(await token.balanceOf(reporter.address)).to.equal(expectedEach);
      }

      // The lying claimant is paid nothing.
      expect(await token.balanceOf(node.address)).to.equal(0n);
      // `epochChannel` still reads 0: a bounty is not a win.
      expect(await task.epochChannel(id, 0)).to.equal(0n);
      expect(subBalanceBefore).to.equal(1_000_000_000n - 1_500_000n);
      expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
    });

    it("refuses a report that agrees with the claim", async () => {
      const { fx, id } = await committing();
      await expect(
        fx.task.connect(fx.node2).reportDispute(id, 0, bytes32Of(999))
      ).to.be.revertedWithCustomError(fx.task, "InvalidParams");
    });

    it("does not let a losing committer redirect the dispute away from the winner", async () => {
      // The bug this guards: `_claimedDigest` was written by *every* committer, so the last
      // commit won it. A losing node could then submit a valid-but-different commit and move the
      // dispute target onto its own digest. Every honest re-executor reproduces the winner's
      // digest (computation is deterministic), so they would all file "disputes", reach quorum,
      // and get an honest epoch rejected — for free, since the liar paid nothing.
      const fx = await deployFixture();
      const { task, vault, token, buyer, node, node2, node3, node4 } = fx;
      const id = await sealed(fx, { epochs: 2, nodes: [node, node2, node3, node4] });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));

      // The tie-break is the lower address, not commit order, so derive it rather than assume.
      const [winner, loser] = BigInt(node.address) < BigInt(node2.address) ? [node, node2] : [node2, node];
      const winnerDigest = bytes32Of(999);

      await task.connect(winner).commitEpoch(id, 0, proofRef(1), bytes32Of(301), bytes32Of(401), bytes32Of(501), winnerDigest);
      await task.connect(loser).commitEpoch(id, 0, proofRef(2), bytes32Of(302), bytes32Of(402), bytes32Of(502), bytes32Of(888));

      expect(await task.epochWinner(id, 0)).to.equal(winner.address);

      // Honest re-executors all reproduce the winner's digest, so there is no disagreement and
      // every report is refused. With the bug, `_claimedDigest` would be 888 and these reports
      // would have been counted, poisoning the epoch.
      for (const reporter of [node3, node4]) {
        await expect(
          task.connect(reporter).reportDispute(id, 0, winnerDigest)
        ).to.be.revertedWithCustomError(task, "InvalidParams");
      }
      const [, have] = await task.disputeQuorum(id);
      expect(have).to.equal(0n);

      // So the epoch settles normally and the honest winner is paid.
      await time.increase(3600 + 600);
      await task.finalizeEpoch(id, 0);
      const channelId = await task.epochChannel(id, 0);
      expect((await vault.channelInfo(channelId)).node).to.equal(winner.address);
      expect(await token.balanceOf(loser.address)).to.equal(0n);
    });

    it("no dispute -> the winner gets an ERC-1271 redeemable channel", async () => {
      const { fx, id } = await committing();
      const { task, vault, node, buyer } = fx;
      await time.increase(3600 + 600);
      await expect(task.finalizeEpoch(id, 0)).to.emit(task, "EpochSettled");

      const channelId = await task.epochChannel(id, 0);
      const ch = await vault.channelInfo(channelId);
      expect(ch.node).to.equal(node.address);
      // The winner receives the epoch's whole node pool: budget 1e9 * nodeShareBps 1500 / 10000
      // / 2 epochs = 7.5e7. `nodeShareBps` is not applied a second time at settlement.
      expect(ch.maxCumulative).to.equal(75_000_000n);

      const sig = ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint128"], [channelId, 0, ch.maxCumulative]);
      const expected = await vault.redeemDigest(channelId, await task.getAddress(), node.address, ch.maxCumulative, ch.unlockAt, ethers.MaxUint256);
      expect(await task.isValidSignature(expected, sig)).to.equal("0x1626ba7e");
      // A tampered amount is not authorised.
      const bad = ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint128"], [channelId, 0, 1n]);
      expect(await task.isValidSignature(expected, bad)).to.equal("0xffffffff");
      void buyer;
    });
  });

  describe("settlement", () => {
    it("pays contributors pro-rata with sqrt damping, streams node pay, and refunds the rest", async () => {
      const fx = await deployFixture();
      const { task, vault, token, buyer, alice, bob, node, treasury } = fx;
      const id = await sealed(fx, { epochs: 1, aRows: 4_000, bRows: 1_000 });
      await runEpoch(fx, id, 0, node);
      await task.settle(id);

      const aliceDue = await task.pendingPayout(alice.address);
      const bobDue = await task.pendingPayout(bob.address);
      expect(aliceDue).to.be.greaterThan(bobDue);
      expect(aliceDue).to.be.lessThan(bobDue * 4n); // sqrt damping, not linear

      // Node pay streams through its channel rather than being credited at settlement.
      const channelId = await task.epochChannel(id, 0);
      const ch = await vault.channelInfo(channelId);
      const digest = await vault.redeemDigest(channelId, await task.getAddress(), node.address, ch.maxCumulative, ch.unlockAt, ethers.MaxUint256);
      expect(digest).to.equal(
        redeemDigest({
          domainSeparator: sliceDomain(await vault.getAddress(), (await ethers.provider.getNetwork()).chainId).domainSeparator,
          channelId,
          streamer: await task.getAddress(),
          node: node.address,
          maxCumulative: ch.maxCumulative,
          unlockAt: ch.unlockAt,
          deadline: ethers.MaxUint256
        })
      );
      const sig = ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint128"], [channelId, 0, ch.maxCumulative]);
      await vault.connect(node).redeem(channelId, 0, ch.maxCumulative, ethers.MaxUint256, sig);
      // Single-epoch task: the node pool is budget 1e9 * nodeShareBps 1500 / 10000 = 1.5e8.
      expect(await token.balanceOf(node.address)).to.equal(150_000_000n);

      await vault.connect(alice).claim();
      await vault.connect(bob).claim();
      expect(await token.balanceOf(alice.address)).to.be.greaterThan(0n);
      expect(await token.balanceOf(bob.address)).to.be.greaterThan(0n);

      // The three legs consume the whole escrow, so there is no dust left for the buyer:
      // users 8000 bps + nodes 1500 bps + committee 500 bps == 10000 bps of a 1e9 budget.
      // The node's 1.5e8 stays in its channel until the reward window matures rather than being
      // swept back to the buyer, and it was fully redeemed above.
      expect(await token.balanceOf(alice.address) + (await token.balanceOf(bob.address))).to.equal(800_000_000n);
      expect(await task.pendingPayout(buyer.address)).to.equal(0n);
      expect(await task.pendingPayout(treasury.address)).to.equal(50_000_000n);
      expect(await vault.taskBalance(id)).to.equal(0n);
      expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
    });

    it("cannot be settled twice", async () => {
      const fx = await deployFixture();
      const { task, node } = fx;
      const id = await sealed(fx, { epochs: 1 });
      await runEpoch(fx, id, 0, node);
      await task.settle(id);
      await expect(task.settle(id)).to.be.revertedWithCustomError(task, "InvalidTaskStatus");
    });

    it("refuses to settle while an epoch is still locked", async () => {
      const fx = await deployFixture();
      const { task, buyer, node } = fx;
      const id = await sealed(fx, { epochs: 2, nodes: [node] });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await expect(task.settle(id)).to.be.revertedWithCustomError(task, "InvalidTaskStatus");
    });

    it("refuses to settle after only some of the epochs have run", async () => {
      const fx = await deployFixture();
      const { task, node } = fx;
      const id = await sealed(fx, { epochs: 3, nodes: [node] });
      // Epoch 0 finalizes cleanly: status is `EpochSettled` and nothing is locked, so the status
      // and lock guards both pass. Settlement must still refuse, or the buyer could take the whole
      // escrow after one of three paid-for epochs.
      await runEpoch(fx, id, 0, node);
      expect((await task.tasks(id)).status).to.equal(6n); // EpochSettled
      expect((await task.tasks(id)).locked).to.equal(0n);
      await expect(task.settle(id)).to.be.revertedWithCustomError(task, "InvalidParams").withArgs("epochs remain");

      await runEpoch(fx, id, 1, node);
      await expect(task.settle(id)).to.be.revertedWithCustomError(task, "InvalidParams").withArgs("epochs remain");

      await runEpoch(fx, id, 2, node);
      await expect(task.settle(id)).to.emit(task, "EscrowSettled");
    });

    it("does not carry a dispute quorum from one epoch into the next", async () => {
      const fx = await deployFixture();
      const { task, buyer, node, node2, node3, node4 } = fx;
      const id = await sealed(fx, { epochs: 2, nodes: [node, node2, node3, node4] });

      // Burn the quorum on epoch 0.
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));
      for (const r of [node2, node3, node4]) {
        await task.connect(r).reportDispute(id, 0, bytes32Of(1234));
      }
      const [, reported] = await task.disputeQuorum(id);
      expect(reported).to.equal(3n);
      await time.increase(3600 + 600);
      await task.finalizeEpoch(id, 0);

      // Epoch 1 must start from zero, otherwise the epoch-0 quorum would auto-reject it without
      // anybody re-executing anything.
      await runEpoch(fx, id, 1, node);
      const ch = await fx.vault.channelInfo(await task.epochChannel(id, 1));
      expect(ch.node).to.equal(node.address);
      expect(ch.maxCumulative).to.be.greaterThan(0n);
    });
  });

  describe("reveal gating", () => {
    async function settled() {
      const fx = await deployFixture();
      const id = await sealed(fx, { epochs: 1 });
      await runEpoch(fx, id, 0, fx.node);
      await fx.task.settle(id);
      return { fx, id };
    }

    it("refuses a reveal without a valid committee signature", async () => {
      const { fx, id } = await settled();
      await expect(fx.task.connect(fx.buyer).requestReveal(id, "0x01")).to.be.revertedWithCustomError(fx.gate, "InvalidBLS");
    });

    it("refuses a reveal of a CID that is not the committed output", async () => {
      const { fx, id } = await settled();
      // `CipherTask.requestReveal` pins the CID itself, so the `OutputNotRegistered` guard is
      // exercised directly on the gate - which is where a caller-supplied CID could actually
      // diverge from the accepted weights. The message is read from the gate rather than rebuilt
      // here, so the test cannot drift from the contract's own encoding.
      const wrongCid = bytes32Of("somebody-elses-weights");
      await fx.bls.approve(await fx.gate.revealMessage(id, wrongCid));
      await expect(fx.gate.requestReveal(id, wrongCid, "0x01")).to.be.revertedWithCustomError(fx.gate, "OutputNotRegistered");
    });

    it("opens on a valid aggregate signature and only counts distinct committee members", async () => {
      const { fx, id } = await settled();
      const { task, bls, gate, buyer, committee, outsider } = fx;
      const [cid] = await task.acceptedWeights(id);

      // A committee signature over a *different* CID must not open the gate, even though the
      // orchestrator asks for the committed one.
      await bls.approve(await gate.revealMessage(id, bytes32Of("somebody-elses-weights")));
      await expect(task.connect(buyer).requestReveal(id, "0x01")).to.be.revertedWithCustomError(gate, "InvalidBLS");

      await bls.approve(await gate.revealMessage(id, cid));
      await expect(task.connect(buyer).requestReveal(id, "0x01")).to.emit(task, "RevealRequested");
      expect((await task.tasks(id)).status).to.equal(8n); // Revealing (TaskStatus.Disclosed == 9)

      // Only registered members may contribute a partial decryption.
      await expect(gate.submitPartialDecryption(id, bytes32Of(1))).to.be.revertedWithCustomError(gate, "NotCommitteeMember");
      await gate.connect(committee).submitPartialDecryption(id, bytes32Of(1));
      expect(await gate.partialCount(id)).to.equal(1n);
      expect(await gate.canDecrypt(id)).to.equal(false); // threshold is 1, so already combined
      void outsider;
    });
  });

  describe("reward channel lifecycle", () => {
    it("rejects a sliceIndex that does not fit the monotonic counter", async () => {
      // `consumed` is a uint64 and `uint64(sliceIndex)` truncates instead of reverting, so
      // `2**64` folded to 0 and set `consumed` back to 1 — silently rewinding the replay guard
      // that F-14 documents. `withdrawn` still bounds the money, but the index must not move
      // backwards, and `uint64(sliceIndex) + 1` must not be able to overflow either.
      const fx = await deployFixture();
      const { task, vault, node } = fx;
      const id = await sealed(fx, { epochs: 1 });
      await runEpoch(fx, id, 0, node);

      const channelId = await task.epochChannel(id, 0);
      const ch = await vault.channelInfo(channelId);
      const sig = ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint128"], [channelId, 0, ch.maxCumulative]);
      await vault.connect(node).redeem(channelId, 0, ch.maxCumulative, ethers.MaxUint256, sig);
      const consumedAfterFirst = (await vault.channelInfo(channelId)).consumed;
      expect(consumedAfterFirst).to.equal(1n);

      for (const bad of [1n << 64n, ethers.MaxUint256]) {
        await expect(
          vault.connect(node).redeem(channelId, bad, ch.maxCumulative, ethers.MaxUint256, sig)
        ).to.be.revertedWithCustomError(vault, "SliceIndexOutOfRange");
      }
      // The counter did not move.
      expect((await vault.channelInfo(channelId)).consumed).to.equal(consumedAfterFirst);
    });

    it("reclaim after a full redeem closes the channel cleanly and preserves the vault invariant", async () => {
      const fx = await deployFixture();
      const { task, vault, token, node } = fx;
      const id = await sealed(fx, { epochs: 1 });
      await runEpoch(fx, id, 0, node);

      const channelId = await task.epochChannel(id, 0);
      const ch = await vault.channelInfo(channelId);
      const sig = ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint128"], [channelId, 0, ch.maxCumulative]);
      await vault.connect(node).redeem(channelId, 0, ch.maxCumulative, ethers.MaxUint256, sig);

      // Window matures; the node reclaims the (empty) remainder. This used to underflow
      // `channelLocksTotal` because the release subtracted the full cap, not the residual.
      await time.increase(7 * 86_400 + 1);
      await expect(vault.connect(node).reclaim(channelId)).to.emit(vault, "ChannelReclaimed");
      expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
      // The whole node pool reached the node via the redeem, nothing more to reclaim.
      expect(await token.balanceOf(node.address)).to.equal(ch.maxCumulative);
    });

    it("settle sweeps an expired channel back into the sub-balance without breaking the invariant", async () => {
      const fx = await deployFixture();
      const { task, vault, token, buyer, node } = fx;
      const id = await sealed(fx, { epochs: 1 });
      await runEpoch(fx, id, 0, node);

      const channelId = await task.epochChannel(id, 0);
      const ch = await vault.channelInfo(channelId);
      const sig = ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint128"], [channelId, 0, ch.maxCumulative]);
      await vault.connect(node).redeem(channelId, 0, ch.maxCumulative, ethers.MaxUint256, sig);

      // Let the reward window mature so `settle`'s sweep actually closes the channel. A sweep
      // of a fully-redeemed channel must be a no-op that keeps `channelLocksTotal` consistent.
      await time.increase(7 * 86_400 + 1);
      await task.settle(id);
      expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
      expect((await vault.channelInfo(channelId)).closed).to.equal(true);
      // The buyer gets back nothing (all legs consumed), but the vault accounting is sound.
      expect(await vault.taskBalance(id)).to.equal(0n);
      void token;
      void buyer;
    });
  });

  describe("abort", () => {
    it("refunds the buyer in full when nothing was committed", async () => {
      const fx = await deployFixture();
      const { task, vault, token, buyer, escrow } = fx;
      await task.connect(buyer).createTask(escrow, params(buyer.address));
      const id = await task.taskCount();
      await task.connect(buyer).abort(id, reason4("changed_mind"));

      expect((await task.tasks(id)).status).to.equal(10n); // Aborted (TaskStatus.Paused == 11)
      expect(await task.pendingPayout(buyer.address)).to.equal(escrow);
      await vault.connect(buyer).claim();
      expect(await token.balanceOf(buyer.address)).to.equal(escrow);
    });

    it("strands nothing when aborted with an open but uncommitted epoch", async () => {
      const fx = await deployFixture();
      const { task, vault, token, buyer, node, escrow } = fx;
      const id = await sealed(fx, { epochs: 3 });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await task.connect(buyer).abort(id, reason4("too_expensive"));

      // Nobody committed, so nobody did work and nothing is retained: the buyer is made whole.
      // The previous behaviour withheld ABORT_LOCK_BPS (20% of the 5e7 lock = 1e7) that was
      // then never paid to anyone, permanently burning it in the vault.
      await vault.connect(buyer).claim();
      expect(await token.balanceOf(buyer.address)).to.equal(escrow);
      expect(await vault.taskBalance(id)).to.equal(0n);
      expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
      void node;
    });

    it("retains a redeemable slice for a node that verified an epoch before the abort", async () => {
      const fx = await deployFixture();
      const { task, vault, token, buyer, node, escrow } = fx;
      const id = await sealed(fx, { epochs: 3 });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));
      await task.connect(buyer).abort(id, reason4("too_expensive"));

      // ABORT_LOCK_BPS is 2000, so the node keeps 20% of the 5e7 epoch lock, and it is a real
      // redeemable channel rather than a number stuck in the sub-balance.
      const slice = 10_000_000n;
      const channelId = await vault.channelNonce();
      const ch = await vault.channelInfo(channelId);
      expect(ch.node).to.equal(node.address);
      expect(ch.maxCumulative).to.equal(slice);

      const sig = ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint128"], [channelId, 0, slice]);
      const digest = await vault.redeemDigest(channelId, await task.getAddress(), node.address, slice, ch.unlockAt, ethers.MaxUint256);
      await vault.connect(node).redeem(channelId, 0, slice, ethers.MaxUint256, sig);
      expect(await token.balanceOf(node.address)).to.equal(slice);

      await vault.connect(buyer).claim();
      expect(await token.balanceOf(buyer.address)).to.equal(escrow - slice);
      expect(await vault.taskBalance(id)).to.equal(0n);
      expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
    });
  });

  describe("access control", () => {
    it("restricts openEpoch to the buyer or update manager", async () => {
      const fx = await deployFixture();
      const { task, buyer, outsider, node } = fx;
      const id = await sealed(fx, { nodes: [node] });
      await expect(
        openEpochAs(fx, id, outsider, bytes32Of(1), bytes32Of(2))
      ).to.be.revertedWithCustomError(task, "NotUpdateManagerOrOwner");
      void buyer;
    });

    it("lets the owner pause and blocks new tasks", async () => {
      const fx = await deployFixture();
      const { task, owner, buyer } = fx;
      await task.connect(owner).setPaused(true);
      await expect(task.connect(buyer).createTask(fx.escrow, params(buyer.address))).to.be.revertedWithCustomError(task, "Paused");
    });

    it("holds the reentrancy guard when a token calls back mid-transfer", async () => {
      // A hostile escrow token is the realistic attack surface: `fundTask` is `nonReentrant` and
      // pulls with `transferFrom`, so a token that re-enters the vault inside its own
      // `transferFrom` lands while the guard flag is set. The callback targets `claim`, which has
      // no access control, so the only thing that can stop it is the guard.
      const base = await deployFixture();
      const evil = await ethers.deployContract("ReentrantTokenMock", [ethers.ZeroAddress, "0x"]);
      const victim = await ethers.deployContract("PaymentVault", [await evil.getAddress()]);

      await evil.mint(base.buyer.address, 1_000_000n);
      await evil.connect(base.buyer).approve(await victim.getAddress(), ethers.MaxUint256);
      await victim.setTaskManager(base.owner.address);
      await evil.setTarget(await victim.getAddress());
      await evil.setReentry(victim.interface.encodeFunctionData("claim"));

      await victim.connect(base.owner).fundTask(1n, 1_000_000n, base.buyer.address);

      // The callback fired and was rejected with the guard's own selector, not with a business
      // error: that is the difference between "the flag held" and "the call happened to fail".
      expect(await evil.tried()).to.equal(true);
      const ret = await evil.lastRevert();
      expect(ret).to.not.equal("0x");
      expect(ret.slice(0, 10)).to.equal(ethers.id("Reentrancy()").slice(0, 10));
      // The outer call completed and the vault's invariant still holds.
      expect(await victim.taskBalance(1n)).to.equal(1_000_000n);
      expect(await victim.totalLocked()).to.equal(await victim.accountedLocked());
    });

    it("releases the reentrancy guard after a successful call", async () => {
      const fx = await deployFixture();
      const token = await ethers.deployContract("TestToken");
      const vault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
      await vault.setTaskManager(fx.owner.address);
      await token.mint(fx.buyer.address, 3_000_000n);
      await token.connect(fx.buyer).approve(await vault.getAddress(), ethers.MaxUint256);

      // Three sequential guarded calls: if the flag leaked from the first, the later ones would
      // revert with `Reentrancy`. Transient storage is per-transaction, so all three must pass.
      for (const id of [7n, 8n, 9n]) {
        await vault.fundTask(id, 500_000n, fx.buyer.address);
        expect(await vault.taskBalance(id)).to.equal(500_000n);
      }
      expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
    });
  });

  describe("verifier rotation timelock", () => {
    // The verifier gates every payout, so a one-transaction owner swap meant a compromised key
    // could install a permissive verifier with no window in which to notice.
    async function verifierFixture() {
      const [owner, outsider] = await ethers.getSigners();
      const inner = await ethers.deployContract("MockStarkVerifier", [48_576]);
      const altInner = await ethers.deployContract("MockStarkVerifier", [48_576]);
      // The timelock lives on the ProofVerifier adapter, not on the mock it points at.
      const verifier = await ethers.deployContract("ProofVerifier", [await inner.getAddress(), 48_576, bytes32Of("domain")]);
      const alt = await altInner.getAddress();
      return { owner, outsider, verifier, alt };
    }

    it("refuses to rotate immediately and requires the timelock to elapse", async () => {
      const { owner, verifier, alt } = await verifierFixture();
      const original = await verifier.starkVerifier();

      await expect(verifier.connect(owner).proposeRotation(alt)).to.emit(verifier, "VerifierRotationProposed");
      // Still the old verifier: proposing must not change anything yet.
      expect(await verifier.starkVerifier()).to.equal(original);

      await expect(verifier.executeRotation()).to.be.revertedWithCustomError(verifier, "TooEarly");
      await time.increase(7 * 86_400);
      await expect(verifier.executeRotation()).to.emit(verifier, "VerifierRotated");
      expect(await verifier.starkVerifier()).to.equal(alt);
    });

    it("lets anyone execute after the delay, so a frozen rotation cannot outlive its owner key", async () => {
      const { outsider, verifier, alt } = await verifierFixture();
      await verifier.proposeRotation(alt);
      await time.increase(7 * 86_400);
      // Not the owner, and not blocked: the delay has passed, so the rotation is owed.
      await expect(verifier.connect(outsider).executeRotation()).to.emit(verifier, "VerifierRotated");
      expect(await verifier.starkVerifier()).to.equal(alt);
    });

    it("lets only the owner cancel a queued rotation, and refuses a double rotation", async () => {
      const { owner, outsider, verifier, alt } = await verifierFixture();
      await verifier.connect(owner).proposeRotation(alt);
      await expect(verifier.connect(outsider).cancelRotation()).to.be.revertedWithCustomError(verifier, "NotOwner");

      await expect(verifier.connect(owner).cancelRotation()).to.emit(verifier, "VerifierRotationCancelled");
      await time.increase(7 * 86_400);
      // Cancelled means cancelled: the old verifier stays.
      await expect(verifier.executeRotation()).to.be.revertedWithCustomError(verifier, "NoPendingRotation");
      expect(await verifier.starkVerifier()).to.not.equal(alt);
    });

    it("refuses a rotation to the zero address and by a non-owner", async () => {
      const { owner, outsider, verifier } = await verifierFixture();
      await expect(verifier.connect(owner).proposeRotation(ethers.ZeroAddress)).to.be.revertedWithCustomError(verifier, "ZeroAddress");
      await expect(verifier.connect(outsider).proposeRotation(ethers.ZeroAddress)).to.be.revertedWithCustomError(verifier, "NotOwner");
    });
  });

  describe("devnet mocks are not open to anyone", () => {
    // `deploy.ts` installs both of these as the devnet's real verifier and BLS verifier, so
    // unrestricted test helpers were reachable attack surface rather than test-only sloppiness.
    it("stops an outsider from poisoning a transcript", async () => {
      const fx = await deployFixture();
      const { verifier, outsider, task, buyer, node } = fx;
      const id = await sealed(fx);
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      const transcript = await task.proofTranscript(id, 0, bytes32Of(999));

      // Anyone could spend a transcript and permanently invalidate the honest node's proof for
      // that (task, epoch), because `consumed` is never cleared.
      await expect(verifier.connect(outsider).consume(transcript)).to.be.revertedWithCustomError(verifier, "NotOwner");
      await verifier.connect(fx.owner).consume(transcript);
      // Now the owner-issued consumption takes effect and the proof is refused.
      await expect(
        task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(1), bytes32Of(2), bytes32Of(3), bytes32Of(999))
      ).to.be.revertedWithCustomError(task, "ProofRejected");
    });

    it("stops an outsider from forging the committee signature", async () => {
      const fx = await deployFixture();
      const { bls, outsider, gate, task } = fx;
      const id = await sealed(fx, { epochs: 1 });
      await runEpoch(fx, id, 0, fx.node);
      await task.settle(id);
      const [cid] = await task.acceptedWeights(id);
      const message = await gate.revealMessage(id, cid);

      await expect(bls.connect(outsider).approve(message)).to.be.revertedWithCustomError(bls, "NotOwner");
      // So an outsider cannot open a reveal for a task they have no business touching.
      await expect(gate.requestReveal(id, cid, "0x01")).to.be.revertedWithCustomError(gate, "InvalidBLS");
    });
  });

  describe("governance recovery", () => {
    it("emergencyUnwind aborts a task stuck past its epoch deadline + dispute window", async () => {
      const fx = await deployFixture();
      const { task, buyer, node } = fx;
      const id = await sealed(fx, { nodes: [node] });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));

      // The epoch is open but nobody committed; after deadline + dispute window the owner
      // can unwind it so funds are recoverable.
      await time.increase(3600 + 600 + 1);
      await expect(task.connect(fx.owner).emergencyUnwind(id)).to.emit(task, "TaskAborted");
      expect((await task.tasks(id)).status).to.equal(10n); // Aborted
    });

    it("emergencyUnwind refuses while the epoch is still live", async () => {
      const fx = await deployFixture();
      const { task, buyer, node } = fx;
      const id = await sealed(fx, { nodes: [node] });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await expect(fx.task.connect(fx.owner).emergencyUnwind(id)).to.be.revertedWithCustomError(task, "InvalidParams");
    });

    it("reclaimUnspentEpochs never touches the contributor or committee pools", async () => {
      const fx = await deployFixture();
      const { task, vault, token, buyer, node, node2, node3, node4, escrow } = fx;
      const id = await sealed(fx, { epochs: 2, nodes: [node, node2, node3, node4] });
      await openEpochAs(fx, id, buyer, bytes32Of(100), bytes32Of(101));
      await task.connect(node).commitEpoch(id, 0, proofRef(1), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));
      // Quorum rejects epoch 0: no winner is paid, and the reporter bounty is only 200 bps of
      // the lock. Run epoch 1 cleanly so `nextEpoch == epochs` and the buyer can reclaim.
      for (const r of [node2, node3, node4]) await task.connect(r).reportDispute(id, 0, bytes32Of(777));
      await task.finalizeEpoch(id, 0);
      await runEpoch(fx, id, 1, node);

      // userPool 800M + committeePool 50M must survive; only the unspent node pool may go back.
      const reserved = 800_000_000n + 50_000_000n;
      const available = await vault.taskBalance(id);
      expect(available).to.be.greaterThan(reserved);
      await task.connect(buyer).reclaimUnspentEpochs(id);

      expect(await vault.taskBalance(id)).to.equal(reserved);
      // The payout is credited, not pushed, so the buyer claims it.
      expect(await task.pendingPayout(buyer.address)).to.equal(available - reserved);
      await vault.connect(buyer).claim();
      expect(await token.balanceOf(buyer.address)).to.equal(available - reserved);
      void escrow;
    });

    it("reclaimUnspentEpochs returns nothing when only the contributor and committee pools remain", async () => {
      const fx = await deployFixture();
      const { task, vault, token, buyer, node, escrow } = fx;
      const id = await sealed(fx, { epochs: 1, nodes: [node] });
      await runEpoch(fx, id, 0, node);

      // The whole node pool went to the winner's channel, so the sub-balance holds exactly the
      // two pools that `settle` owns. Reclaiming must be a no-op rather than a silent drain of
      // what the contributors and the committee are owed.
      expect(await vault.taskBalance(id)).to.equal(850_000_000n);
      await task.connect(buyer).reclaimUnspentEpochs(id);
      expect(await vault.taskBalance(id)).to.equal(850_000_000n);
      expect(await token.balanceOf(buyer.address)).to.equal(0n);

      // `settle` still pays everyone out in full afterwards.
      await task.settle(id);
      expect(await vault.taskBalance(id)).to.equal(0n);
      void escrow;
    });
  });

  describe("full reveal flow", () => {
    async function settled() {
      const fx = await deployFixture();
      const id = await sealed(fx, { epochs: 1 });
      await runEpoch(fx, id, 0, fx.node);
      await fx.task.settle(id);
      return { fx, id };
    }

    it("requestReveal -> partial decryptions -> withdraw releases the task to Disclosed", async () => {
      const { fx, id } = await settled();
      const { task, bls, gate, buyer, committee } = fx;
      const [cid] = await task.acceptedWeights(id);

      await bls.approve(await gate.revealMessage(id, cid));
      await expect(task.connect(buyer).requestReveal(id, "0x01")).to.emit(task, "RevealRequested");
      expect((await task.tasks(id)).status).to.equal(8n); // Revealing

      await gate.connect(committee).submitPartialDecryption(id, bytes32Of(1));
      expect(await gate.partialCount(id)).to.equal(1n);

      await expect(task.connect(buyer).withdraw(id)).to.emit(task, "RevealCompleted");
      expect((await task.tasks(id)).status).to.equal(9n); // Disclosed
    });

    it("withdraw is blocked before the reveal starts", async () => {
      const { fx, id } = await settled();
      await expect(fx.task.connect(fx.buyer).withdraw(id)).to.be.revertedWithCustomError(fx.task, "RevealNotAllowed");
    });

    it("withdraw is blocked while the gate has not reached threshold", async () => {
      // The bug this guards: `withdraw` only checked `status == Revealing`, so the buyer could
      // call it the instant `requestReveal` succeeded — zero partials submitted — and reach
      // `Disclosed`. That status is the protocol's on-chain attestation that the committee
      // decrypted the output, so bypassing the ceremony made it worthless as evidence.
      const { fx, id } = await settled();
      const { task, bls, gate, buyer, committee, owner } = fx;
      const [cid] = await task.acceptedWeights(id);

      await bls.approve(await gate.revealMessage(id, cid));
      await task.connect(buyer).requestReveal(id, "0x01");
      expect((await task.tasks(id)).status).to.equal(8n); // Revealing
      expect(await gate.revealCompleted(id)).to.equal(false);

      // Not the buyer, not the update manager, not even the owner: nobody may shortcut it.
      for (const caller of [buyer, owner]) {
        await expect(task.connect(caller).withdraw(id)).to.be.revertedWithCustomError(task, "RevealNotAllowed");
      }
      expect((await task.tasks(id)).status).to.equal(8n); // still Revealing

      // Once the committee actually submits, the same call succeeds.
      await gate.connect(committee).submitPartialDecryption(id, bytes32Of(1));
      expect(await gate.revealCompleted(id)).to.equal(true);
      await expect(task.connect(buyer).withdraw(id)).to.emit(task, "RevealCompleted");
      expect((await task.tasks(id)).status).to.equal(9n); // Disclosed
    });

    it("revealCompleted is false for a task that never requested a reveal", async () => {
      const { fx, id } = await settled();
      expect(await fx.gate.revealCompleted(id)).to.equal(false);
      expect(await fx.gate.partialCount(id)).to.equal(0n);
    });
  });

  describe("encrypted state ACL", () => {
    it("refuses to grant decryption of the orchestration state to an unrelated address", async () => {
      // The bug this guards: `grantStateAccess(account)` had no access control at all, so any
      // caller could hand a third party a decryption grant on `_encState` — the buyer's
      // encrypted loss curve, noise budget and epoch checkpoint.
      const fx = await deployFixture();
      const { task, buyer, alice, outsider, node } = fx;
      const id = await sealed(fx, { nodes: [node] });

      for (const stranger of [alice, outsider]) {
        await expect(
          task.grantStateAccess(id, stranger.address)
        ).to.be.revertedWithCustomError(task, "InvalidParams").withArgs("not a task party");
      }
      // The restriction is on the *target*, not just the caller: even the buyer, whose telemetry
      // this is, cannot widen the ACL to an address that has no role in the task.
      await expect(
        task.connect(buyer).grantStateAccess(id, alice.address)
      ).to.be.revertedWithCustomError(task, "InvalidParams").withArgs("not a task party");

      // The parties the protocol already trusts keep working access: a registered node, the
      // buyer themselves, and the owner.
      await expect(task.grantStateAccess(id, node.address)).to.emit(task, "StateAccessGranted");
      await expect(task.grantStateAccess(id, buyer.address)).to.emit(task, "StateAccessGranted");
      await expect(task.grantStateAccess(id, fx.owner.address)).to.emit(task, "StateAccessGranted");
      // Zero address is rejected outright.
      await expect(task.grantStateAccess(id, ethers.ZeroAddress)).to.be.revertedWithCustomError(task, "ZeroAddress");
      // Unknown task.
      await expect(task.grantStateAccess(999n, node.address)).to.be.revertedWithCustomError(task, "InvalidParams").withArgs("unknown");
    });
  });
});
