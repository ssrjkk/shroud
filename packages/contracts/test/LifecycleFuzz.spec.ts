import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

import type { CipherTask, PaymentVault } from "../typechain-types";
import { deployLinked } from "../scripts/libraries";
import { bytes32Of, externalUint64, matureRewardWindows, params, proofFor, proofRef, reason4 } from "./helpers";

/**
 * Stateful fuzz over the epoch lifecycle and the settlement accounting.
 *
 * A deterministic PRNG (mulberry32, fixed seeds) drives a weighted mix of every
 * money-moving entry point across several tasks — create, contribute, seal, open,
 * register, commit (honest and divergent digests), dispute (bare and commit-reveal),
 * contribution-bond requirements, finalize, paged settlement,
 * bond release, aborts and time travel — while two invariants are asserted after *every*
 * step, whether the step succeeded or reverted:
 *
 *   1. `totalLocked == accountedLocked()` (the vault's own O(1) conservation check);
 *   2. `token.balanceOf(vault) >= totalLocked` (the vault never pays what it holds).
 *
 * Pure uniform choice almost never lines a lifecycle up, so each action prefers tasks
 * in the local phase it needs (tracked without extra RPC; the chain stays the
 * authority), aborts spare pipelined tasks, and commits prefer registered nodes — the
 * way the real worker only bids after `registerNode` lands. Reverts are ordinary data
 * (tallied per action with first examples); a Hardhat *panic* (arithmetic fault) is
 * not — it rethrows and fails the run. If chaos alone settles nothing, a directed
 * closing drives one task through the full loop and asserts `isFullySettled`.
 *
 * A failure message names the seed, the step and the action, and the seeds make the
 * whole run reproducible: `npx hardhat test test/LifecycleFuzz.spec.ts`.
 */
describe("LifecycleFuzz", () => {
  /** Deterministic PRNG: same seed, same run, on every machine. */
  function mulberry32(seed: number) {
    let a = seed >>> 0;
    return () => {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  type Fx = Awaited<ReturnType<typeof deployFixture>>;

  async function deployFixture() {
    const [owner, buyer, alice, bob, carol, node, node2, node3, committee, outsider, treasury] =
      await ethers.getSigners();
    const token = await ethers.deployContract("TestToken");
    const vault: PaymentVault = await ethers.deployContract("PaymentVault", [
      await token.getAddress(),
    ]);
    const verifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
    const bls = await ethers.deployContract("MockBLS");
    const gate = await ethers.deployContract("DecryptionGate", [
      await bls.getAddress(),
      bytes32Of("bls-agg"),
      1,
    ]);
    const task: CipherTask = await deployLinked("CipherTask", [
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

    // Generous funding: the fuzz creates several tasks, and every registration pulls a
    // fresh bond. Exact-balance assertions belong to the deterministic suite; here the
    // invariant is conservation, not parsimony.
    await token.mint(buyer.address, 1_000_000_000_000_000n);
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);
    const bond = await vault.REGISTRATION_BOND();
    for (const n of [node, node2, node3]) {
      await token.mint(n.address, bond * 50n);
      await token.connect(n).approve(await vault.getAddress(), ethers.MaxUint256);
    }
    return { token, vault, task, owner, buyer, alice, bob, carol, node, node2, node3, committee, outsider, treasury };
  }

  async function checkInvariants(fx: Fx, ctx: string) {
    const { token, vault } = fx;
    const locked = await vault.totalLocked();
    const accounted = await vault.accountedLocked();
    expect(locked, `${ctx}: totalLocked == accountedLocked`).to.equal(accounted);
    const balance = await token.balanceOf(await vault.getAddress());
    expect(balance >= locked, `${ctx}: vault holds what it owes (${balance} < ${locked})`).to.be.true;
  }

  function isPanic(e: unknown): boolean {
    return /panic code|invalid opcode|0x4e487b71/i.test(String((e as Error)?.message ?? e));
  }

  for (const seed of [11, 22, 33]) {
    it(`keeps the vault solvent through a random lifecycle (seed ${seed})`, async function () {
      this.timeout(600_000);
      const fx = await deployFixture();
      const { task, token, vault, buyer, node, node2, node3, alice, bob, carol, outsider } = fx;
      const rand = mulberry32(seed);
      const nodes = [node, node2, node3];
      const contributors = [alice, bob, carol, outsider];
      const tasks: bigint[] = [];
      let ctr = 1_000_000;
      // Cached once: the PoP message binds all five, and re-reading them per step would
      // spend two RPCs per registration for values that never change mid-run.
      const taskAddr = await task.getAddress();
      const chainId = Number((await ethers.provider.getNetwork()).chainId);
      let okCommits = 0;
      let okFinalizes = 0;
      const attempts: Record<string, number> = {};
      const successes: Record<string, number> = {};
      const firstRevert: Record<string, string> = {};
      const revertKinds: Record<string, Record<string, number>> = {};
      // Nodes this run registered, per task: commits aim where registration exists,
      // the way the real worker only bids after `registerNode` lands.
      const registered = new Map<bigint, Set<string>>();
      const note = (kind: string, ok: boolean, e?: unknown) => {
        attempts[kind] = (attempts[kind] ?? 0) + 1;
        if (ok) {
          successes[kind] = (successes[kind] ?? 0) + 1;
        } else {
          if (firstRevert[kind] === undefined) {
            firstRevert[kind] = String((e as Error)?.message ?? e).split("\n")[0].slice(0, 160);
          }
          // EDR names custom errors only when it recognises the executing contract, and
          // that recognition is flaky across multi-fixture runs (same selector, same
          // transaction: named alone, "unrecognized" in a pack). Fall back to the raw
          // 4-byte selector so the tally keeps its granularity either way; the selectors
          // themselves are pinned against the artifacts, not against prose.
          const msg = String((e as Error)?.message ?? "");
          const name = /custom error '(\w+)/.exec(msg)?.[1]
            ?? /return data: (0x[0-9a-f]{8})/.exec(msg)?.[1]
            ?? "other";
          const tally = (revertKinds[kind] ??= {});
          tally[name] = (tally[name] ?? 0) + 1;
        }
      };
      const pick = <T,>(xs: T[]): T => xs[Math.floor(rand() * xs.length) % xs.length];
      const honestDigest = (id: bigint, epoch: bigint) =>
        ethers.keccak256(ethers.toUtf8Bytes(`Shroud/fuzz/honest/${id}/${epoch}`));
      const byzDigest = (id: bigint, epoch: bigint, salt: number) =>
        ethers.keccak256(ethers.toUtf8Bytes(`Shroud/fuzz/byz/${id}/${epoch}/${salt}`));

      const STEPS = 200;
      const kindOf = (a: string) => (a.startsWith("time+") ? "time" : a.split("/")[0]);
      // Local lifecycle phases per task (0 fresh … 6 settled), advanced on successful
      // actions only. Random choice alone almost never lines a lifecycle up, so each
      // action prefers tasks in the phase it needs; aborts mark tasks dead. No extra
      // RPC: the chain remains the authority, this is only a scheduler.
      const phase = new Map<bigint, number>();
      const dead = new Set<bigint>();
      const alive = () => tasks.filter((id) => !dead.has(id));
      const inPhases = (lo: number, hi: number) =>
        alive().filter((id) => {
          const p = phase.get(id) ?? 0;
          return p >= lo && p <= hi;
        });
      const pickPhase = (lo: number, hi: number): bigint | null => {
        const c = inPhases(lo, hi);
        return c.length ? pick(c) : null;
      };
      const anyAlive = (): bigint | null => {
        const c = alive();
        return c.length ? pick(c) : null;
      };
      const raise = (id: bigint, to: number) => {
        phase.set(id, Math.max(phase.get(id) ?? 0, to));
      };
      for (let step = 0; step < STEPS; step++) {
        const roll = rand() * 118;
        let act = "idle";
        try {
          if (roll < 8) {
            act = "createTask";
            const p = params(buyer.address, {
              epochs: 1 + Math.floor(rand() * 3),
              minContributors: 1,
              maxContributors: 5,
              minRowsPerShard: 1 + Math.floor(rand() * 3),
              features: 2,
              labelBits: 8,
              contributionWindow: 86400,
              epochDuration: 300 + Math.floor(rand() * 600),
              disputeWindow: 60 + Math.floor(rand() * 240),
            });
            await task.connect(buyer).createTask(1_000_000_000n, p);
            const id = await task.taskCount();
            tasks.push(id);
            phase.set(id, 0);
          } else if (roll < 22) {
            const id = pickPhase(0, 1) ?? anyAlive();
            if (id === null) continue;
            act = `contribute/${id}`;
            const c = pick(contributors);
            await task
              .connect(c)
              .submitContribution(
                id,
                bytes32Of(ctr++),
                bytes32Of(ctr++),
                proofFor(ctr++),
                bytes32Of(ctr++),
                1 + Math.floor(rand() * 500)
              );
          } else if (roll < 28) {
            const id = pickPhase(0, 1) ?? anyAlive();
            if (id === null) continue;
            act = `seal/${id}`;
            await task.connect(buyer).sealTask(id);
            phase.set(id, 2);
          } else if (roll < 40) {
            const id = pickPhase(2, 6) ?? anyAlive();
            if (id === null) continue;
            act = `open/${id}`;
            const st = await externalUint64(await task.getAddress(), buyer.address, BigInt(ctr++));
            await task.connect(buyer).openEpoch(id, bytes32Of(ctr++), bytes32Of(ctr++), st.handle, st.proof);
            raise(id, 3);
          } else if (roll < 50) {
            const id = anyAlive();
            if (id === null) continue;
            const n = pick(nodes);
            act = `register/${id}/${n.address.slice(0, 10)}`;
            if (rand() < 0.4) {
              // Proof-of-possession registration: the BLS key bound to a live signer.
              // Same bond path as the bare registration underneath.
              const key = bytes32Of(ctr++);
              const inner = ethers.keccak256(
                ethers.AbiCoder.defaultAbiCoder().encode(
                  ["uint256", "bytes32", "address", "uint256", "address"],
                  [id, key, n.address, chainId, taskAddr]
                )
              );
              const sig = await n.signMessage(ethers.getBytes(inner));
              await task.connect(n).registerNodeWithPop(id, key, sig);
            } else {
              await task.connect(n).registerNode(id, bytes32Of(ctr++));
            }
            if (!registered.has(id)) registered.set(id, new Set());
            registered.get(id)?.add(n.address);
          } else if (roll < 70) {
            const id = pickPhase(2, 5) ?? anyAlive();
            if (id === null) continue;
            const t = await task.tasks(id);
            const epoch = t.nextEpoch;
            const known = [...nodes.filter((n) => registered.get(id)?.has(n.address))];
            const n = known.length && rand() < 0.8 ? pick(known) : pick(nodes);
            const digest =
              rand() < 0.7 ? honestDigest(id, epoch) : byzDigest(id, epoch, ctr++);
            act = `commit/${id}/${epoch}/${n.address.slice(0, 10)}`;
            const pins = [bytes32Of(ctr++), bytes32Of(ctr++), bytes32Of(ctr++)];
            if (rand() < 0.3) {
              // Segmented path: same bindings and winner logic through the segmented verifier.
              await task
                .connect(n)
                .commitEpochSegmented(id, epoch, proofRef(ctr++), pins[0], pins[1], pins[2], digest);
            } else {
              await task
                .connect(n)
                .commitEpoch(
                  id,
                  epoch,
                  proofRef(ctr++),
                  pins[0],
                  pins[1],
                  pins[2],
                  digest
                );
            }
            raise(id, 4);
            okCommits++;
          } else if (roll < 78) {
            const id = pickPhase(2, 5) ?? anyAlive();
            if (id === null) continue;
            const t = await task.tasks(id);
            act = `dispute/${id}/${t.nextEpoch}`;
            // Every node whose verified commit differs from the claim reports it: with
            // divergent commits in flight this reaches quorum organically and exercises
            // the rejection path, not just single reports. Reports that agree with the
            // claim (or repeat) revert inside and are skipped, not counted.
            let sent = 0;
            for (const n of nodes) {
              const mine = await task.commits(id, t.nextEpoch, n.address);
              if (!mine.verified || mine.traceDigest === ethers.ZeroHash) continue;
              try {
                await task.connect(n).reportDispute(id, t.nextEpoch, mine.traceDigest);
                sent++;
              } catch {
                // Agrees with the claim, already recorded, or outside the window.
              }
            }
            if (sent === 0) continue;
          } else if (roll < 90) {
            const id = pickPhase(2, 5) ?? anyAlive();
            if (id === null) continue;
            const t = await task.tasks(id);
            act = `finalize/${id}/${t.nextEpoch}`;
            await task.finalizeEpoch(id, t.nextEpoch);
            raise(id, 5);
            okFinalizes++;
          } else if (roll < 98) {
            const id = pickPhase(4, 6) ?? anyAlive();
            if (id === null) continue;
            const cursor = await task.settleCursor(id);
            act = `settleFrom/${id}/${cursor}`;
            await task.settleFrom(id, cursor);
            raise(id, 6);
          } else if (roll < 101) {
            const cand = tasks.length ? pick(tasks) : null;
            if (cand === null) continue;
            const id = cand;
            const n = pick(nodes);
            act = `releaseBond/${id}`;
            await vault.releaseBond(id, n.address);
          } else if (roll < 105) {
            const dt = 1 + Math.floor(rand() * 900);
            act = `time+${dt}s`;
            await time.increase(dt);
          } else if (roll < 108) {
            // Contribution-bond requirement (buyer/manager only, pre-seal preferred).
            // Funded + approved for one random contributor so later submits on this task
            // exercise the pull path instead of only the revert path; unbonded tasks are
            // unaffected. Bonds live in the orchestrator, outside the vault invariant.
            const id = pickPhase(0, 1) ?? anyAlive();
            if (id === null) continue;
            act = `bond/${id}`;
            const amount = pick([0n, 500_000n, 2_000_000n]);
            await task.connect(buyer).setContributionBondRequirement(id, amount);
            if (amount > 0n) {
              const c = pick(contributors);
              await token.mint(c.address, amount);
              await token.connect(c).approve(await task.getAddress(), amount);
            }
          } else if (roll < 111) {
            // Commit-reveal dispute: same standing rule as the bare path (own verified
            // commit, digest differs from the claim), but the digest stays hidden until
            // the reveal. Reports that agree with the claim revert inside and are skipped.
            const id = pickPhase(2, 5) ?? anyAlive();
            if (id === null) continue;
            const t = await task.tasks(id);
            act = `commitreveal/${id}/${t.nextEpoch}`;
            let sent = 0;
            for (const n of nodes) {
              const mine = await task.commits(id, t.nextEpoch, n.address);
              if (!mine.verified || mine.traceDigest === ethers.ZeroHash) continue;
              try {
                const salt = bytes32Of(ctr++);
                const commitment = ethers.solidityPackedKeccak256(
                  ["bytes32", "bytes32", "address"],
                  [mine.traceDigest, salt, n.address]
                );
                await task.connect(n).commitDispute(id, t.nextEpoch, commitment);
                await task.connect(n).reportDisputeWithSalt(id, t.nextEpoch, mine.traceDigest, salt);
                sent++;
              } catch {
                // Agrees with the claim, already recorded (bare or committed), outside the
                // window, or a commitment already open from an earlier step. The commit
                // itself may still have landed — money never moves here either way.
              }
            }
            // No `continue` on sent == 0: even a reads-only pass is a scheduled step worth
            // tallying, and the invariant check below must run regardless.
          } else if (roll < 114) {
            // Slash a contribution bond (buyer). Mostly reverts with NoBondToRelease on
            // unbonded tasks — the path, not the payout, is what's exercised — and honors
            // the post-settlement cutoff when a bonded task actually settles.
            const id = anyAlive();
            if (id === null) continue;
            act = `slashbond/${id}`;
            await task.connect(buyer).slashContributionBond(id, pick(contributors).address);
          } else if (roll < 116) {
            // Release a contribution bond (permissionless, pays the contributor only).
            // Reverts until the task can no longer slash; succeeds after.
            const id = anyAlive();
            if (id === null) continue;
            act = `releasebond/${id}`;
            await task.releaseContributionBond(id, pick(contributors).address);
          } else {
            // Abort only setup-stage tasks: killing a pipeline mid-epoch proves nothing
            // about the unwind path that aborting a fresh task does not, and it starves
            // the commit/finalize coverage the later assertions need.
            const id = pickPhase(0, 2);
            if (id === null) continue;
            act = `abort/${id}`;
            await task.connect(buyer).abort(id, reason4("fuzz"));
            dead.add(id);
          }
        } catch (e) {
          // Phase, window and quorum rules make most random calls revert; that is data,
          // not failure. An arithmetic panic (or anything equally structural) is.
          note(kindOf(act), false, e);
          if (isPanic(e)) throw new Error(`seed=${seed} step=${step} act=${act}: ${e}`);
          await checkInvariants(fx, `seed=${seed} step=${step} act=${act}`);
          continue;
        }
        note(kindOf(act), true);
        await checkInvariants(fx, `seed=${seed} step=${step} act=${act}`);
      }

      // Terminal sweep: settle everything settleable, release every bond, and prove the
      // books still balance afterwards.
      let swept = 0;
      for (const id of tasks) {
        for (let page = 0; page < 12; page++) {
          try {
            await task.settleFrom(id, await task.settleCursor(id));
          } catch {
            break;
          }
        }
        try {
          if (await task.isFullySettled(id)) swept++;
        } catch {
          // A task that never ran to completion is not fully settled; the loop below
          // still releases what it can.
        }
        for (const n of nodes) {
          try {
            await vault.releaseBond(id, n.address);
          } catch {
            // Unregistered or already released: nothing to do.
          }
        }
        await checkInvariants(fx, `seed=${seed} sweep/task=${id}`);
      }
      if (swept === 0) {
        // Chaos alone rarely finishes every epoch of a task (settlement needs all of
        // them finalized), so close one task deterministically: the assertion below
        // then proves the money path works on a ledger the fuzz has already churned.
        const p = params(buyer.address, {
          epochs: 1,
          minContributors: 1,
          maxContributors: 5,
          minRowsPerShard: 1,
          features: 2,
          epochDuration: 600,
          disputeWindow: 120,
        });
        await task.connect(buyer).createTask(1_000_000_000n, p);
        const id: bigint = await task.taskCount();
        await task
          .connect(alice)
          .submitContribution(id, bytes32Of(ctr++), bytes32Of(ctr++), proofFor(ctr++), bytes32Of(ctr++), 8);
        await task.connect(buyer).sealTask(id);
        await task.connect(node).registerNode(id, bytes32Of(ctr++));
        const st = await externalUint64(await task.getAddress(), buyer.address, 1n);
        await task.connect(buyer).openEpoch(id, bytes32Of(ctr++), bytes32Of(ctr++), st.handle, st.proof);
        const digest = honestDigest(id, 0n);
        await task
          .connect(node)
          .commitEpoch(id, 0, proofRef(ctr++), bytes32Of(ctr++), bytes32Of(ctr++), bytes32Of(ctr++), digest);
        await time.increase(600 + 120 + 1);
        await task.finalizeEpoch(id, 0);
        // The directed task pays its winner through a fresh channel; the final settlement
        // page waits for it to mature (F-22).
        await matureRewardWindows();
        for (let page = 0; page < 12; page++) {
          try {
            await task.settleFrom(id, await task.settleCursor(id));
          } catch {
            break;
          }
        }
        expect(await task.isFullySettled(id), "directed closing settles").to.be.true;
        tasks.push(id);
        okCommits++;
        okFinalizes++;
        swept++;
        await checkInvariants(fx, `seed=${seed} sweep/directed=${id}`);
      }
      expect(swept, "at least one task settled end to end").to.be.greaterThan(0);

      expect(tasks.length, "the fuzz created tasks").to.be.greaterThan(0);
      console.log(`seed=${seed} coverage:`,
        Object.keys(attempts).sort()
          .map((k) => `${k} ${successes[k] ?? 0}/${attempts[k]}${firstRevert[k] ? ` e.g. ${firstRevert[k]}` : ""}`)
          .join(" | "));
      console.log(`seed=${seed} revert tally:`, JSON.stringify(revertKinds));
      expect(okCommits, "some commits landed").to.be.greaterThan(0);
      expect(okFinalizes, "some epochs finalized").to.be.greaterThan(0);
      expect(await task.taskCount(), "no task vanished").to.equal(BigInt(tasks.length));
      await checkInvariants(fx, `seed=${seed} final`);
    });
  }
});
