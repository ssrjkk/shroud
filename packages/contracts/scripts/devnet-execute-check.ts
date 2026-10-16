/**
 * Devnet execution e2e: two live Rust nodes independently execute one epoch and agree.
 *
 * The pre-existing `devnet-e2e-check` stops at seal + register with *fabricated* pins
 * (`bytes32Of(11)` is nobody's keccak of anything), so no node could ever execute that
 * task. This script builds a task a real node can actually run, then proves it does:
 *
 *   1. encrypt a real development shard (`NoopEncryptor`, `shroud/noop/v1`) and publish
 *      it straight into the nodes' shared DA directory (`NODE_CACHE_DIR`, which is the
 *      nodes' `[shard] cache_dir`) via `FileShardStore` — the file layout is identical,
 *      so what the SDK writes the node reads;
 *   2. publish a genesis seed-weights file (`shroud/weights/v1`, all zeros) the same way;
 *   3. create → contribute → seal a 1-epoch task pinning the *real* digests;
 *   4. wait until both node operators are registered, then `openEpoch` the seed weights;
 *   5. poll both nodes' `commits` until each holds a verified commit, and assert the two
 *      `traceDigest`s are equal and non-zero, the `proof`s carry the STAR magic, and the
 *      published weights CID is the one both nodes committed.
 *
 * Two independent binaries agreeing byte-for-byte is the determinism property the dispute
 * quorum needs — asserted on a live chain rather than in a unit test.
 *
 * Run after both nodes are up (CI starts them first):
 *
 *   NODE_CACHE_DIR=$RUNNER_TEMP/shroud-cache OPERATOR_B_KEY=0x… \
 *     npx hardhat run scripts/devnet-execute-check.ts --network localhost
 */
import { ethers, fhevm } from "hardhat";
import { readFileSync } from "fs";
import { join } from "path";
import { bytes32Of, externalUint64 } from "../test/helpers";

const OUT = join(__dirname, "../../../infra/devnet/addresses.json");
const CACHE_DIR = process.env.NODE_CACHE_DIR;
const OPERATOR_A_KEY =
  process.env.CM_OPERATOR_KEY ??
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const OPERATOR_B_KEY = process.env.OPERATOR_B_KEY;
if (!CACHE_DIR) throw new Error("NODE_CACHE_DIR is required (the nodes' shared [shard] cache_dir)");
if (!OPERATOR_B_KEY) throw new Error("OPERATOR_B_KEY is required (node B's operator key)");
// Narrowed copies: the guards above run at import time, which does not narrow inside main().
const cacheDir: string = CACHE_DIR;
const operatorBKey: string = OPERATOR_B_KEY;

const FEATURES = 2;
const ROWS = 8;
// x = 1..8, y = 2x: non-negative, finite, exactly representable — the engine's happy path.
const MATRIX = Array.from({ length: ROWS }, (_, i) => [i + 1, 2 * (i + 1)]).flat();

async function main() {
  // `hardhat test` initializes the fhevm mock in-process, but `hardhat run --network
  // localhost` does not: encrypted inputs need the CLI API pointed at the standalone
  // node first, otherwise `createEncryptedInput` throws "plugin is not initialized".
  await fhevm.initializeCLIApi();
  const addrs = JSON.parse(readFileSync(OUT, "utf8"));
  const [buyer, alice] = await ethers.getSigners();
  const provider = ethers.provider;
  const token = await ethers.getContractAt("TestToken", addrs.token);
  const task = await ethers.getContractAt("CipherTask", addrs.cipherTask);
  const vault = await ethers.getContractAt("PaymentVault", addrs.vault);

  // SDK dist is built before this script runs (CI builds packages/sdk first): one source
  // of truth for both envelope layouts, no byte-level duplication here.
  // @ts-ignore: cross-package `.js` import — contracts tsconfig uses moduleResolution
  // node, which takes `.js` literally and misses the adjacent `.d.ts`; node resolves it
  // fine at runtime.
  const sdk = await import("../../sdk/dist/index.js");
  // @ts-ignore: same as above.
  const weights = await import("../../sdk/dist/weights.js");
  // @ts-ignore: FileShardStore is node-only (node:fs), so it lives under the
  // `./file-store` subpath rather than the browser-safe index.
  const filestore = await import("../../sdk/dist/file-store.js");

  // --- 1-2. Seed the shared DA directory -------------------------------------------
  const store = new filestore.FileShardStore(cacheDir);
  const shard = await new sdk.NoopEncryptor().encryptRows(MATRIX, FEATURES);
  const putShard = await store.put(shard.ciphertext);
  const ctDigest = ethers.keccak256(shard.ciphertext);
  if (putShard.digest.toLowerCase() !== ctDigest.toLowerCase()) throw new Error("shard store digest drift");
  console.log(`shard: ${ROWS} rows x ${FEATURES} features, cid ${putShard.cid}`);

  const seedBytes = weights.encodeWeights(FEATURES, weights.zeroWeights(FEATURES));
  const putWeights = await store.put(seedBytes);
  const seedDigest = weights.weightsDigest(weights.zeroWeights(FEATURES));
  console.log(`seed weights: cid ${putWeights.cid} digest ${seedDigest}`);

  // --- Operators: fund B's gas FIRST (a fresh wallet cannot approve without it),
  // then top up A (one bond is already locked on task 1) and approve the vault ------
  const bond: bigint = await vault.REGISTRATION_BOND();
  const operatorA = new ethers.Wallet(OPERATOR_A_KEY, provider);
  const operatorB = new ethers.Wallet(operatorBKey, provider);
  const addrA = await operatorA.getAddress();
  const addrB = await operatorB.getAddress();
  console.log(`operator A ${addrA}, operator B ${addrB}, bond ${bond}`);

  if ((await provider.getBalance(addrB)) === 0n) {
    await (await buyer.sendTransaction({ to: addrB, value: ethers.parseEther("1") })).wait();
  }
  for (const [op, need] of [[operatorA, bond * 2n], [operatorB, bond]] as const) {
    const addr = await op.getAddress();
    if ((await token.balanceOf(addr)) < need) {
      await (await token.mint(addr, need - (await token.balanceOf(addr)))).wait();
    }
    if ((await token.allowance(addr, addrs.vault)) < need) {
      await (await token.connect(op).approve(addrs.vault, ethers.MaxUint256)).wait();
    }
  }

  // --- 3. Task with real pins ---------------------------------------------------------
  const escrow = 1_000_000_000n;
  await (await token.mint(buyer.address, escrow)).wait();
  await (await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256)).wait();
  await (
    await task.connect(buyer).createTask(escrow, {
      buyer: buyer.address,
      updateManager: ethers.ZeroAddress,
      epochs: 1,
      minContributors: 1,
      maxContributors: 10,
      minRowsPerShard: 2,
      features: FEATURES,
      labelBits: 8,
      contributionWindow: 86400,
      epochDuration: 900,
      disputeWindow: 120,
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
  const id: bigint = await task.taskCount();
  console.log("task", id.toString(), "created");

  await (
    await task.connect(alice).submitContribution(
      id,
      putShard.cid,
      ctDigest,
      "0x53544152" + "11".repeat(64),
      shard.rowCommitment,
      ROWS
    )
  ).wait();
  await (await task.connect(buyer).sealTask(id)).wait();
  console.log("sealed, ctRoot", await task.ctRootOf(id));

  // --- 4. Both nodes register (they do it themselves on the seal), then open --------
  await waitFor(
    "both operators registered",
    async () =>
      ((await task.nodeRegistered(id, addrA)) && (await task.nodeRegistered(id, addrB))
        ? true
        : null),
    180_000
  );
  console.log("both nodes registered");

  const taskAddr = await task.getAddress();
  const st = await externalUint64(taskAddr, buyer.address, 7n);
  await (await task.connect(buyer).openEpoch(id, putWeights.cid, seedDigest, st.handle, st.proof)).wait();
  console.log("epoch 0 opened");

  // --- 5. Both nodes commit the same verified digest ----------------------------------
  const done = await waitFor(
    "both nodes committed",
    async () => {
      const a = await task.commits(id, 0, addrA);
      const b = await task.commits(id, 0, addrB);
      return a.committedAt !== 0n && b.committedAt !== 0n ? { a, b } : null;
    },
    420_000
  );
  console.log("A trace", done.a.traceDigest, "verified", done.a.verified);
  console.log("B trace", done.b.traceDigest, "verified", done.b.verified);
  if (done.a.traceDigest === ethers.ZeroHash || done.b.traceDigest === ethers.ZeroHash) {
    throw new Error("a node committed an empty digest");
  }
  if (done.a.traceDigest !== done.b.traceDigest) {
    throw new Error(`nodes disagree: A=${done.a.traceDigest} B=${done.b.traceDigest}`);
  }
  if (!done.a.verified || !done.b.verified) throw new Error("a commit is not verified");
  for (const [who, c] of [["A", done.a], ["B", done.b]] as const) {
    if (!String(c.proof).startsWith("0x53544152")) throw new Error(`${who} proof lacks the STAR prefix`);
    if (String(c.encWeightsCid).toLowerCase() !== putWeights.cid.toLowerCase()) {
      throw new Error(`${who} committed weights ${c.encWeightsCid}, published ${putWeights.cid}`);
    }
    if (String(c.metricsCid) === ethers.ZeroHash) throw new Error(`${who} committed empty metrics`);
  }
  console.log("DEVNET EXECUTE E2E OK");
}

/** Poll `ready` until it returns non-null, logging heartbeats; throw on timeout. */
async function waitFor<T>(what: string, ready: () => Promise<T | null>, timeoutMs: number): Promise<T> {
  const start = Date.now();
  for (;;) {
    const got = await ready().catch((e) => {
      console.log(`poll (${what}): ${(e as Error).message.split("\n")[0]}`);
      return null;
    });
    if (got !== null) return got;
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting: ${what}`);
    await new Promise((r) => setTimeout(r, 5_000));
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
