/**
 * Tests that need no bot token, no Telegram connection and no chain.
 *
 * The point is to cover the parts that are easy to get quietly wrong: HTML
 * escaping of chain-derived values, the "configured vs empty" distinction, and
 * the ABI assumptions. A formatter bug here would show up in a chat as broken
 * markup rather than as a failed build, so it is worth asserting directly.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { fmtEth, shortAddr, shortId, taskStatusName } from "../src/chain.js";
import {
  renderStatus,
  renderPool,
  renderTask,
  renderCommitMismatch,
  renderDispute,
  renderRotation,
  renderTreasury,
  renderVerifier,
  renderLimits,
  renderHelp,
  renderWatchlist,
  humanStatus,
  htmlEscape,
} from "../src/format.js";
import { createHandlers, mismatchArgs, replyText } from "../src/index.js";

const ZERO32 = "0x" + "0".repeat(64);
const ZERO20 = "0x" + "0".repeat(40);

const task = {
  taskId: "42",
  status: 5,
  statusName: "EpochCommitting",
  budget: 1_500_000_000_000_000_000n,
  locked: 250_000_000_000_000_000n,
  contributors: 3,
  shards: 7,
  nextEpoch: 2,
  ctRoot: ZERO32,
  ctRootSet: false,
  params: { epochs: 4, labelBits: 16, features: 512, contributionWindow: 60, disputeWindow: 30 },
};

test("fmtEth renders wei without losing the integer part", () => {
  assert.equal(fmtEth(0n), "0");
  assert.equal(fmtEth(1_000_000_000_000_000_000n), "1");
  assert.equal(fmtEth(1_500_000_000_000_000_000n), "1.5");
  assert.equal(fmtEth(1_234_500_000_000_000_000n), "1.2345");
  // Dust is honest about being dust instead of collapsing to the same "0"
  // as a true zero balance.
  assert.equal(fmtEth(1n), "<0.0001");
  assert.equal(fmtEth(1n, 4, 6), "<0.0001");
  assert.equal(fmtEth(1_000_000n, 4, 6), "1");
  // Negatives keep their sign; garbage scales fall back to 18.
  assert.equal(fmtEth(-5n), "-<0.0001");
  assert.equal(fmtEth(1_000_000_000_000_000_000n, 4, "abc"), "1");
  assert.equal(fmtEth(100n, 4, 300), "<0.0001");
});

test("shortId and shortAddr never return an empty string", () => {
  assert.equal(shortId(42n), "42");
  assert.ok(shortId(12345678901234567890n).includes("…"));
  assert.equal(shortAddr(null), "—");
  assert.ok(shortAddr("0x1234567890abcdef1234567890abcdef12345678").includes("…"));
  // Chain structs occasionally carry non-strings where an address belongs; like
  // shortId, shortAddr shows the value instead of aborting the whole reply.
  assert.equal(shortAddr(42), "42…42");
  assert.equal(shortAddr(undefined), "—");
});

test("humanStatus never markets Nothing as open, nor Revealing as paid", () => {
  // Status 0 means uninitialized: rendering it "open" would invite funding
  // a task that does not exist.
  assert.equal(humanStatus(0, "en"), "None");
  assert.equal(humanStatus(1, "en"), "open");
  assert.equal(humanStatus(4, "ru"), "идёт обучение");
  // Revealing (threshold decryption in flight) is not yet a payout.
  assert.equal(humanStatus(8, "en"), "revealing");
  assert.equal(humanStatus(8, "ru"), "раскрытие ключей");
  assert.equal(humanStatus(6, "en"), "paying out");
  assert.equal(humanStatus(99, "en"), "Unknown(99)");
});

test("taskStatusName mirrors the contract enum and admits unknowns", () => {
  assert.equal(taskStatusName(0), "None");
  assert.equal(taskStatusName(9), "Disclosed");
  assert.equal(taskStatusName(10), "Aborted");
  // An unrecognised discriminant must be visible, not silently mapped to None:
  // a bot that labels an unknown status "None" hides a contract change.
  assert.equal(taskStatusName(99), "Unknown(99)");
});

test("htmlEscape neutralises markup in chain-derived text", () => {
  assert.equal(htmlEscape("<script>"), "&lt;script&gt;");
  assert.equal(htmlEscape("a & b"), "a &amp; b");

  // Task ids and addresses come from the chain, so a render path that forgot to
  // escape would let on-chain data inject markup into the chat. The fixture
  // below smuggles a tag through the id to prove the escape actually runs.
  const hostile = { ...task, taskId: "<b>1</b>" };
  const rendered = renderTask({ task: hostile, commits: [], winner: null, quorum: null }, hostile.taskId);
  assert.ok(!rendered.includes("<b>1</b>"), "raw tag from input must not survive");
  assert.ok(rendered.includes("&lt;b&gt;1&lt;/b&gt;"), "input must appear escaped");
});

test("renderStatus distinguishes 'not configured' from 'unreadable' from 'read'", () => {
  const none = renderStatus(
    { chainId: 31337, blockNumber: 9, networkParams: null, pendingRotation: null },
    { cipherTask: null, paymentVault: null, networkParams: null }
  );
  assert.ok(none.includes("not configured (NETWORK_PARAMS_ADDRESS)"));
  assert.ok(none.includes("not configured"));
  assert.ok(none.includes("none queued"));

  const unreadable = renderStatus(
    { chainId: 1, blockNumber: 1, networkParams: null, pendingRotation: null },
    { cipherTask: "0xabc", paymentVault: "0xdef", networkParams: "0x123" }
  );
  assert.ok(unreadable.includes("could not be read from the RPC"));

  const good = renderStatus(
    {
      chainId: 31337,
      blockNumber: 12,
      networkParams: {
        chainId: 31337,
        keyVersion: 4,
        fhePublicKeyHash: ZERO32,
        committeeThreshold: 3,
        committeeSize: 7,
        maxProofBytes: 48576,
        maxCiphertextBytes: 1048576,
        maxFeatures: 512,
        activatedAt: 0,
        active: true,
      },
      pendingRotation: {
        scheduledAt: 1234,
        expectedHash: ZERO32,
        proposer: "0x1234567890abcdef1234567890abcdef12345678",
        approver: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
      },
    },
    { cipherTask: "0x1234567890abcdef1234567890abcdef12345678", paymentVault: null, networkParams: "0x123" }
  );
  assert.ok(good.includes("key version"));
  assert.ok(good.includes("a rotation is pending"));
  assert.ok(good.includes("approved by"));
  const awaiting = renderStatus(
    {
      chainId: 31337,
      blockNumber: 12,
      networkParams: {
        chainId: 31337,
        keyVersion: 4,
        fhePublicKeyHash: ZERO32,
        committeeThreshold: 3,
        committeeSize: 7,
        maxProofBytes: 48576,
        maxCiphertextBytes: 1048576,
        maxFeatures: 512,
        activatedAt: 0,
        active: true,
      },
      pendingRotation: {
        scheduledAt: 1234,
        expectedHash: ZERO32,
        proposer: "0x1234567890abcdef1234567890abcdef12345678",
        approver: "0x" + "0".repeat(40),
      },
    },
    { cipherTask: "0x1234567890abcdef1234567890abcdef12345678", paymentVault: null, networkParams: "0x123" }
  );
  assert.ok(awaiting.includes("awaiting approver"));
});

test("simple status never leaks a !missing-key! marker", () => {
  // The EN "status.simpleLine" key was once typed with a slash, so every
  // English simple-mode /status rendered a literal !status.simpleLine!.
  // RU worked, and the i18n parity test was blind to it (EN fallback).
  for (const lang of ["en", "ru"]) {
    for (const pending of [
      null,
      { scheduledAt: 1, expectedHash: ZERO32, proposer: ZERO20, approver: ZERO20 },
    ]) {
      const out = renderStatus(
        { chainId: 1, blockNumber: 2, networkParams: null, pendingRotation: pending },
        { cipherTask: null, paymentVault: null, networkParams: null },
        lang,
        "simple"
      );
      assert.ok(!out.includes("!"), `${lang} simple status leaks a key`);
    }
  }
});

test("renderTask flags two different digests in one epoch", () => {
  const same = renderTask(
    { task, commits: [{ node: "0x" + "1".repeat(40), traceDigest: ZERO32, verified: true }], winner: null, quorum: null },
    "42"
  );
  assert.ok(!same.includes("different digests"));

  const split = renderTask(
    {
      task,
      commits: [
        { node: "0x" + "1".repeat(40), traceDigest: ZERO32, verified: true },
        { node: "0x" + "2".repeat(40), traceDigest: "0x" + "9".repeat(64), verified: false },
      ],
      winner: null,
      quorum: null,
    },
    "42"
  );
  assert.ok(split.includes("2 different digests for one epoch"));
});

test("renderTask caps a long commit list instead of risking truncation", () => {
  const many = Array.from({ length: 10 }, (_, i) => ({
    node: "0x" + String(i + 1).repeat(40).slice(0, 40),
    traceDigest: ZERO32,
    verified: true,
  }));
  const out = renderTask({ task, commits: many, winner: null, quorum: null }, "42");
  assert.ok(out.includes("more commits"));
  assert.ok(out.length < 4096);
});

test("renderTask shows the proof reference when the reader provides it", () => {
  const proof = "0x53544152" + "ab".repeat(28);
  const withProof = renderTask(
    {
      task,
      commits: [{ node: "0x" + "1".repeat(40), traceDigest: ZERO32, verified: true, proof }],
      winner: null,
      quorum: null,
    },
    "42"
  );
  assert.ok(withProof.includes("proof"), "proof reference shown");
  assert.ok(withProof.includes("0x53544152"), "STAR magic visible at a glance");
  // Old fixtures without a proof render exactly as before: no dangling label.
  const without = renderTask(
    {
      task,
      commits: [{ node: "0x" + "1".repeat(40), traceDigest: ZERO32, verified: true }],
      winner: null,
      quorum: null,
    },
    "42"
  );
  assert.ok(!without.includes("proof"), "no proof label without a proof");
});

test("renderTask shows quorum progress as have over need", () => {
  const out = renderTask({ task, commits: [], winner: null, quorum: { need: 3, have: 1 } }, "42");
  assert.ok(out.includes("1/3"), "progress shown");
  assert.ok(!out.includes("NaN"), "never NaN");
});

test("money scales by escrow decimals, not a hardcoded 18", () => {
  // The devnet escrow token is 6-decimal USDC-style: 1_000_000_000 units is
  // 1000 tokens, but 18-decimal math renders it "0".
  const rich = { ...task, budget: 1_000_000_000n, locked: 250_000_000n };
  const out6 = renderTask({ task: rich, commits: [], winner: null, quorum: null }, "42", "en", "pro", 6);
  assert.ok(out6.includes("<code>1000</code>"), "budget at 6dp");
  assert.ok(out6.includes("<code>250</code>"), "locked at 6dp");
  const out18 = renderTask({ task: rich, commits: [], winner: null, quorum: null }, "42");
  assert.ok(out18.includes("0.0001"), "18dp default marks sub-wei dust instead of calling it 0");
  const pool6 = renderPool(
    [{ ...task, taskId: "9", budget: 2_000_000n, status: 2, statusName: "Collecting", contributors: 1 }],
    1, null, "en", "pro", 6
  );
  assert.ok(pool6.includes("<code>2</code>"), "pool budget at 6dp");
  const settled = renderDispute(
    { name: "TaskSettled", args: { taskId: 1n, userPool: 2_000_000n, nodePool: 1_000_000n, treasury: 500_000n }, blockNumber: 7, txHash: ZERO32 },
    "en", 6
  );
  assert.ok(settled.includes("<code>2</code>"), "contributors at 6dp");
  assert.ok(settled.includes("<code>0.5</code>"), "treasury at 6dp");
});

test("mismatchArgs carries the previous digest to the renderer", () => {
  const ev = {
    args: {
      taskId: 9n,
      epoch: 2,
      node: "0x" + "5".repeat(40),
      traceDigest: "0x" + "ab".repeat(32),
    },
  };
  const out = renderCommitMismatch(mismatchArgs(ev, "0x" + "cd".repeat(32)));
  assert.ok(out.includes("epoch 2"));
  assert.ok(!out.includes("previously —"), "previous digest present, not a dash");
});

test("pool handler reads newest-first and skips nothing", async () => {
  // The off-by-one this pins: ids start at 1, taskCount() is the newest id.
  const seen = [];
  const stub = {
    taskCount: async () => 3,
    task: async (id) => {
      seen.push(id);
      return { taskId: String(id), status: 2, statusName: "Collecting", budget: 1n, locked: 0n, contributors: 1, shards: 1, nextEpoch: 0, ctRoot: "0x", ctRootSet: false, params: null };
    },
  };
  const { pool } = createHandlers(stub, {});
  const out = replyText(await pool());
  assert.deepEqual(seen, [3n, 2n, 1n]);
  assert.ok(out.includes("Collecting"));
});

test("pool reads fan out instead of crawling the chain one RPC at a time", async () => {
  // /pool was 12 sequential round trips. The stub delays every read: sequential code
  // never overlaps two reads, concurrent code does. Order of results is newest-first
  // either way (Promise.all preserves input order).
  let inFlight = 0;
  let maxInFlight = 0;
  const stub = {
    taskCount: async () => 4,
    task: async (id) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return { taskId: String(id), status: 2, statusName: "Collecting", budget: 1n, locked: 0n, contributors: 1, shards: 1, nextEpoch: 0, ctRoot: "0x", ctRootSet: false, params: null };
    },
  };
  const { pool } = createHandlers(stub, {});
  const out = replyText(await pool());
  assert.ok(maxInFlight > 1, `pool reads serialized (max ${maxInFlight} in flight)`);
  assert.ok(out.includes("Collecting"));
});

test("task handler threads the running epoch through commits, winner and quorum", async () => {
  const calls = [];
  const fakeTask = { taskId: "7", status: 5, statusName: "EpochCommitting", budget: 1n, locked: 0n, contributors: 1, shards: 1, nextEpoch: 4, ctRoot: "0x", ctRootSet: false, params: null };
  const stub = {
    task: async (id) => {
      calls.push(["task", id]);
      return id === 7n ? fakeTask : null;
    },
    commitsForEpoch: async (id, epoch) => {
      calls.push(["commitsForEpoch", id, epoch]);
      return [];
    },
    epochWinner: async (id, epoch) => {
      calls.push(["epochWinner", id, epoch]);
      return null;
    },
    disputeQuorum: async (id) => {
      calls.push(["disputeQuorum", id]);
      return { need: 3, have: 0 };
    },
  };
  const { task } = createHandlers(stub, {});
  const out = replyText(await task(["7"]));
  assert.deepEqual(calls, [
    ["task", 7n],
    ["commitsForEpoch", 7n, 4],
    ["epochWinner", 7n, 4],
    ["disputeQuorum", 7n],
  ]);
  assert.ok(out.includes("0/3"), "quorum progress shown");
  assert.ok(replyText(await task([])).includes("usage"));
  assert.ok(replyText(await task(["abc"])).includes("decimal integers"));
  assert.ok(replyText(await task(["9".repeat(21)])).includes("decimal integers"), "kilobyte ids rejected pre-RPC");
});

test("status surfaces shed alerts, and stays silent when none were shed", async () => {
  const stub = {
    chainId: async () => 31337,
    blockNumber: async () => 100,
    networkParams: async () => null,
  };
  const { status } = createHandlers(stub, {});
  assert.ok(!replyText(await status()).includes("shed"), "no drops, no line");
  const withDrops = createHandlers(stub, {}, { droppedSends: () => 7 });
  const out = replyText(await withDrops.status());
  assert.ok(out.includes("7 alert(s) shed"), "operator learns about the loss");
});

test("status surfaces a failing chain read instead of showing an empty pool", async () => {
  // Same stub shape as above, plus a recorded read failure: the operator must see
  // "RPC dead", not a clean bill of health.
  const stub = {
    chainId: async () => 31337,
    blockNumber: async () => 100,
    networkParams: async () => null,
    lastReadError: () => "task: missing response for request",
  };
  const { status } = createHandlers(stub, {});
  const out = replyText(await status());
  assert.ok(out.includes("chain reads failing"), "outage is visible");
  assert.ok(out.includes("task: missing response"), "source is named");
});

test("status truncates a hostile read error before wrapping it in markup", async () => {
  // Proxies answer RPC failures with HTML bodies; embedding a 5KB body inside
  // <b> would push the message past 4096 and Telegram would 400 the whole
  // /status — exactly when the operator needs it most.
  const stub = {
    chainId: async () => 31337,
    blockNumber: async () => 100,
    networkParams: async () => null,
    lastReadError: () => "task: <html>" + "x".repeat(5000),
  };
  const { status } = createHandlers(stub, {});
  const out = replyText(await status());
  assert.ok(out.length < 4096, `status must always fit, got ${out.length}`);
  assert.ok(out.includes("…"), "truncation is marked");
});

test("renderWatchlist caps a full book instead of risking truncation", () => {
  const ids = Array.from({ length: 200 }, (_, i) => String(10 ** 19 + i));
  const out = renderWatchlist(ids, "en");
  assert.ok(out.length < 4096, `watchlist must always fit, got ${out.length}`);
  assert.ok(out.includes("Watchlist (200)"), "count survives the cap");
  assert.ok(out.includes("more"), "the cut is marked");
});

test("status warns when the send queue stalls instead of hiding the backlog", async () => {
  const stub = {
    chainId: async () => 31337,
    blockNumber: async () => 100,
    networkParams: async () => null,
  };
  const stalled = createHandlers(stub, {}, { queueDelayMs: () => 15_000 });
  const out = replyText(await stalled.status());
  assert.ok(out.includes("queued send waited 15s"), "stall is visible with its age");
  // Fast queue, no line.
  const { status } = createHandlers(stub, {}, { queueDelayMs: () => 0 });
  assert.ok(!replyText(await status()).includes("queued send"));
});

test("renderTask says 'no task' rather than rendering an empty task", () => {
  const out = renderTask({ task: null, commits: [], winner: null, quorum: null }, "999");
  assert.ok(out.includes("no task with id"));
  // The zero address must not be presented as a winner.
  const withZero = renderTask({ task, commits: [], winner: ZERO20, quorum: null }, "42");
  assert.ok(!withZero.includes("Winner"));
});

test("renderPool handles the empty pool and the truncated tail", () => {
  const empty = renderPool([], 0);
  assert.ok(empty.includes("no tasks"));

  const many = renderPool([task, task], 10);
  assert.ok(many.includes("and 8 earlier"));
});

test("renderPool distinguishes unreadable from empty", () => {
  // taskCount answered but every body read failed: must not render as "no tasks".
  const out = renderPool([null, null], 25, null, "en", "pro");
  assert.ok(!out.includes("no tasks"));
  assert.ok(out.includes("25"));
  assert.ok(out.includes("/status"));
});

test("commit mismatch alert names the epoch and both digests", () => {
  const out = renderCommitMismatch({
    taskId: "42",
    epoch: 3,
    challenger: "0x" + "2".repeat(40),
    challengerDigest: "0x" + "ab".repeat(32),
    previousDigest: "0x" + "cd".repeat(32),
  });
  assert.ok(out.includes("Digest mismatch on epoch 3"));
  assert.ok(out.includes("non-deterministic"));
});

test("renderDispute covers every event the bot subscribes to", () => {
  const cases = [
    ["DisputeReported", { taskId: 1n, epoch: 2n, reporter: ZERO20, digest: ZERO32 }, "Dispute reported"],
    ["EpochVerified", { taskId: 1n, epoch: 2n, node: ZERO20, ok: true }, "Epoch verified"],
    ["EpochVerified", { taskId: 1n, epoch: 2n, node: ZERO20, ok: false }, "Epoch rejected"],
    ["TaskSettled", { taskId: 1n, userPool: 1n, nodePool: 2n, treasury: 0n }, "Task settled"],
    ["TaskStatusChanged", { taskId: 1n, from: 3, to: 9 }, "Status changed"],
    ["NodeBondSlashed", { taskId: 1n, epoch: 2n, node: ZERO20, amount: 10000000n }, "Bond slashed"],
  ];
  for (const [name, args, expected] of cases) {
    const out = renderDispute({ name, args, blockNumber: 7, txHash: ZERO32 });
    assert.ok(out && out.includes(expected), `${name} must render "${expected}"`);
    assert.ok(out.includes("block 7"));
  }
  // An event nobody subscribed to must render as null rather than "undefined".
  assert.equal(renderDispute({ name: "SomethingElse", args: {}, blockNumber: 1, txHash: ZERO32 }), null);
});

test("rotation alerts warn in both directions", () => {
  const proposed = renderRotation("proposed", {
    proposer: ZERO20,
    expectedHash: ZERO32,
    scheduledAt: 99,
  });
  assert.ok(proposed.includes("do not upload anything"));
  const approved = renderRotation("approved", { approver: ZERO20, expectedHash: ZERO32 });
  assert.ok(approved.includes("timelock"));
  const cancelled = renderRotation("cancelled", { scheduledAt: 99 });
  assert.ok(cancelled.includes("never activate"));
  const executed = renderRotation("executed", { keyVersion: 5, fhePublicKeyHash: ZERO32 });
  assert.ok(executed.includes("key-substitution attack"));
});

test("verifier alerts warn in all directions", () => {
  const proposed = renderVerifier("proposed", { to: ZERO20, executableAt: 99 });
  assert.ok(proposed.includes("not effective yet"));
  assert.ok(proposed.includes("0x0000"));
  const cancelled = renderVerifier("cancelled", { dropped: ZERO20 });
  assert.ok(cancelled.includes("never activate"));
  const executed = renderVerifier("executed", { from: ZERO20, to: ZERO20 });
  assert.ok(executed.includes("permissive verifier pays fraudsters"));
});

test("renderStatus shows a queued verifier rotation only when configured", () => {
  const view = {
    chainId: 31337,
    blockNumber: 12,
    networkParams: null,
    pendingRotation: null,
    pendingVerifier: { to: ZERO20, executableAt: 99 },
  };
  const unconfigured = renderStatus(view, { cipherTask: null, paymentVault: null, networkParams: null }, "en", "pro");
  assert.ok(!unconfigured.includes("Verifier rotation"), "no verifier screen without VERIFIER_ADDRESS");
  const queued = renderStatus(
    view,
    { cipherTask: null, paymentVault: null, networkParams: null, verifier: "0x1234567890abcdef1234567890abcdef12345678" },
    "en",
    "pro"
  );
  assert.ok(queued.includes("Verifier rotation"));
  assert.ok(queued.includes("executable at"));
  assert.ok(queued.includes("ProofVerifier"));
});

test("treasury alerts say the window is still open, and where the money goes", () => {
  const proposed = renderTreasury("proposed", { to: ZERO20, eta: 1234 });
  // The proposal is the only moment somebody can still say no, so the text has to
  // say that the change is not effective yet.
  assert.ok(proposed.includes("not effective yet"));
  assert.ok(proposed.includes("0x0000"));

  const executed = renderTreasury("executed", { from: ZERO20, to: ZERO20 });
  assert.ok(executed.includes("slashed contribution bond"));
  assert.ok(executed.includes("Check the new address"));

  const cancelled = renderTreasury("cancelled", { dropped: ZERO20 });
  assert.ok(cancelled.includes("did not happen"));
});

test("limits and help state the honest limits, not marketing", () => {
  const limits = renderLimits();
  assert.ok(limits.includes("not</b> Sybil-resistant"));
  assert.ok(limits.includes("Not externally audited"));

  const help = renderHelp();
  assert.ok(help.includes("read-only"));
  assert.ok(help.includes("/limits"));
});