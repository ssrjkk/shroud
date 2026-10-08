/**
 * Formatting.
 *
 * Telegram HTML mode accepts only a small tag set and silently renders anything
 * else as literal text. Every message is therefore assembled through these
 * helpers rather than by string interpolation at call sites: chain-derived
 * values (task ids, addresses, digests) are exactly the kind of input that would
 * break the markup, and a bot that leaks raw tags into a chat looks broken.
 *
 * Renderers take already-resolved plain values, never a chain handle. That keeps
 * them synchronous and directly testable — a formatter that could reach out to
 * the RPC is a formatter whose output cannot be asserted on.
 */

import { fmtEth, shortAddr, shortId, taskStatusName } from "./chain.js";

const htmlEscape = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const mono = (s) => `<code>${htmlEscape(s)}</code>`;

const OK = "✅";
const BAD = "❌";
const WARN = "⚠️";

const STATUS_TONE = {
  0: "·",
  1: "◔",
  2: "◕",
  3: "▣",
  4: "▶",
  5: "◈",
  6: "✓",
  7: "◔",
  8: "◑",
  9: "★",
  10: "✕",
  11: "⏸",
};

const header = (icon, text) => `${icon} <b>${htmlEscape(text)}</b>`;

/** Truncate a digest or hash for display without pretending it is the whole thing. */
const shortHash = (h) => (h ? `${String(h).slice(0, 14)}…` : "—");

export function renderStatus(view, config) {
  const lines = [header("🕶", "Shroud node status"), ""];

  lines.push(`<b>Chain</b>  ${mono(view.chainId)}`);
  lines.push(`<b>Head</b>  ${mono(view.blockNumber)}`);

  lines.push("");
  lines.push("<b>Network parameters</b>");
  if (!view.networkParams) {
    lines.push(
      "  " +
        (config.networkParams
          ? "could not be read from the RPC"
          : "not configured (NETWORK_PARAMS_ADDRESS)")
    );
  } else {
    const np = view.networkParams;
    lines.push(`  key version   ${mono(np.keyVersion)}`);
    lines.push(`  FHE key hash  ${mono(shortHash(np.fhePublicKeyHash))}`);
    lines.push(
      `  committee     ${mono(`${np.committeeThreshold} of ${np.committeeSize}`)} threshold`
    );
    lines.push(`  max proof     ${mono(np.maxProofBytes)} bytes`);
    lines.push(`  max features  ${mono(np.maxFeatures)}`);
  }

  lines.push("");
  lines.push("<b>Key rotation</b>");
  if (!view.pendingRotation) {
    lines.push("  none queued");
  } else {
    const p = view.pendingRotation;
    lines.push(`  ${WARN} <b>a rotation is pending</b>`);
    lines.push(`  proposed by   ${mono(shortAddr(p.proposer))}`);
    lines.push(`  expected hash ${mono(shortHash(p.expectedHash))}`);
    lines.push(`  executes from block/timestamp ${mono(p.scheduledAt)}`);
  }

  lines.push("");
  lines.push("<b>Contracts</b>");
  for (const [name, addr] of [
    ["CipherTask", config.cipherTask],
    ["PaymentVault", config.paymentVault],
    ["NetworkParams", config.networkParams],
  ]) {
    lines.push(`  ${addr ? mono(shortAddr(addr)) : "not configured"}  ${mono(name)}`);
  }

  lines.push("");
  lines.push(mono("not audited") + " — this deployment is not safe for real value. See /limits");
  return lines.join("\n");
}

/** `items` are task views, newest first, already resolved. */
export function renderPool(items, total) {
  if (!items.length) {
    return `${header("📋", "Task pool")}\n\nno tasks, or CipherTask is not configured.`;
  }

  const lines = [header("📋", `Task pool (${total ?? items.length})`), ""];
  for (const t of items) {
    if (!t) continue;
    const tone = STATUS_TONE[t.status] ?? "?";
    lines.push(
      `${tone} ${mono(shortId(t.taskId))}  ${htmlEscape(t.statusName)}  ` +
        `${mono(fmtEth(t.budget))}  ${mono(t.contributors)} contributors`
    );
  }
  if (total && total > items.length) {
    lines.push("");
    lines.push(mono(`… and ${total - items.length} earlier`));
  }
  lines.push("");
  lines.push(`${mono("/task <id>")} for detail.`);
  return lines.join("\n");
}

/**
 * `view` = { task, commits, winner, quorum }.
 *
 * The commit list is the point of this screen: if one epoch shows more than one
 * distinct digest, that is the condition a dispute exists for, so it is called
 * out rather than left for the reader to compare.
 */
export function renderTask(view, taskId) {
  const { task, commits = [], winner = null, quorum = null } = view;

  if (!task) {
    return (
      `${header("🔍", "Task")}\n\n` +
      `no task with id ${mono(taskId)} on this chain, or CipherTask is not configured.`
    );
  }

  const tone = STATUS_TONE[task.status] ?? "?";
  const lines = [header("🔍", `Task ${shortId(task.taskId)}`), ""];

  lines.push(`<b>Status</b>       ${tone} ${htmlEscape(task.statusName)}`);
  lines.push(`<b>Budget</b>       ${mono(fmtEth(task.budget))}`);
  lines.push(`<b>Locked</b>       ${mono(fmtEth(task.locked))}`);
  lines.push(`<b>Contributors</b> ${mono(task.contributors)}`);
  lines.push(`<b>Shards</b>       ${mono(task.shards)}`);
  lines.push(`<b>Next epoch</b>   ${mono(task.nextEpoch)}`);
  lines.push(`<b>ctRoot</b>       ${mono(task.ctRootSet ? shortId(task.ctRoot) : "not set")}`);

  if (task.params) {
    lines.push("");
    lines.push("<b>Params</b>");
    lines.push(
      `  epochs ${mono(task.params.epochs)} · labelBits ${mono(task.params.labelBits)} · ` +
        `features ${mono(task.params.features)}`
    );
    lines.push(
      `  contributionWindow ${mono(task.params.contributionWindow)}s · ` +
        `disputeWindow ${mono(task.params.disputeWindow)}s`
    );
  }

  lines.push("");
  lines.push(`<b>Commits for epoch ${task.nextEpoch}</b>`);
  if (!commits.length) {
    lines.push("  none yet");
  } else {
    for (const c of commits) {
      lines.push(
        `  ${c.verified ? OK : WARN} ${mono(shortAddr(c.node))}  ${mono(shortHash(c.traceDigest))}`
      );
    }
    const digests = new Set(commits.map((c) => c.traceDigest));
    if (digests.size > 1) {
      lines.push("");
      lines.push(
        `  ${BAD} <b>${digests.size} different digests for one epoch</b> — a dispute is justified.`
      );
    }
  }

  if (winner && winner !== "0x" + "0".repeat(40)) {
    lines.push("");
    lines.push(`<b>Winner</b>       ${mono(shortAddr(winner))}`);
  }
  if (quorum) {
    lines.push(`<b>Disputes</b>    ${mono(quorum)} on record`);
  }

  return lines.join("\n");
}

/** Two nodes, one epoch, two digests. The most useful signal in the system. */
export function renderCommitMismatch(m) {
  return [
    `${BAD} <b>Digest mismatch on epoch ${m.epoch}</b>`,
    "",
    `task ${mono(shortId(m.taskId))}`,
    "",
    `${mono(shortAddr(m.challenger))}  ${mono(shortHash(m.challengerDigest))}`,
    `previously                  ${mono(shortHash(m.previousDigest))}`,
    "",
    `Node ${mono(shortAddr(m.challenger))} committed twice for the same epoch with ` +
      `different digests. On chain that cannot happen — the contract rejects it — so either ` +
      `the executor is non-deterministic or this is a bug worth stopping the node for.`,
  ].join("\n");
}

export function renderDispute(ev) {
  const a = ev.args;
  const tail =
    `\n\n${mono(`block ${ev.blockNumber}`)} ${mono(`tx ${shortHash(ev.txHash)}`)}`;

  switch (ev.name) {
    case "DisputeReported":
      return (
        `${WARN} <b>Dispute reported</b>\n\n` +
        `task ${mono(shortId(a.taskId))} · epoch ${mono(a.epoch)}\n` +
        `reporter ${mono(shortAddr(a.reporter))}\n` +
        `digest   ${mono(shortHash(a.digest))}\n\n` +
        `A node re-executed this epoch and disagrees with the winner.` +
        tail
      );
    case "EpochVerified":
      return a.ok
        ? `${OK} <b>Epoch verified</b>\n\ntask ${mono(shortId(a.taskId))} · epoch ${mono(a.epoch)}\n` +
            `node ${mono(shortAddr(a.node))}${tail}`
        : `${BAD} <b>Epoch rejected</b>\n\ntask ${mono(shortId(a.taskId))} · epoch ${mono(a.epoch)}\n` +
            `node ${mono(shortAddr(a.node))}\n\n` +
            `The dispute quorum rejected this epoch. Nobody is paid for it.` +
            tail;
    case "TaskSettled":
      return (
        `${OK} <b>Task settled</b>\n\ntask ${mono(shortId(a.taskId))}\n\n` +
          `contributors ${mono(fmtEth(a.userPool))}\n` +
          `nodes        ${mono(fmtEth(a.nodePool))}\n` +
          `treasury     ${mono(fmtEth(a.treasury))}` +
          tail
      );
    case "TaskStatusChanged":
      return (
        `<b>Status changed</b>\n\ntask ${mono(shortId(a.taskId))}\n` +
          `${htmlEscape(taskStatusName(Number(a.from)))} → ${htmlEscape(taskStatusName(Number(a.to)))}` +
          tail
      );
    default:
      return null;
  }
}

export function renderRotation(kind, p) {
  if (kind === "proposed") {
    return (
      `${WARN} <b>FHE key rotation proposed</b>\n\n` +
        `A new network key is scheduled to become active.\n\n` +
        `proposed by ${mono(shortAddr(p.proposer))}\n` +
        `expected hash ${mono(shortHash(p.expectedHash))}\n` +
        `scheduled at ${mono(p.scheduledAt)}\n\n` +
        `<b>If you did not expect this, do not upload anything.</b> ` +
        `Clients still encrypting to the old key after this point are sending ciphertext that ` +
        `the chain no longer trusts, and participants cannot detect it at submission time. ` +
        `The on-chain history allows after-the-fact detection only.`
    );
  }
  return (
    `${WARN} <b>FHE key rotation executed</b>\n\n` +
      `key version ${mono(p.keyVersion)}\n` +
      `new FHE key hash ${mono(shortHash(p.fhePublicKeyHash))}\n\n` +
      `Every client pinning the previous hash now refuses to encrypt — that is intended. ` +
      `It is also exactly what a key-substitution attack looks like, so verify it through your ` +
      `own channel before trusting it.`
  );
}

export function renderLimits() {
  return [
    header(WARN, "Known limits — read before trusting this deployment"),
    "",
    "<b>Not enforced</b>",
    "  · the dispute quorum is <b>not</b> Sybil-resistant; three cheap addresses can deny a node its reward",
    "  · there is no slashable contribution bond; row farming is only sqrt(rows)-weighted",
    "  · the chain does <b>not</b> fully verify the STARK",
    "  · a substituted FHE public key is <b>not</b> detected by participants at submission time",
    "",
    "<b>By design</b>",
    "  · a majority of the decryption committee can decrypt user rows",
    "",
    "<b>Not externally audited.</b> Do not use real value.",
  ].join("\n");
}

export function renderHelp() {
  return [
    header("🕶", "Shroud ops bot"),
    "",
    "<b>Read</b>",
    `${mono("/status")}  chain, key pin, pending rotation`,
    `${mono("/pool")}  recent tasks`,
    `${mono("/task <id>")}  one task, with that epoch's commits`,
    `${mono("/limits")}  what this deployment does not protect against`,
    `${mono("/help")}  this list`,
    "",
    "<b>Alerts</b> (enable in .env)",
    `${mono("ALERT_COMMIT_MISMATCH")}  same node, same epoch, two digests`,
    `${mono("ALERT_DISPUTES")}  disputes, rejections and settlements`,
    `${mono("ALERT_KEY_ROTATION")}  any network key change`,
    "",
    "This bot is read-only. It holds no keys and cannot sign or send a transaction.",
  ].join("\n");
}

export { htmlEscape, mono, shortHash };