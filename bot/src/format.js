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
export function renderPool(items, total, page = null) {
  if (!items.length) {
    return `${header("📋", "Task pool")}\n\nno tasks, or CipherTask is not configured.`;
  }

  const title =
    page && page.pages > 1
      ? `Task pool — page ${page.page}/${page.pages} (${total ?? items.length})`
      : `Task pool (${total ?? items.length})`;
  const lines = [header("📋", title), ""];
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
      const proof = c.proof ? `  ${mono(`proof ${shortHash(c.proof)}`)}` : "";
      lines.push(
        `  ${c.verified ? OK : WARN} ${mono(shortAddr(c.node))}  ${mono(shortHash(c.traceDigest))}${proof}`
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
    lines.push(`<b>Disputes</b>    ${mono(`${quorum.have}/${quorum.need}`)} recorded`);
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
    case "DisputeCommitted":
      return (
        `${WARN} <b>Dispute commitment posted</b>\n\n` +
        `task ${mono(shortId(a.taskId))} · epoch ${mono(a.epoch)}\n` +
        `reporter ${mono(shortAddr(a.reporter))}\n\n` +
        `A node committed to a dispute digest without revealing it yet (commit-reveal ` +
        `against mempool front-running). A commitment with no follow-up reveal is a stuck ` +
        `reporter — or someone testing the quorum.` +
        tail
      );
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
    case "NodeBondSlashed":
      return (
        `${BAD} <b>Bond slashed</b>\n\n` +
        `task ${mono(shortId(a.taskId))} — epoch ${mono(a.epoch)}\n` +
        `node ${mono(shortAddr(a.node))}\n` +
        `amount ${mono(a.amount.toString())}\n\n` +
        `The dispute quorum rejected this epoch and the winner's registration bond went to the ` +
        `buyer refund. Reporters keep theirs.` +
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

/**
 * The treasury rotation.
 *
 * The treasury is where slashed contribution bonds and every committee leg lands
 * (a slashed winner bond rejoins the task balance and refunds to the buyer), and
 * it moves through a seven-day window. The proposal is the moment an operator can
 * still do something about it, so it gets its own alert: by the time the change
 * is executed, the money is already pointed somewhere else.
 */
export function renderTreasury(kind, p) {
  if (kind === "proposed") {
    return (
      `${WARN} <b>Treasury change proposed</b>\n\n` +
        `The treasury receives slashed contribution bonds and every committee leg.\n\n` +
        `new treasury ${mono(shortAddr(p.to))}\n` +
        `executable at ${mono(p.eta)}\n\n` +
        `<b>It is not effective yet.</b> ` +
        `The change waits out its window before it can be executed, and it can still be ` +
        `cancelled until then. If you did not expect this, raise it in the channel that ` +
        `owns the deployment.`
    );
  }
  if (kind === "cancelled") {
    return (
      `${OK} <b>Treasury change cancelled</b>\n\n` +
        `The queued treasury change did not happen and the treasury is unchanged.\n\n` +
        `dropped candidate ${mono(shortAddr(p.dropped))}`
    );
  }
  return (
    `${WARN} <b>Treasury changed</b>\n\n` +
      `The treasury now receives slashed contribution bonds and every committee leg.\n\n` +
      `from ${mono(shortAddr(p.from))}\n` +
      `to ${mono(shortAddr(p.to))}\n\n` +
      `Check the new address against your own records: money that already went to the old ` +
      `treasury stays there, and the new one is where the next slashes and committee legs go.`
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
    `${mono("/pool [page]")}  recent tasks, 12 per page`,
    `${mono("/task <id>")}  one task, with that epoch's commits`,
    `${mono("/limits")}  what this deployment does not protect against`,
    `${mono("/help")}  this list`,
    "",
    "<b>Watch</b>",
    `${mono("/watch <id>")}  alert only on this task's disputes and mismatches`,
    `${mono("/unwatch <id>")}  stop watching a task`,
    `${mono("/watchlist")}  tasks this chat watches (empty means everything)`,
    `${mono("/alerts")}  per-chat alert flags; tap to toggle`,
    "",
    "<b>Alerts</b> (enable in .env)",
    `${mono("ALERT_COMMIT_MISMATCH")}  same node, same epoch, two digests`,
    `${mono("ALERT_DISPUTES")}  disputes, rejections and settlements`,
    `${mono("ALERT_KEY_ROTATION")}  any network key change`,
    "",
    "Buttons under every reply do the same as the commands — tap instead of typing.",
    "This bot is read-only. It holds no keys and cannot sign or send a transaction.",
  ].join("\n");
}

/**
 * The chat's watchlist. An empty list is the default "everything" filter, so
 * it is rendered as such rather than as "nothing watched" (which reads like
 * alerts are off when they are in fact at their widest).
 */
export function renderWatchlist(ids) {
  if (!ids.length) {
    return (
      `${header("👁", "Watchlist")}\n\n` +
      `watching <b>everything</b> — task-scoped alerts arrive for all tasks.\n\n` +
      `${mono("/watch <id>")} to narrow to specific tasks.`
    );
  }
  const lines = [header("👁", `Watchlist (${ids.length})`), ""];
  for (const id of ids) lines.push(`  ${mono(`#${id}`)}  ${mono(`/task ${id}`)}`);
  lines.push("");
  lines.push(`${mono("/unwatch <id>")} to drop one, or watch nothing new to keep this filter.`);
  return lines.join("\n");
}

/**
 * Per-chat alert flags. `effective` is already resolved against the global
 * config; `inherited` marks flags the chat never overrode, so "off because
 * the operator turned it off globally" does not look like "off because you
 * tapped it".
 */
export function renderAlerts(effective, inherited) {
  const row = (key, label) => {
    const on = effective[key];
    const src = inherited[key] ? "global" : "this chat";
    return `  ${on ? OK : BAD} ${label}  ${mono(src)}`;
  };
  return [
    header("🔔", "Alerts for this chat"),
    "",
    row("mm", "commit mismatch"),
    row("disp", "disputes"),
    row("rot", "key rotation"),
    "",
    "Tap a button to toggle. Unset flags follow the global .env.",
  ].join("\n");
}

export { htmlEscape, mono, shortHash };