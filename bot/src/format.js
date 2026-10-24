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
 *
 * Every renderer takes `(..., lang = "en", mode = "pro")`. The pro English
 * output keeps the historical phrases byte-identical (tests pin them), while
 * the layout around them is a clean card: header, thin divider, sections.
 * "simple" trims to plain words and key facts, "pro" is the geek version —
 * every digest, window and quorum count.
 */

import { fmtEth, shortAddr, shortId, taskStatusName } from "./chain.js";
import { t } from "./i18n.js";

const htmlEscape = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const mono = (s) => `<code>${htmlEscape(s)}</code>`;

const OK = "✅";
const BAD = "❌";
const WARN = "⚠️";
const DIV = "────────";

const STATUS_TONE = {
  0: "·",
  1: "◔",
  2: "◕",
  3: "▣",
  4: "▶",
  5: "◈",
  6: "✓",
  7: "◍",
  8: "◑",
  9: "★",
  10: "✕",
  11: "⏸",
};

const header = (icon, text) => `${icon} <b>${htmlEscape(text)}</b>`;

/** Truncate a digest or hash for display without pretending it is the whole thing. */
const shortHash = (h) => (h === null || h === undefined || h === "" ? "—" : `${String(h).slice(0, 14)}…`);

const isPro = (mode) => mode !== "simple";

/** Simple-mode one-liner appended everywhere: where to go next. */
const nextHint = (lang) => `\n\n${mono(t(lang, "common.nextHint"))}`;

/** Human status for simple mode: plain words instead of enum names. */
export function humanStatus(status, lang = "en") {
  const s = Number(status);
  // 0 (None) is not "open": it means uninitialized, and must never read as fundable.
  if (s === 0) return taskStatusName(0);
  if (s === 1) return t(lang, "task.humanOpen");
  if (s === 2 || s === 3) return t(lang, "task.humanCollecting");
  if (s === 4 || s === 5) return t(lang, "task.humanTraining");
  if (s === 6 || s === 7) return t(lang, "task.humanSettling");
  if (s === 8) return t(lang, "task.humanRevealing");
  if (s === 9) return t(lang, "task.humanDone");
  if (s === 10 || s === 11) return t(lang, "task.humanStopped");
  return taskStatusName(s);
}

export function renderStatus(view, config, lang = "en", mode = "pro") {
  const simple = !isPro(mode);
  const lines = [header("🕶", t(lang, "status.t")), DIV];
  if (simple) {
    lines.push(
      `${view.pendingRotation ? WARN + " " : OK + " "}` +
        t(lang, "status.simpleLine", { chain: view.chainId, head: view.blockNumber })
    );
    if (view.pendingRotation) lines.push("", WARN + " " + t(lang, "status.simpleRotation"));
    lines.push(DIV);
    lines.push(`${mono(t(lang, "status.audit"))} — ${t(lang, "status.auditWhy")}`);
    lines.push(nextHint(lang));
    return lines.join("\n");
  }

  lines.push(`⛓ <b>${t(lang, "status.chain")}</b>  ${mono(view.chainId)}`);
  lines.push(`📦 <b>${t(lang, "status.head")}</b>  ${mono(view.blockNumber)}`);
  lines.push(DIV);
  lines.push(`<b>${t(lang, "status.net")}</b>`);
  if (!view.networkParams) {
    lines.push(
      "  " +
        (config.networkParams
          ? t(lang, "status.netMissingRpc")
          : t(lang, "status.netMissingCfg"))
    );
  } else {
    const np = view.networkParams;
    lines.push(`  ${t(lang, "status.keyver")}   ${mono(np.keyVersion)}`);
    lines.push(`  ${t(lang, "status.keyhash")}  ${mono(shortHash(np.fhePublicKeyHash))}`);
    lines.push(
      `  ${t(lang, "status.committee")}     ${mono(`${np.committeeThreshold} of ${np.committeeSize}`)} ${t(lang, "status.threshold")}`
    );
    lines.push(`  ${t(lang, "status.maxproof")}     ${mono(np.maxProofBytes)} ${t(lang, "status.bytes")}`);
    lines.push(`  ${t(lang, "status.maxfeat")}  ${mono(np.maxFeatures)}`);
  }

  lines.push(DIV);
  lines.push(`<b>${t(lang, "status.rotation")}</b>`);
  if (!view.pendingRotation) {
    lines.push(`  ${t(lang, "status.rotationNone")}`);
  } else {
    const p = view.pendingRotation;
    lines.push(`  ${WARN} <b>${t(lang, "status.rotationPending")}</b>`);
    lines.push(`  ${t(lang, "status.proposedBy")}   ${mono(shortAddr(p.proposer))}`);
    lines.push(`  ${t(lang, "status.expectedHash")} ${mono(shortHash(p.expectedHash))}`);
    lines.push(`  ${t(lang, "status.execFrom")} ${mono(p.scheduledAt)}`);
    // Whether the queue can still be stopped: an approval means anyone may
    // execute after the timelock, so "pending" alone undersells the urgency.
    const zero = "0x" + "0".repeat(40);
    if (p.approver && String(p.approver).toLowerCase() !== zero) {
      lines.push(`  ${t(lang, "status.approvedBy")}   ${mono(shortAddr(p.approver))}`);
    } else {
      lines.push(`  ${t(lang, "status.awaitApproval")}`);
    }
  }

  // Verifier rotation state, when a verifier is configured at all. Same
  // question as the key pin above: is a new verifier queued, and from when
  // may anyone install it.
  if (config.verifier) {
    lines.push(DIV);
    lines.push(`<b>${t(lang, "status.verRotation")}</b>`);
    if (!view.pendingVerifier) {
      lines.push(`  ${t(lang, "status.rotationNone")}`);
    } else {
      const v = view.pendingVerifier;
      lines.push(`  ${WARN} <b>${t(lang, "status.rotationPending")}</b>`);
      lines.push(`  ${t(lang, "status.verTo")} ${mono(shortAddr(v.to))}`);
      lines.push(`  ${t(lang, "status.verExecutableAt")} ${mono(v.executableAt)}`);
    }
  }

  lines.push(DIV);
  lines.push(`<b>${t(lang, "status.contracts")}</b>`);
  for (const [name, addr] of [
    ["CipherTask", config.cipherTask],
    ["PaymentVault", config.paymentVault],
    ["NetworkParams", config.networkParams],
    ["ProofVerifier", config.verifier],
  ]) {
    lines.push(`  ${addr ? mono(shortAddr(addr)) : t(lang, "status.notConfigured")}  ${mono(name)}`);
  }

  lines.push(DIV);
  lines.push(
    `${mono(t(lang, "status.audit"))} — ${t(lang, "status.auditWhy")}`
  );
  lines.push(t(lang, "status.modeLine", { mode: t(lang, mode === "pro" ? "common.modePro" : "common.modeSimple"), lang }));
  return lines.join("\n");
}

/** `items` are task views, newest first, already resolved. */
export function renderPool(items, total, page = null, lang = "en", mode = "pro", tokenDecimals = 18) {
  const simple = !isPro(mode);
  if (!items.length) {
    return `${header("📋", t(lang, "pool.t"))}\n${DIV}\n\n${t(lang, "pool.empty")}`;
  }
  // taskCount answered but every body read failed (dead RPC, not an empty
  // pool): without this branch the screen renders a header with zero rows,
  // which reads as "no tasks". The per-read failures are already recorded
  // in the reader and surfaced by /status.
  if (total > 0 && !items.some((it) => it)) {
    return `${header("📋", t(lang, "pool.t"))}\n${DIV}\n\n${t(lang, "pool.unreadable", { total })}`;
  }

  const title =
    page && page.pages > 1
      ? t(lang, "pool.pageTitle", { page: page.page, pages: page.pages, total: total ?? items.length })
      : `${t(lang, "pool.t")} (${total ?? items.length})`;
  const lines = [header("📋", title), DIV, ""];
  if (simple) {
    for (const it of items) {
      if (!it) continue;
      const tone = STATUS_TONE[it.status] ?? "?";
      lines.push(`${tone} ${mono(shortId(it.taskId))}  ${htmlEscape(humanStatus(it.status, lang))}`);
    }
    lines.push("");
    lines.push(t(lang, "pool.simpleLine", { n: items.length }));
    lines.push(nextHint(lang));
    return lines.join("\n");
  }
  for (const it of items) {
    if (!it) continue;
    const tone = STATUS_TONE[it.status] ?? "?";
    lines.push(
      `${tone} ${mono(shortId(it.taskId))}  ${htmlEscape(it.statusName)}  ` +
        `${mono(fmtEth(it.budget, 4, tokenDecimals))}  ${mono(it.contributors)} contributors`
    );
  }
  if (total && total > items.length) {
    lines.push("");
    lines.push(mono(t(lang, "pool.more", { n: total - items.length })));
  }
  lines.push("");
  lines.push(t(lang, "pool.hint"));
  return lines.join("\n");
}

/**
 * `view` = { task, commits, winner, quorum }.
 *
 * The commit list is the point of this screen: if one epoch shows more than one
 * distinct digest, that is the condition a dispute exists for, and it is called
 * out rather than left for the reader to compare.
 */
export function renderTask(view, taskId, lang = "en", mode = "pro", tokenDecimals = 18) {
  const { task, commits = [], winner = null, quorum = null } = view;

  if (!task) {
    return (
      `${header("🔍", t(lang, "task.t"))}\n${DIV}\n\n` +
      t(lang, "task.missing", { id: mono(taskId) })
    );
  }

  if (!isPro(mode)) {
    const lines = [header("🔍", `${t(lang, "task.t")} ${shortId(task.taskId)}`), DIV, ""];
    lines.push(
      t(lang, "task.simpleStatus", {
        status: htmlEscape(humanStatus(task.status, lang)),
        budget: fmtEth(task.budget, 4, tokenDecimals),
        contributors: task.contributors,
        epoch: task.nextEpoch,
      })
    );
    lines.push("");
    lines.push(t(lang, "task.simpleSealed", { id: htmlEscape(String(task.taskId)), status: htmlEscape(humanStatus(task.status, lang)) }));
    const digests = new Set(commits.map((c) => c.traceDigest));
    if (digests.size > 1) {
      lines.push("");
      lines.push(
        `  ${BAD} <b>${t(lang, "task.diffDigests", { n: digests.size })}</b> — ${t(lang, "task.disputeWorth")}`
      );
    }
    lines.push(nextHint(lang));
    return lines.join("\n");
  }

  const tone = STATUS_TONE[task.status] ?? "?";
  const lines = [header("🔍", `${t(lang, "task.t")} ${shortId(task.taskId)}`), DIV, ""];

  lines.push(`<b>${t(lang, "task.status")}</b>       ${tone} ${htmlEscape(task.statusName)} · ${htmlEscape(humanStatus(task.status, lang))}`);
  lines.push(`<b>${t(lang, "task.budget")}</b>       ${mono(fmtEth(task.budget, 4, tokenDecimals))}`);
  lines.push(`<b>${t(lang, "task.locked")}</b>       ${mono(fmtEth(task.locked, 4, tokenDecimals))}`);
  lines.push(`<b>${t(lang, "task.contributors")}</b> ${mono(task.contributors)}`);
  lines.push(`<b>${t(lang, "task.shards")}</b>       ${mono(task.shards)}`);
  lines.push(`<b>${t(lang, "task.nextEpoch")}</b>   ${mono(task.nextEpoch)}`);
  lines.push(`<b>${t(lang, "task.ctRoot")}</b>       ${mono(task.ctRootSet ? shortHash(task.ctRoot) : t(lang, "task.ctRootUnset"))}`);

  if (task.params) {
    lines.push("");
    lines.push(`<b>${t(lang, "task.params")}</b>`);
    lines.push(
      `  epochs ${mono(task.params.epochs)} · labelBits ${mono(task.params.labelBits)} · ` +
        `features ${mono(task.params.features)}`
    );
    lines.push(
      `  ${t(lang, "task.window", { c: task.params.contributionWindow, d: task.params.disputeWindow })}`
    );
  }

  lines.push("");
  lines.push(DIV);
  lines.push(`<b>${t(lang, "task.commits", { epoch: task.nextEpoch })}</b>`);
  if (!commits.length) {
    lines.push(`  ${t(lang, "task.noneYet")}`);
  } else {
    // Bounded: a task with many contributors would otherwise blow past
    // Telegram's 4096 cap and get silently truncated mid-list. The digest
    // split below still considers every commit, only the listing is capped.
    const SHOWN = 8;
    for (const c of commits.slice(0, SHOWN)) {
      const proof = c.proof ? `  ${mono(`proof ${shortHash(c.proof)}`)}` : "";
      lines.push(
        `  ${c.verified ? OK : WARN} ${mono(shortAddr(c.node))}  ${mono(shortHash(c.traceDigest))}${proof}`
      );
    }
    if (commits.length > SHOWN) {
      lines.push(`  ${mono(t(lang, "task.moreCommits", { n: commits.length - SHOWN }))}`);
    }
    const digests = new Set(commits.map((c) => c.traceDigest));
    if (digests.size > 1) {
      lines.push("");
      lines.push(
        `  ${BAD} <b>${t(lang, "task.diffDigests", { n: digests.size })}</b> — ${t(lang, "task.disputeWorth")}`
      );
    }
  }

  if (winner && winner !== "0x" + "0".repeat(40)) {
    lines.push("");
    lines.push(`<b>${t(lang, "task.winner")}</b>       ${mono(shortAddr(winner))}`);
  }
  if (quorum) {
    lines.push(`<b>${t(lang, "task.disputes")}</b>    ${mono(`${quorum.have}/${quorum.need}`)} ${t(lang, "task.recorded")}`);
  }

  return lines.join("\n");
}

/** Two nodes, one epoch, two digests. The most useful signal in the system. */
export function renderCommitMismatch(m, lang = "en") {
  return [
    `${BAD} <b>${t(lang, "al.mismatchT", { epoch: m.epoch })}</b>`,
    DIV,
    "",
    `${t(lang, "al.task")} ${mono(shortId(m.taskId))}`,
    "",
    `${mono(shortAddr(m.challenger))}  ${mono(shortHash(m.challengerDigest))}`,
    `${t(lang, "al.mismatchPrev")}                  ${mono(shortHash(m.previousDigest))}`,
    "",
    t(lang, "al.mismatchB"),
  ].join("\n");
}

export function renderDispute(ev, lang = "en", tokenDecimals = 18) {
  const a = ev.args;
  const tail =
    `\n\n${mono(`${t(lang, "al.block")} ${ev.blockNumber}`)} ${mono(`${t(lang, "al.tx")} ${shortHash(ev.txHash)}`)}`;

  switch (ev.name) {
    case "DisputeCommitted":
      return (
        `${WARN} <b>${t(lang, "al.disputeCommitT")}</b>\n\n` +
        `${t(lang, "al.task")} ${mono(shortId(a.taskId))} · ${t(lang, "al.epoch")} ${mono(a.epoch)}\n` +
        `${t(lang, "al.reporter")} ${mono(shortAddr(a.reporter))}\n\n` +
        t(lang, "al.disputeCommitB") +
        tail
      );
    case "DisputeReported":
      return (
        `${WARN} <b>${t(lang, "al.disputeReportT")}</b>\n\n` +
        `${t(lang, "al.task")} ${mono(shortId(a.taskId))} · ${t(lang, "al.epoch")} ${mono(a.epoch)}\n` +
        `${t(lang, "al.reporter")} ${mono(shortAddr(a.reporter))}\n` +
        `${t(lang, "al.digest")}   ${mono(shortHash(a.digest))}\n\n` +
        t(lang, "al.disputeReportB") +
        tail
      );
    case "EpochVerified":
      return a.ok
        ? `${OK} <b>${t(lang, "al.epochVerifiedT")}</b>\n\n${t(lang, "al.task")} ${mono(shortId(a.taskId))} · ${t(lang, "al.epoch")} ${mono(a.epoch)}\n` +
            `${t(lang, "al.node")} ${mono(shortAddr(a.node))}${tail}`
        : `${BAD} <b>${t(lang, "al.epochRejectedT")}</b>\n\n${t(lang, "al.task")} ${mono(shortId(a.taskId))} · ${t(lang, "al.epoch")} ${mono(a.epoch)}\n` +
            `${t(lang, "al.node")} ${mono(shortAddr(a.node))}\n\n` +
            t(lang, "al.epochRejectedB") +
            tail;
    case "TaskSettled":
      return (
        `${OK} <b>${t(lang, "al.settledT")}</b>\n\n${t(lang, "al.task")} ${mono(shortId(a.taskId))}\n\n` +
        `${t(lang, "al.settledContrib")} ${mono(fmtEth(a.userPool, 4, tokenDecimals))}\n` +
        `${t(lang, "al.settledNodes")}    ${mono(fmtEth(a.nodePool, 4, tokenDecimals))}\n` +
        `${t(lang, "al.settledTreasury")}  ${mono(fmtEth(a.treasury, 4, tokenDecimals))}` +
        tail
      );
    case "TaskStatusChanged":
      return (
        `<b>${t(lang, "al.statusT")}</b>\n\n${t(lang, "al.task")} ${mono(shortId(a.taskId))}\n` +
        `${htmlEscape(taskStatusName(Number(a.from)))} → ${htmlEscape(taskStatusName(Number(a.to)))}` +
        tail
      );
    case "NodeBondSlashed":
      return (
        `${BAD} <b>${t(lang, "al.slashedT")}</b>\n\n` +
        `${t(lang, "al.task")} ${mono(shortId(a.taskId))} — ${t(lang, "al.epoch")} ${mono(a.epoch)}\n` +
        `${t(lang, "al.node")} ${mono(shortAddr(a.node))}\n` +
        `${t(lang, "al.amount")} ${mono(a.amount.toString())}\n\n` +
        t(lang, "al.slashedB") +
        tail
      );
    default:
      return null;
  }
}

export function renderRotation(kind, p, lang = "en") {
  if (kind === "proposed") {
    return (
      `${WARN} <b>${t(lang, "al.rotPropT")}</b>\n${DIV}\n\n` +
      `${t(lang, "al.rotPropB")}\n\n` +
      `${t(lang, "al.rotPropBy")} ${mono(shortAddr(p.proposer))}\n` +
      `${t(lang, "al.rotPropHash")} ${mono(shortHash(p.expectedHash))}\n` +
      `${t(lang, "al.rotPropAt")} ${mono(p.scheduledAt)}\n\n` +
      `<b>${t(lang, "al.rotPropWarn")}</b>`
    );
  }
  if (kind === "approved") {
    return (
      `${WARN} <b>${t(lang, "al.rotApproveT")}</b>\n${DIV}\n\n` +
      `${t(lang, "al.rotApproveB")}\n\n` +
      `${t(lang, "al.rotApproveBy")} ${mono(shortAddr(p.approver))}\n` +
      `${t(lang, "al.rotPropHash")} ${mono(shortHash(p.expectedHash))}\n\n` +
      `<b>${t(lang, "al.rotApproveWarn")}</b>`
    );
  }
  if (kind === "cancelled") {
    return (
      `${OK} <b>${t(lang, "al.rotCancelT")}</b>\n${DIV}\n\n` +
      `${t(lang, "al.rotCancelB")}\n\n` +
      `${t(lang, "al.rotPropAt")} ${mono(p.scheduledAt)}`
    );
  }
  return (
    `${WARN} <b>${t(lang, "al.rotExecT")}</b>\n${DIV}\n\n` +
    `${t(lang, "al.rotExecKey")} ${mono(p.keyVersion)}\n` +
    `${t(lang, "al.rotExecHash")} ${mono(shortHash(p.fhePublicKeyHash))}\n\n` +
    t(lang, "al.rotExecB")
  );
}

/**
 * The verifier rotation.
 *
 * The verifier gates every payout: a verifier that accepts anything pays
 * fraudsters. So the lifecycle mirrors the key rotation — propose (owner),
 * 7-day timelock, execute (anyone) or cancel (owner) — and the proposal is
 * again the only moment anyone can still say no.
 */
export function renderVerifier(kind, p, lang = "en") {
  if (kind === "proposed") {
    return (
      `${WARN} <b>${t(lang, "al.verPropT")}</b>\n${DIV}\n\n` +
      `${t(lang, "al.verPropB")}\n\n` +
      `${t(lang, "al.verPropNew")} ${mono(shortAddr(p.to))}\n` +
      `${t(lang, "al.verPropEta")} ${mono(p.executableAt)}\n\n` +
      `<b>${t(lang, "al.verPropWait")}</b>`
    );
  }
  if (kind === "cancelled") {
    return (
      `${OK} <b>${t(lang, "al.verCancelT")}</b>\n${DIV}\n\n` +
      `${t(lang, "al.verCancelB")}\n\n` +
      `${t(lang, "al.verCancelDrop")} ${mono(shortAddr(p.dropped))}`
    );
  }
  return (
    `${WARN} <b>${t(lang, "al.verExecT")}</b>\n${DIV}\n\n` +
    `${t(lang, "al.verExecB")}\n\n` +
    `${t(lang, "al.verExecFrom")} ${mono(shortAddr(p.from))}\n` +
    `${t(lang, "al.verExecTo")} ${mono(shortAddr(p.to))}\n\n` +
    t(lang, "al.verExecCheck")
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
export function renderTreasury(kind, p, lang = "en") {
  if (kind === "proposed") {
    return (
      `${WARN} <b>${t(lang, "al.trePropT")}</b>\n${DIV}\n\n` +
      `${t(lang, "al.trePropB")}\n\n` +
      `${t(lang, "al.trePropNew")} ${mono(shortAddr(p.to))}\n` +
      `${t(lang, "al.trePropEta")} ${mono(p.eta)}\n\n` +
      `<b>${t(lang, "al.trePropWait")}</b>`
    );
  }
  if (kind === "cancelled") {
    return (
      `${OK} <b>${t(lang, "al.treCancelT")}</b>\n${DIV}\n\n` +
      `${t(lang, "al.treCancelB")}\n\n` +
      `${t(lang, "al.treCancelDrop")} ${mono(shortAddr(p.dropped))}`
    );
  }
  return (
    `${WARN} <b>${t(lang, "al.treExecT")}</b>\n${DIV}\n\n` +
    `${t(lang, "al.treExecB")}\n\n` +
    `${t(lang, "al.treExecFrom")} ${mono(shortAddr(p.from))}\n` +
    `${t(lang, "al.treExecTo")} ${mono(shortAddr(p.to))}\n\n` +
    t(lang, "al.treExecCheck")
  );
}

export function renderLimits(lang = "en") {
  return [
    header(WARN, t(lang, "limits.t")),
    DIV,
    "",
    `<b>${t(lang, "limits.notenforced")}</b>`,
    `  · ${t(lang, "limits.l1")}`,
    `  · ${t(lang, "limits.l2")}`,
    `  · ${t(lang, "limits.l3")}`,
    `  · ${t(lang, "limits.l4")}`,
    "",
    `<b>${t(lang, "limits.bydesign")}</b>`,
    `  · ${t(lang, "limits.l5")}`,
    "",
    DIV,
    t(lang, "limits.foot"),
  ].join("\n");
}

export function renderHelp(lang = "en") {
  return [
    header("🕶", t(lang, "help.t")),
    DIV,
    "",
    t(lang, "help.read"),
    `${mono("/status")}  ${t(lang, "help.l1")}`,
    `${mono("/pool [page]")}  ${t(lang, "help.l2")}`,
    `${mono("/task <id>")}  ${t(lang, "help.l3")}`,
    `${mono("/menu")}  ${t(lang, "help.l6")}`,
    `${mono("/how")}  ${t(lang, "help.l7")}`,
    `${mono("/protocol")}  ${t(lang, "help.l8")}`,
    `${mono("/settings")}  ${t(lang, "help.l9")}`,
    `${mono("/limits")}  ${t(lang, "help.l4")}`,
    `${mono("/help")}  ${t(lang, "help.l5")}`,
    "",
    t(lang, "help.watch"),
    `${mono("/watch <id>")}  ${t(lang, "help.w1")}`,
    `${mono("/unwatch <id>")}  ${t(lang, "help.w2")}`,
    `${mono("/watchlist")}  ${t(lang, "help.w3")}`,
    `${mono("/alerts")}  ${t(lang, "help.w4")}`,
    "",
    t(lang, "help.alerts"),
    `${mono("ALERT_COMMIT_MISMATCH")}  ${t(lang, "help.a1")}`,
    `${mono("ALERT_DISPUTES")}  ${t(lang, "help.a2")}`,
    `${mono("ALERT_KEY_ROTATION")}  ${t(lang, "help.a3")}`,
    `${mono("ALERT_TREASURY")}  ${t(lang, "help.a4")}`,
    `${mono("ALERT_VERIFIER_ROTATION")}  ${t(lang, "help.a5")}`,
    "",
    t(lang, "help.mode"),
    `${mono("/start")}  ${t(lang, "help.start")}`,
    `${mono("/role")}  ${t(lang, "help.m4")}`,
    `${mono("/simple")}  ${t(lang, "help.m1")}`,
    `${mono("/pro")}  ${t(lang, "help.m2")}`,
    `${mono("/lang")}  ${t(lang, "help.m3")}`,
    "",
    t(lang, "help.short"),
    "",
    DIV,
    t(lang, "help.foot"),
    `<a href="https://ssrjkk.github.io/shroud/">ssrjkk.github.io/shroud</a> · ${mono("/menu")}`,
  ].join("\n");
}

/**
 * The chat's watchlist. An empty list is the default "everything" filter, so
 * it is rendered as such rather than as "nothing watched" (which reads like
 * alerts are off when they are in fact at their widest).
 */
export function renderWatchlist(ids, lang = "en") {
  if (!ids.length) {
    return (
      `${header("👁", t(lang, "watch.t"))}\n${DIV}\n\n` +
      `${t(lang, "watch.everything")}\n\n` +
      t(lang, "watch.narrow")
    );
  }
  const lines = [header("👁", `${t(lang, "watch.t")} (${ids.length})`), DIV, ""];
  // Bounded like the commit list: 200 long ids would blow past Telegram's
  // 4096 cap and get cut mid-tag (unparsable → the whole message is dropped).
  const SHOWN = 30;
  for (const id of ids.slice(0, SHOWN)) lines.push(`  ${mono(`#${id}`)}  ${mono(`/task ${id}`)}`);
  if (ids.length > SHOWN) lines.push(`  ${mono(t(lang, "watch.more", { n: ids.length - SHOWN }))}`);
  lines.push("");
  lines.push(t(lang, "watch.drop"));
  return lines.join("\n");
}

/**
 * Start / menu hub: what the bot is, where to go, who you are.
 * Mode-aware lead: simple gets plain words, geek gets the stack.
 */
export function renderStart(lang = "en", mode = "pro") {
  const geek = isPro(mode);
  return [
    header("🕶", t(lang, "menu.t")),
    DIV,
    "",
    geek ? t(lang, "menu.leadGeek") : t(lang, "menu.leadSimple"),
    "",
    `<b>${t(lang, "menu.read")}</b>`,
    `${mono("/status")} · ${mono("/pool")} · ${mono("/task <id>")}`,
    "",
    `<b>${t(lang, "menu.build")}</b>`,
    `${mono("/how")} · ${mono("/protocol")} · ${mono("/role")}`,
    "",
    `<b>${t(lang, "menu.trust")}</b>`,
    `${mono("/limits")} · ${mono("/alerts")} · ${mono("/settings")}`,
    "",
    DIV,
    `<b>${t(lang, "menu.you")}</b>`,
    t(lang, "start.roles"),
    "",
    mono(geek ? t(lang, "menu.modeGeek") : t(lang, "menu.modeSimple")),
    t(lang, "menu.hint"),
    `<a href="https://ssrjkk.github.io/shroud/">ssrjkk.github.io/shroud</a>`,
  ].join("\n");
}

/** Alias: /menu renders the same hub without touching prefs. */
export function renderMenu(lang = "en", mode = "pro") {
  return renderStart(lang, mode);
}

/** How it works: 7 steps, mode-aware detail. */
export function renderHow(lang = "en", mode = "pro") {
  const geek = isPro(mode);
  const d = (n) => t(lang, `how.s${n}d${geek ? "Geek" : "Simple"}`);
  const steps = [1, 2, 3, 4, 5, 6, 7]
    .map((n) => `<b>${n}. ${t(lang, `how.s${n}t`)}</b>\n${d(n)}`)
    .join("\n\n");
  return [
    header("✦", t(lang, "how.t")),
    DIV,
    "",
    geek ? t(lang, "how.leadGeek") : t(lang, "how.leadSimple"),
    "",
    steps,
    "",
    DIV,
    t(lang, "how.foot"),
  ].join("\n");
}

/** Geek spec: binding, compute, disputes, money, keys. Always technical. */
export function renderProtocol(lang = "en") {
  const blocks = [1, 2, 3, 4, 5, 6]
    .map((n) => `<b>${t(lang, `proto.b${n}t`)}</b>\n${t(lang, `proto.b${n}d`)}`)
    .join("\n\n");
  return [
    header("◈", t(lang, "proto.t")),
    DIV,
    "",
    t(lang, "proto.lead"),
    "",
    blocks,
    "",
    DIV,
    t(lang, "proto.foot"),
  ].join("\n");
}

/**
 * Per-chat alert flags. `effective` is already resolved against the global
 * config; `inherited` marks flags the chat never overrode, so "off because
 * the operator turned it off globally" does not look like "off because you
 * tapped it".
 */
export function renderAlerts(effective, inherited, lang = "en") {
  const row = (key, labelKey) => {
    const on = effective[key];
    const src = inherited[key] ? t(lang, "alerts.srcGlobal") : t(lang, "alerts.srcChat");
    return `  ${on ? OK : BAD} ${t(lang, labelKey)}  ${mono(src)}`;
  };
  return [
    header("🔔", t(lang, "alerts.t")),
    DIV,
    "",
    row("mm", "alerts.mm"),
    row("disp", "alerts.disp"),
    row("rot", "alerts.rot"),
    row("tre", "alerts.tre"),
    row("ver", "alerts.ver"),
    "",
    t(lang, "help.w4"),
  ].join("\n");
}

/** Combined settings: depth + language + alert flags. */
export function renderSettings(effective, inherited, lang = "en", mode = "pro") {
  const geek = isPro(mode);
  const row = (key, labelKey) => {
    const on = effective[key];
    const src = inherited[key] ? t(lang, "alerts.srcGlobal") : t(lang, "alerts.srcChat");
    return `  ${on ? OK : BAD} ${t(lang, labelKey)}  ${mono(src)}`;
  };
  return [
    header("⚙", t(lang, "settings.t")),
    DIV,
    "",
    `<b>${t(lang, "settings.depth")}</b> — ${mono(geek ? t(lang, "common.modePro") : t(lang, "common.modeSimple"))}`,
    geek ? t(lang, "settings.depthHintGeek") : t(lang, "settings.depthHintSimple"),
    "",
    `<b>RU / EN</b> — ${mono(lang)}`,
    t(lang, "settings.langHint"),
    "",
    `<b>${t(lang, "alerts.t")}</b>`,
    row("mm", "alerts.mm"),
    row("disp", "alerts.disp"),
    row("rot", "alerts.rot"),
    row("tre", "alerts.tre"),
    row("ver", "alerts.ver"),
    t(lang, "settings.alertsHint"),
    "",
    DIV,
    t(lang, "settings.foot"),
  ].join("\n");
}

/**
 * Render one collected alert for a chat, in that chat's language. Alerts are
 * collected language-neutral and rendered at delivery: the same on-chain event
 * reaches a RU chat in Russian and an EN chat in English. `alert` carries
 * `{ kind, payload }`; see the scanner in index.js for the shapes.
 */
export function renderAlert(alert, lang = "en", tokenDecimals = 18) {
  const p = alert.payload;
  switch (alert.kind) {
    case "mismatch":
      return renderCommitMismatch(p, lang);
    case "dispute":
      return renderDispute(p, lang, tokenDecimals);
    case "verifier":
      return renderVerifier(p.variant, p.args, lang);
    case "rotation":
      return renderRotation(p.variant, p.args, lang);
    case "treasury":
      return renderTreasury(p.variant, p.args, lang);
    default:
      return null;
  }
}

export { htmlEscape, mono, shortHash };
