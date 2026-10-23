/**
 * Human words of the bot, in Russian and English.
 *
 * Every user-visible string lives here — no hardcoded prose in formatters,
 * handlers or keyboards — so a missing translation fails loudly (`t` returns
 * the key wrapped, never undefined) and both languages stay complete by
 * construction. `bot/test/i18n.test.js` asserts RU/EN key parity.
 *
 * Placeholders use `{name}` and are filled from `vars`; values are NOT
 * escaped here — escaping stays at the call site that knows HTML context
 * (format.js), because this module must remain markup-agnostic.
 */

export const LANGS = ["ru", "en"];

export function isLang(v) {
  return v === "ru" || v === "en";
}

/** Telegram `language_code` ("ru-RU", "ru", "uk"…) → bot language. RU stays RU, everything else is EN. */
export function pickLang(code) {
  return typeof code === "string" && code.toLowerCase().startsWith("ru") ? "ru" : "en";
}

const EN = {
  // --- common -------------------------------------------------------------
  "common.usageTask": "usage: /task &lt;id&gt;",
  "common.usageWatch": "usage: /watch &lt;id&gt;",
  "common.usageUnwatch": "usage: /unwatch &lt;id&gt;",
  "common.unavailable": "unavailable in this context.",
  "common.failed": "could not complete /{name}: {err}",
  "common.failedNoName": "could not complete: {err}",
  "common.badId": "task ids are decimal integers. Try /pool.",
  "common.noWatch": "watchlist unavailable in this context.",
  "common.noAlerts": "per-chat alerts unavailable in this context.",
  "common.modeSimple": "simple",
  "common.modePro": "geek",
  "common.onState": "on",
  "common.offState": "off",
  "toast.watching": "watching #{id}",
  "toast.unwatched": "unwatched #{id}",
  "toast.stale": "that button is stale — send the command again",
  "toast.failed": "that failed — try again",
  "toast.oldBot": "that button is from an older bot — send the command again",
  "common.nextHint": "Send /pro for the full picture, /role to pick a guide.",

  // --- /start ---------------------------------------------------------------
  "start.roles": "buyer · contributor · node · watcher",

  // --- roles ------------------------------------------------------------------
  "role.pick": "Pick a guide:",
  "role.buyerB":
    "<b>Buyer — fund a private training task.</b>\n\n" +
    "You lock a budget in the escrow token (USDC-style, 6 decimals on devnet) and publish the model spec; nodes train over ciphertext, and the escrow streams out to contributors, nodes and the committee as epochs settle.\n\n" +
    "Here: /pool to browse tasks, /task &lt;id&gt; for epochs, commits and disputes.\n" +
    "Out there: <code>ShroudSdk.uploadAndMonetize</code> is the buyer-side call (see <code>packages/sdk</code>); <code>createTask</code> → <code>sealTask</code> → <code>openEpoch</code> per epoch.\n\n" +
    "Watch /limits before trusting real value: no external audit, quorum is 3 reporters, the STARK is sampled on-chain.",
  "role.contribB":
    "<b>Contributor — sell your data's value, not the data.</b>\n\n" +
    "Rows are encrypted on your own device (confidential path: browser FHEWasm or @shroud/sdk/relayer; SDK default NoopEncryptor is dev-only) and only ciphertext leaves it. One shard per address per task; the reward is your rows times liveness, paid out at settlement.\n\n" +
    "Here: /pool for open tasks, /task &lt;id&gt; for the spec and windows, /watch &lt;id&gt; to follow one.\n" +
    "Out there: <code>sdk.uploadAndMonetize(data, taskId, { features })</code> — it pre-checks everything the chain would revert on, so you never burn gas learning the rules.",
  "role.nodeB":
    "<b>Node operator — execute epochs, commit, dispute, get paid.</b>\n\n" +
    "Register once per task — bond 10 CMUSD (REGISTRATION_BOND, ~20% of a typical epoch lock) — then execute the FHE epoch, commit the trace digest, and watch the claim: if it disagrees with your re-execution, report it via commit-reveal (the bare path is a fallback, not the default).\n\n" +
    "Here: /status for chain, key pin and pending rotations; /task &lt;id&gt; for commits and digests per epoch; /alerts for mismatch and dispute pings.\n" +
    "Out there: the Rust node (<code>node/</code>) does watch → execute → commit → dispute → finalize → redeem/reclaim on its own. Never run it against a key rotation you did not verify.",
  "role.watchB":
    "<b>Watcher — alerts without running anything.</b>\n\n" +
    "No keys, no bond, no node. Subscribe and read: /watch &lt;id&gt; narrows task-scoped alerts to one task (empty watchlist means everything), /alerts toggles mismatch / disputes / rotations / treasury per chat.\n\n" +
    "The two alerts that matter most: a commit mismatch on an epoch (somebody's executor disagrees with the claim) and any rotation proposal (keys or treasury) — the proposal is the only moment anyone can still say no.",

  // --- /help ------------------------------------------------------------------
  "help.t": "Shroud ops bot",
  "help.m1": "plain words, key facts first (default for new chats)",
  "help.m2": "geek version: every digest, window and quorum count",
  "help.m3": "switch language — /lang ru|en, bare /lang shows current",
  "help.m4": "guided path for your side — buyer|contributor|node|watcher (contrib, watch work too)",
  "help.start": "hub + onboarding in your language, plain words first",
  "help.read": "<b>Read</b>",
  "help.watch": "<b>Watch</b>",
  "help.alerts": "<b>Alerts</b> (global flags in .env)",
  "help.mode": "<b>Depth</b>",
  "help.l1": "chain, key pin, pending rotation",
  "help.l2": "recent tasks, 12 per page — /pool 2 jumps to page 2",
  "help.l3": "one task, with that epoch's commits",
  "help.l4": "what this deployment does not protect against",
  "help.l5": "this list",
  "help.w1": "alert only on this task's disputes and mismatches",
  "help.w2": "stop watching a task",
  "help.w3": "tasks this chat watches (empty means everything)",
  "help.w4": "per-chat alert flags; tap to toggle",
  "help.a1": "same node, same epoch, two digests",
  "help.a2": "disputes, rejections and settlements",
  "help.a3": "any network key change",
  "help.a4": "any treasury rotation step",
  "help.a5": "any verifier rotation step",
  "help.short": "Shortcuts: RU aliases work (/статус), bare <code>12</code> opens task 12, <code>/proto</code> = <code>/protocol</code>.",
  "help.l6": "main menu with everything",
  "help.l7": "how the protocol works in 60 seconds",
  "help.l8": "geek spec: binding, disputes, money, keys",
  "help.l9": "language, depth and alert flags on one screen",
  "help.foot": "Buttons under every reply do the same as the commands — tap instead of typing. This bot is read-only. It holds no keys and cannot sign or send a transaction.",

  // --- /status ------------------------------------------------------------------
  "status.t": "Shroud node status",
  "status.chain": "Chain",
  "status.head": "Head",
  "status.net": "Network parameters",
  "status.netMissingCfg": "not configured (NETWORK_PARAMS_ADDRESS)",
  "status.netMissingRpc": "could not be read from the RPC",
  "status.keyver": "key version",
  "status.keyhash": "FHE key hash",
  "status.committee": "committee",
  "status.threshold": "threshold",
  "status.maxproof": "max proof",
  "status.maxfeat": "max features",
  "status.bytes": "bytes",
  "status.rotation": "Key rotation",
  "status.rotationNone": "none queued",
  "status.rotationPending": "a rotation is pending",
  "status.proposedBy": "proposed by",
  "status.approvedBy": "approved by",
  "status.awaitApproval": "awaiting approver signature — still stoppable",
  "status.expectedHash": "expected hash",
  "status.execFrom": "executes from block/timestamp",
  "status.verRotation": "Verifier rotation",
  "status.verTo": "new verifier",
  "status.verExecutableAt": "executable at",
  "status.contracts": "Contracts",
  "status.notConfigured": "not configured",
  "status.audit": "not audited",
  "status.auditWhy": "this deployment is not safe for real value. See /limits",
  "status.modeLine": "depth: {mode} · lang: {lang} — /pro, /simple, /lang",
  "status.errReads": "chain reads failing: {err}",
  "status.errSlow": "slowest queued send waited {s}s — Telegram is answering slowly and alerts are delayed behind it. Treat recent silence as backlog, not as calm.",
  "status.errDrop": "{n} alert(s) shed by the send queue — the bot dropped outbound messages faster than Telegram drained them. Treat recent silence as data loss, not as calm.",
  "status.simpleLine": "Everything looks normal: chain {chain}, head {head}, no rotation queued.",
  "status.simpleRotation": "Attention: a key rotation is pending — open /status in pro mode before you trust anything.",

  // --- /pool --------------------------------------------------------------------
  "pool.t": "Task pool",
  "pool.pageTitle": "Task pool — page {page}/{pages} ({total})",
  "pool.empty": "no tasks, or CipherTask is not configured. See /status to check which.",
  "pool.unreadable": "the chain reports {total} tasks but none of their bodies could be read — the RPC is likely failing, not the pool empty. See /status.",
  "pool.more": "… and {n} earlier",
  "pool.hint": "/task &lt;id&gt; for detail · /menu for hub.",
  "pool.simpleLine": "{n} tasks, newest first. Tap one for epochs and money.",

  // --- /task ----------------------------------------------------------------------
  "task.t": "Task",
  "task.missing": "no task with id {id} on this chain, or CipherTask is not configured.",
  "task.status": "Status",
  "task.budget": "Budget",
  "task.locked": "Locked",
  "task.contributors": "Contributors",
  "task.shards": "Shards",
  "task.nextEpoch": "Next epoch",
  "task.ctRoot": "ctRoot",
  "task.ctRootUnset": "not set",
  "task.params": "Params",
  "task.commits": "Commits for epoch {epoch}",
  "task.noneYet": "none yet",
  "task.moreCommits": "… and {n} more commits",
  "task.diffDigests": "{n} different digests for one epoch",
  "task.disputeWorth": "a dispute is justified.",
  "task.winner": "Winner",
  "task.disputes": "Disputes",
  "task.recorded": "recorded",
  "task.simpleStatus": "{status} · budget {budget} · {contributors} contributors · epoch {epoch}",
  "task.simpleSealed": "Task {id} is {status}. Next: watch epochs land, then settlement pays out.",
  "task.window": "contributionWindow {c}s · disputeWindow {d}s",

  // --- /limits ----------------------------------------------------------------------
  "limits.t": "Known limits — read before trusting this deployment",
  "limits.notenforced": "Not enforced",
  "limits.l1": "the dispute quorum is <b>not</b> Sybil-resistant: three bonded addresses can deny a node its reward — the bond prices the attack (locked till terminality) but does not prevent it",
  "limits.l2": "the contribution bond is opt-in and attested, not proven; row farming is only rows-weighted",
  "limits.l3": "the chain does <b>not</b> fully verify the STARK",
  "limits.l4": "a substituted FHE public key is <b>not</b> detected by participants at submission time",
  "limits.bydesign": "By design",
  "limits.l5": "a majority of the decryption committee can decrypt user rows",
  "limits.foot": "<b>Not externally audited.</b> Do not use real value.",

  // --- /alerts + watchlist ----------------------------------------------------------
  "alerts.t": "Alerts for this chat",
  "alerts.srcGlobal": "global",
  "alerts.srcChat": "this chat",
  "alerts.mm": "commit mismatch",
  "alerts.disp": "disputes",
  "alerts.rot": "rotation",
  "alerts.tre": "treasury",
  "alerts.ver": "verifier",
  "watch.t": "Watchlist",
  "watch.everything": "watching <b>everything</b> — task-scoped alerts arrive for all tasks.",
  "watch.narrow": "/watch &lt;id&gt; to narrow to specific tasks.",
  "watch.drop": "/unwatch &lt;id&gt; to drop one, or watch nothing new to keep this filter.",
  "watch.more": "… and {n} more",

  // --- pushed alerts ------------------------------------------------------------------
  "al.mismatchT": "Digest mismatch on epoch {epoch}",
  "al.mismatchPrev": "previously",
  "al.mismatchB": "Node {node} committed twice for the same epoch with different digests. On chain that cannot happen — the contract rejects it — so either the executor is non-deterministic or this is a bug worth stopping the node for.",
  "al.disputeCommitT": "Dispute commitment posted",
  "al.disputeCommitB": "A node committed to a dispute digest without revealing it yet (commit-reveal against mempool front-running). A commitment with no follow-up reveal is a stuck reporter — or someone testing the quorum. Watch /task: if no reveal lands, the quorum decides without them.",
  "al.disputeReportT": "Dispute reported",
  "al.disputeReportB": "A node re-executed this epoch and disagrees with the winner.",
  "al.epochVerifiedT": "Epoch verified",
  "al.epochRejectedT": "Epoch rejected",
  "al.epochRejectedB": "The dispute quorum rejected this epoch. The winner gets nothing — reporters split a re-execution bounty from the lock.",
  "al.settledT": "Task settled",
  "al.settledContrib": "contributors",
  "al.settledNodes": "nodes",
  "al.settledTreasury": "treasury",
  "al.statusT": "Status changed",
  "al.slashedT": "Bond slashed",
  "al.slashedB": "The dispute quorum rejected this epoch and the winner's registration bond went to the buyer refund. Reporters keep theirs.",
  "al.task": "task",
  "al.epoch": "epoch",
  "al.reporter": "reporter",
  "al.digest": "digest",
  "al.node": "node",
  "al.amount": "amount",
  "al.block": "block",
  "al.tx": "tx",
  "al.rotPropT": "FHE key rotation proposed",
  "al.rotPropB": "A new network key is scheduled to become active.",
  "al.rotPropBy": "proposed by",
  "al.rotPropHash": "expected hash",
  "al.rotPropAt": "scheduled at",
  "al.rotPropWarn": "If you did not expect this, do not upload anything. Clients still encrypting to the old key after this point are sending ciphertext that the chain no longer trusts, and participants cannot detect it at submission time. The on-chain history allows after-the-fact detection only.",
  "al.rotApproveT": "FHE key rotation approved",
  "al.rotApproveB": "The approver signed the queued key. After the timelock anyone can execute it.",
  "al.rotApproveBy": "approved by",
  "al.rotApproveWarn": "If you did not expect this, you are down to the timelock window — after that the key activates whether you object or not.",
  "al.rotCancelT": "FHE key rotation cancelled",
  "al.rotCancelB": "The queued key will never activate. Clients keep pinning the current hash.",
  "al.rotExecT": "FHE key rotation executed",
  "al.rotExecKey": "key version",
  "al.rotExecHash": "new FHE key hash",
  "al.rotExecB": "Every client pinning the previous hash now refuses to encrypt — that is intended. It is also exactly what a key-substitution attack looks like, so verify it through your own channel before trusting it.",
  "al.verPropT": "Verifier rotation proposed",
  "al.verPropB": "The contract that decides every payout is about to change.",
  "al.verPropNew": "new verifier",
  "al.verPropEta": "executable at",
  "al.verPropWait": "It is not effective yet. The change waits out its 7-day window and can still be cancelled until then. If you did not expect this, raise it in the channel that owns the deployment.",
  "al.verExecT": "Verifier rotated",
  "al.verExecB": "Payouts are now checked against a new verifier.",
  "al.verExecFrom": "from",
  "al.verExecTo": "to",
  "al.verExecCheck": "Check the new verifier against the audited implementation: a permissive verifier pays fraudsters and nothing on chain can tell.",
  "al.verCancelT": "Verifier rotation cancelled",
  "al.verCancelB": "The queued verifier will never activate.",
  "al.verCancelDrop": "dropped candidate",
  "al.trePropT": "Treasury change proposed",
  "al.trePropB": "The treasury receives slashed contribution bonds and every committee leg.",
  "al.trePropNew": "new treasury",
  "al.trePropEta": "executable at",
  "al.trePropWait": "It is not effective yet. The change waits out its window before it can be executed, and it can still be cancelled until then. If you did not expect this, raise it in the channel that owns the deployment.",
  "al.treExecT": "Treasury changed",
  "al.treExecB": "The treasury now receives slashed contribution bonds and every committee leg.",
  "al.treExecFrom": "from",
  "al.treExecTo": "to",
  "al.treExecCheck": "Check the new address against your own records: money that already went to the old treasury stays there, and the new one is where the next slashes and committee legs go.",
  "al.treCancelT": "Treasury change cancelled",
  "al.treCancelB": "The queued treasury change did not happen and the treasury is unchanged.",
  "al.treCancelDrop": "dropped candidate",

  // --- menu / hub ---------------------------------------------------------------
  "menu.t": "Shroud — menu",
  "menu.leadSimple": "I read the chain so you don't have to. Tasks, epochs, disputes, keys, treasury — in plain words.",
  "menu.leadGeek": "Read-only ops surface over CipherTask · PaymentVault · NetworkParams. eth_call + eth_getLogs, no keys, no signatures.",
  "menu.read": "Look",
  "menu.build": "Build",
  "menu.trust": "Trust",
  "menu.you": "Who are you here as?",
  "menu.hint": "Tap a button — or type /task 12 for any task card.",
  "menu.modeSimple": "now: simple · tap for geek detail",
  "menu.modeGeek": "now: geek · tap for plain words",

  // --- how it works -------------------------------------------------------------
  "how.t": "How Shroud works — 60 seconds",
  "how.leadSimple": "A buyer locks money, people bring encrypted data, nodes train without seeing it, the chain pays everyone.",
  "how.leadGeek": "Escrow → encrypted contributions → sealed ctRoot → per-epoch FHE execute → transcript-bound commit → dispute quorum → paged settle + threshold reveal.",
  "how.s1t": "Buyer locks a budget",
  "how.s1dSimple": "Money goes into an on-chain safe (escrow token) + a model spec. Nobody is paid yet.",
  "how.s1dGeek": "createTask(budget, params) escrows exactly the named amount in CipherTask. Spec CID + epochs, windows, pricePerRow.",
  "how.s2t": "People bring data, encrypted",
  "how.s2dSimple": "Rows are encrypted on your own device. Only ciphertext leaves it.",
  "how.s2dGeek": "Encrypt under s_pub (browser FHEWasm or @shroud/sdk/relayer; SDK default NoopEncryptor is dev-only, non-confidential). submitContribution{...} is a plain tx, one shard per address.",
  "how.s3t": "Dataset locks",
  "how.s3dSimple": "The set closes — a lock. After that the rules cannot change mid-game.",
  "how.s3dGeek": "sealTask pins ctRoot and closes the contribution window (it opened at createTask). Contributors/shards fixed.",
  "how.s4t": "Nodes train blind",
  "how.s4dSimple": "Compute nodes learn over ciphertexts. They never see your rows.",
  "how.s4dGeek": "openEpoch(taskId, ...) per epoch — buyer or updateManager only (owner cannot). Node: TFHE SIMD matmul + SGD, hash-chained trace.",
  "how.s5t": "Everyone leaves a fingerprint",
  "how.s5dSimple": "Each node publishes a digest of what it computed. Same input must mean same digest.",
  "how.s5dGeek": "commitEpoch{traceDigest, proofRef STAR*} — transcript keccak('SHROUD/PoC/v1', chainId, CipherTask, task, epoch, ctRoot, weights, trace, node). Sampled on-chain, full check off-chain.",
  "how.s6t": "Disagreement becomes a dispute",
  "how.s6dSimple": "Digests differ — someone re-executes and 3 reporters decide who is right. A rejected epoch pays its winner nothing; reporters earn a re-execution bounty.",
  "how.s6dGeek": "commitDispute → reportDisputeWithSalt (commit-reveal vs mempool front-run). Sortition-weighted set, flat quorum of 3, winner bond slashes to buyer refund.",
  "how.s7t": "Settlement streams the money",
  "how.s7dSimple": "Contributors, nodes, committee get paid from the safe. Change goes back to the buyer.",
  "how.s7dGeek": "settleFrom(cursor) pays 200 contributors per call, final page pays committee + refunds buyer. PaymentVault EIP-712 channels, ChannelsImmature gate.",
  "how.foot": "Full spec: /protocol. Honest limits: /limits.",

  // --- protocol (geek) ------------------------------------------------------------
  "proto.t": "Protocol spec — geek version",
  "proto.lead": "What is bound to what, who checks whom, where the money sits. Nothing here moves funds — the bot only reads.",
  "proto.b1t": "Binding",
  "proto.b1d": "Transcript keccak('SHROUD/PoC/v1', chainId, CipherTask, task, epoch, ctRoot, weights, trace, node). Commits compare only inside one (task, epoch); trace itself chains hyperparams + shard leaves to next weights.",
  "proto.b2t": "Compute",
  "proto.b2d": "reference-cpu deterministic engine (golden-tested); tfhe-rs behind prover feature. STARK proves shard order + linear map, not TFHE correctness — that comes from re-execution quorum.",
  "proto.b3t": "Disputes",
  "proto.b3d": "First dispute action fixes the seed (nodeSetHash + prevrandao). Only the drawn set reports, salt bound to reporter. 3 distinct digests reject the epoch; reporters keep theirs, winner bond → buyer refund.",
  "proto.b4t": "Money",
  "proto.b4d": "CipherTask escrow, PaymentVault streaming channels (EIP-712 slices). settleFrom paged by 200, committee + refund on the last page. Slashed contribution bonds → treasury.",
  "proto.b5t": "Keys & treasury",
  "proto.b5d": "NetworkParams pins s_pub hash (keccak of s_pub) + committee. Rotation: owner proposes (timelock >= 7 days) + approver signs, anyone executes after; only owner cancels. Treasury: owner proposes/cancels, anyone executes after 7 days. Verifier: same window, no approver — anyone executes, only owner cancels.",
  "proto.b6t": "What is NOT proven",
  "proto.b6d": "No Sybil-resistant quorum (flat 3), no full on-chain STARK, committee majority can decrypt rows, no external audit. See /limits before trusting value.",
  "proto.foot": "Code: packages/contracts · packages/sdk · node/. Numbers: /status. Tasks: /pool.",

  // --- settings -------------------------------------------------------------------
  "settings.t": "Settings",
  "settings.depth": "Depth",
  "settings.depthHintSimple": "Plain words, key facts first. For ML/web3 detail tap geek.",
  "settings.depthHintGeek": "Every digest, window and quorum count. For plain words tap simple.",
  "settings.langHint": "Language of every screen and alert.",
  "settings.alertsHint": "Per-chat flags. Global rotation alerts ignore the watchlist.",
  "settings.foot": "Watchlist: /watchlist. All commands: /help.",

  // --- task human states ------------------------------------------------------------
  "task.humanCollecting": "collecting data",
  "task.humanTraining": "training",
  "task.humanSettling": "paying out",
  "task.humanRevealing": "revealing",
  "task.humanDone": "done",
  "task.humanStopped": "stopped",
  "task.humanOpen": "open",

  // --- buttons ----------------------------------------------------------------------
  "btn.refresh": "⟳ refresh",
  "btn.pool": "pool",
  "btn.prev": "‹ prev",
  "btn.next": "next ›",
  "btn.watch": "☆ watch",
  "btn.unwatch": "★ unwatch",
  "btn.status": "status",
  "btn.viewTask": "view task #{id}",
  "btn.viewStatus": "view status",
  "btn.modeSimple": "mode: simple",
  "btn.modePro": "mode: geek",
  "btn.roleBuyer": "Buyer",
  "btn.roleContrib": "Contributor",
  "btn.roleNode": "Node",
  "btn.roleWatcher": "Watcher",
  "btn.menu": "⌂ menu",
  "btn.how": "✦ how it works",
  "btn.proto": "◈ protocol",
  "btn.settings": "⚙ settings",
  "btn.limits": "🛡 limits",
  "btn.statusLong": "📊 status",
  "btn.poolLong": "📋 tasks",
  "btn.alertsLong": "🔔 alerts",
  // --- simple role guides (mode=simple) ---
  "role.buyerS": "<b>Buyer — 3 steps.</b>\n\n1. Pick a task in /pool — budget and status are in plain words.\n2. Fund it on-chain (the SDK does it: <code>createTask</code> → <code>sealTask</code>), then open every epoch (<code>openEpoch</code>) — no epoch runs without your transaction.\n3. Watch epochs in /task and get the change back at settlement.\n\nGeek detail: /pro, then re-open this guide.",
  "role.contribS": "<b>Contributor — 3 steps.</b>\n\n1. Pick an open task in /pool.\n2. Encrypt rows on your device (the app does it) — only ciphertext leaves.\n3. Get paid at settlement: your rows × liveness.\n\nOne address = one shard per task. Geek detail: /pro.",
  "role.nodeS": "<b>Node operator — 3 steps.</b>\n\n1. Check /status — chain, key pin, no pending rotation you did not expect.\n2. Register once per task, then the software executes + commits each epoch.\n3. Watch /alerts: a digest mismatch means stop and investigate.\n\nNever run under a rotation you did not verify. Geek detail: /pro.",
  "role.watchS": "<b>Watcher — 2 steps.</b>\n\n1. /watch &lt;id&gt; narrows alerts to one task. Empty list = everything.\n2. /alerts toggles mismatch / disputes / rotations / treasury.\n\nThe two that matter most: a digest mismatch and any rotation proposal.",
};

const RU = {
  // --- common -----------------------------------------------------------------
  "common.usageTask": "формат: /task &lt;id&gt;",
  "common.usageWatch": "формат: /watch &lt;id&gt;",
  "common.usageUnwatch": "формат: /unwatch &lt;id&gt;",
  "common.unavailable": "недоступно в этом контексте.",
  "common.failed": "не вышло выполнить /{name}: {err}",
  "common.failedNoName": "не вышло выполнить: {err}",
  "common.badId": "id тасков — только цифры. Попробуй /pool.",
  "common.noWatch": "вотчлист недоступен в этом контексте.",
  "common.noAlerts": "флаги алертов недоступны в этом контексте.",
  "common.modeSimple": "просто",
  "common.modePro": "гик",
  "common.onState": "вкл",
  "common.offState": "выкл",
  "toast.watching": "слежу за #{id}",
  "toast.unwatched": "больше не слежу за #{id}",
  "toast.stale": "кнопка устарела — отправь команду заново",
  "toast.failed": "не вышло — попробуй ещё раз",
  "toast.oldBot": "кнопка от старого бота — отправь команду заново",
  "common.nextHint": "Отправь /pro для полной картины, /role — выбрать гайд.",

  // --- /start -------------------------------------------------------------------
  "start.roles": "покупатель · контрибьютор · узел · наблюдатель",

  // --- roles --------------------------------------------------------------------
  "role.pick": "Выбери гайд:",
  "role.buyerB":
    "<b>Покупатель — закажи приватное обучение.</b>\n\n" +
    "Кладёшь бюджет в эскроу-токен (USDC-подобный, 6 знаков на девнете) и публикуешь спек модели; узлы учатся по шифротекстам, а эскроу по мере эпох растекается контрибьюторам, узлам и комитету.\n\n" +
    "Здесь: /pool — смотреть таски, /task &lt;id&gt; — эпохи, коммиты и споры.\n" +
    "Там: <code>ShroudSdk.uploadAndMonetize</code> — покупательский вызов (см. <code>packages/sdk</code>); <code>createTask</code> → <code>sealTask</code> → <code>openEpoch</code> на каждую эпоху.\n\n" +
    "Сначала /limits: аудита нет, кворум — 3 репортера, STARK на цепи проверен частично.",
  "role.contribB":
    "<b>Контрибьютор — продай ценность данных, не данные.</b>\n\n" +
    "Строки шифруются у тебя на устройстве (конфиденциально: FHEWasm в браузере или @shroud/sdk/relayer; дефолтный NoopEncryptor в SDK — dev-only) и наружу уходит только шифротекст. Один шард на адрес на таск; награда — твои строки, умноженные на живость, выплачивается при расчёте.\n\n" +
    "Здесь: /pool — открытые таски, /task &lt;id&gt; — спек и окна, /watch &lt;id&gt; — следить за одним.\n" +
    "Там: <code>sdk.uploadAndMonetize(data, taskId, { features })</code> — сам всё проверит до траты газа, чтобы цепь не завернула транзакцию.",
  "role.nodeB":
    "<b>Оператор узла — исполняй эпохи, коммить, оспаривай, забирай.</b>\n\n" +
    "Одна регистрация на таск — бонд 10 CMUSD (REGISTRATION_BOND, ~20% типичного лока эпохи) — дальше исполняешь FHE-эпоху, коммитишь дайджест трейса, следишь за клеймом: не сошёлся с твоим пересчётом — репортишь через commit-reveal (голый репорт — только фолбэк).\n\n" +
    "Здесь: /status — цепь, пин ключа и висящие ротации; /task &lt;id&gt; — коммиты и дайджесты по эпохам; /alerts — пинги про расхождения и споры.\n" +
    "Там: Rust-узел (<code>node/</code>) сам делает watch → execute → commit → dispute → finalize → redeem/reclaim. Не гоняй его под ротацию ключа, которую не проверил.",
  "role.watchB":
    "<b>Наблюдатель — алерты без запуска чего-либо.</b>\n\n" +
    "Ни ключей, ни бонда, ни узла. Подписался и читаешь: /watch &lt;id&gt; сужает алерты до одного таска (пустой вотчлист — значит все), /alerts переключает расхождение коммита / споры / ротации / казну под этот чат.\n\n" +
    "Два самых важных алерта: расхождение коммита на эпохе (чей-то исполнитель не согласен с клеймом) и любое предложение ротации (ключей или казны) — предложение единственный момент, когда ещё можно сказать «нет».",

  // --- /help ----------------------------------------------------------------------
  "help.t": "Shroud ops bot",
  "help.m1": "простыми словами, главное сначала (по умолчанию для новых чатов)",
  "help.m2": "версия для гиков: каждый дайджест, окно и счёт кворума",
  "help.m3": "переключить язык — /lang ru|en, голый /lang покажет текущий",
  "help.m4": "гайд под твою сторону — buyer|contributor|node|watcher (contrib и watch тоже работают)",
  "help.start": "хаб + онбординг на твоём языке, сначала простыми словами",
  "help.read": "<b>Читать</b>",
  "help.watch": "<b>Следить</b>",
  "help.alerts": "<b>Алерты</b> (включаются в .env)",
  "help.mode": "<b>Глубина</b>",
  "help.l1": "цепь, пин ключа, висящая ротация",
  "help.l2": "свежие таски, 12 на страницу",
  "help.l3": "один таск и коммиты его эпохи",
  "help.l4": "чем этот деплой тебя НЕ защищает",
  "help.l5": "этот список",
  "help.w1": "алерты только по спорам и расхождениям этого таска",
  "help.w2": "перестать следить за таском",
  "help.w3": "за чем следит этот чат (пусто — значит за всем)",
  "help.w4": "флаги алертов чата; тап — переключить",
  "help.a1": "один узел, одна эпоха, два дайджеста",
  "help.a2": "споры, отклонения и расчёты",
  "help.a3": "любое изменение сетевого ключа",
  "help.a4": "любой шаг ротации казны",
  "help.a5": "любой шаг ротации верифаера",
  "help.short": "Шорткаты: работают RU-алиасы (/статус), голое <code>12</code> открывает таск 12, <code>/proto</code> = <code>/protocol</code>.",
  "help.l6": "главное меню со всем",
  "help.l7": "как работает протокол, за 60 секунд",
  "help.l8": "спека для гиков: привязка, споры, деньги, ключи",
  "help.l9": "язык, глубина и флаги алертов на одном экране",
  "help.foot": "Кнопки под каждым ответом делают то же, что команды, — жми вместо набора. Бот только читает. Ключей у него нет, подписать или отправить транзакцию он не может.",

  // --- /status ----------------------------------------------------------------------
  "status.t": "Shroud: статус узла",
  "status.chain": "Цепь",
  "status.head": "Голова",
  "status.net": "Параметры сети",
  "status.netMissingCfg": "не задано (NETWORK_PARAMS_ADDRESS)",
  "status.netMissingRpc": "не прочиталось из RPC",
  "status.keyver": "версия ключа",
  "status.keyhash": "хеш FHE-ключа",
  "status.committee": "комитет",
  "status.threshold": "порог",
  "status.maxproof": "макс. пруф",
  "status.maxfeat": "макс. фичей",
  "status.bytes": "байт",
  "status.rotation": "Ротация ключей",
  "status.rotationNone": "в очереди пусто",
  "status.rotationPending": "ротация висит",
  "status.proposedBy": "предложил",
  "status.approvedBy": "одобрил",
  "status.awaitApproval": "ждёт подписи аппрувера — ещё остановимо",
  "status.expectedHash": "ожидаемый хеш",
  "status.execFrom": "вступит с блока/времени",
  "status.verRotation": "Ротация верифаера",
  "status.verTo": "новый верифаер",
  "status.verExecutableAt": "исполнимо с",
  "status.contracts": "Контракты",
  "status.notConfigured": "не задано",
  "status.audit": "не аудировано",
  "status.auditWhy": "этот деплой небезопасен для реальных денег. См. /limits",
  "status.modeLine": "глубина: {mode} · язык: {lang} — /pro, /simple, /lang",
  "status.errReads": "запросы к цепи сыплются: {err}",
  "status.errSlow": "самый медленный ответ в очереди ждал {s}с — Telegram отвечает медленно, и алерты опаздывают. Молчание сейчас — это лаг, а не тишина.",
  "status.errDrop": "очередь выкинула {n} алерт(ов) — бот слал быстрее, чем Telegram разбирал. Молчание сейчас — это потерянные данные, а не тишина.",
  "status.simpleLine": "Всё спокойно: цепь {chain}, голова {head}, ротаций в очереди нет.",
  "status.simpleRotation": "Внимание: висит ротация ключа — открой /status в pro-режиме, прежде чем чему-то верить.",

  // --- /pool --------------------------------------------------------------------------
  "pool.t": "Пул тасков",
  "pool.pageTitle": "Пул тасков — стр. {page}/{pages} ({total})",
  "pool.empty": "тасков нет, или CipherTask не задан. См. /status — там видно что именно.",
  "pool.unreadable": "цепь сообщает о {total} тасках, но ни одно тело не прочиталось — скорее сыплется RPC, а не пул пуст. См. /status.",
  "pool.more": "… и ещё {n} раньше",
  "pool.hint": "/task &lt;id&gt; — детали · /menu — хаб.",
  "pool.simpleLine": "{n} тасков, сначала новые. Ткни в номер — там эпохи и деньги.",

  // --- /task ----------------------------------------------------------------------------
  "task.t": "Таск",
  "task.missing": "таска {id} на этой цепи нет, или CipherTask не задан.",
  "task.status": "Статус",
  "task.budget": "Бюджет",
  "task.locked": "Заблокировано",
  "task.contributors": "Контрибьюторы",
  "task.shards": "Шарды",
  "task.nextEpoch": "След. эпоха",
  "task.ctRoot": "ctRoot",
  "task.ctRootUnset": "не задан",
  "task.params": "Параметры",
  "task.commits": "Коммиты эпохи {epoch}",
  "task.noneYet": "пока нет",
  "task.moreCommits": "… и ещё {n}",
  "task.diffDigests": "{n} разных дайджеста на одну эпоху",
  "task.disputeWorth": "спор оправдан.",
  "task.winner": "Победитель",
  "task.disputes": "Споры",
  "task.recorded": "записано",
  "task.simpleStatus": "{status} · бюджет {budget} · контрибьюторов: {contributors} · эпоха {epoch}",
  "task.simpleSealed": "Таск {id}: {status}. Дальше — жди эпохи, потом расчёт выплатит всем.",
  "task.window": "окно взносов {c}с · окно споров {d}с",

  // --- /limits ----------------------------------------------------------------------------
  "limits.t": "Известные ограничения — прочитай, прежде чем доверять деньги",
  "limits.notenforced": "Не обеспечивается",
  "limits.l1": "кворум споров <b>не</b> Sybil-устойчив: три бондовых адреса могут лишить узел награды — бонд лишь удорожает атаку (возвращается после завершения), а не исключает её",
  "limits.l2": "бонд взносов opt-in и аттестован, а не доказан; фарм строк взвешен только строками",
  "limits.l3": "цепь <b>не</b> проверяет STARK полностью",
  "limits.l4": "подменённый FHE-ключ <b>не</b> палится участниками в момент сабмита",
  "limits.bydesign": "Так задумано",
  "limits.l5": "большинство комитета расшифровки может читать строки юзеров",
  "limits.foot": "<b>Внешнего аудита не было.</b> Реальные деньги — нельзя.",

  // --- /alerts + watchlist ------------------------------------------------------------------
  "alerts.t": "Алерты этого чата",
  "alerts.srcGlobal": "глобально",
  "alerts.srcChat": "этот чат",
  "alerts.mm": "расхождение коммита",
  "alerts.disp": "споры",
  "alerts.rot": "ротация",
  "alerts.tre": "казна",
  "alerts.ver": "верифаер",
  "watch.t": "Вотчлист",
  "watch.everything": "слежу за <b>всем</b> — алерты по таскам приходят по всем таскам.",
  "watch.narrow": "/watch &lt;id&gt; — сузить до конкретных тасков.",
  "watch.drop": "/unwatch &lt;id&gt; — убрать один, или ничего нового не вочь — фильтр останется.",
  "watch.more": "… и ещё {n}",

  // --- pushed alerts --------------------------------------------------------------------------
  "al.mismatchT": "Расхождение дайджестов, эпоха {epoch}",
  "al.mismatchPrev": "предыдущий",
  "al.mismatchB": "Узел {node} закоммитил дважды на одну эпоху с разными дайджестами. На цепи так нельзя — контракт такое режектит, — значит исполнитель недетерминирован или это баг, ради которого стоит остановить ноду.",
  "al.disputeCommitT": "Опубликован коммит спора",
  "al.disputeCommitB": "Узел закоммитил дайджест спора, пока не раскрывая его (commit-reveal против фронтранна из мемпула). Коммит без последующего раскрытия — зависший репортер или кто-то щупает кворум. Следи за /task: если раскрытия не будет, кворум решит без них.",
  "al.disputeReportT": "Засчитан репорт спора",
  "al.disputeReportB": "Узел переисполнил эту эпоху и не согласен с победителем.",
  "al.epochVerifiedT": "Эпоха проверена",
  "al.epochRejectedT": "Эпоха отклонена",
  "al.epochRejectedB": "Кворум споров отклонил эту эпоху. Победитель не получает ничего — репортеры делят баунти за переисполнение из лока.",
  "al.settledT": "Таск рассчитан",
  "al.settledContrib": "контрибьюторы",
  "al.settledNodes": "узлы",
  "al.settledTreasury": "казна",
  "al.statusT": "Статус сменился",
  "al.slashedT": "Бонд срезан",
  "al.slashedB": "Кворум споров отклонил эту эпоху, и регистрационный бонд победителя ушёл в возврат покупателю. Репортеры свои оставляют.",
  "al.task": "таск",
  "al.epoch": "эпоха",
  "al.reporter": "репортер",
  "al.digest": "дайджест",
  "al.node": "узел",
  "al.amount": "сумма",
  "al.block": "блок",
  "al.tx": "транзакция",
  "al.rotPropT": "Предложена ротация FHE-ключа",
  "al.rotPropB": "Новый сетевой ключ скоро станет активным.",
  "al.rotPropBy": "предложил",
  "al.rotPropHash": "ожидаемый хеш",
  "al.rotPropAt": "запланировано на",
  "al.rotPropWarn": "Если ты этого не ждал — ничего не загружай. Клиенты, шифрующие под старый ключ после этого момента, шлют шифротекст, которому цепь больше не доверяет, а участники не палят это в момент сабмита. Ончейн-история позволяет только задним числом разобраться.",
  "al.rotApproveT": "Ротация FHE-ключа одобрена",
  "al.rotApproveB": "Аппрувер подписал ключ в очереди. После таймлока его сможет исполнить кто угодно.",
  "al.rotApproveBy": "одобрил",
  "al.rotApproveWarn": "Если ты этого не ждал — осталось только окно таймлока: после него ключ активируется, возражай или нет.",
  "al.rotCancelT": "Ротация FHE-ключа отменена",
  "al.rotCancelB": "Ключ из очереди никогда не активируется. Клиенты продолжают пинить текущий хеш.",
  "al.rotExecT": "Ротация FHE-ключа выполнена",
  "al.rotExecKey": "версия ключа",
  "al.rotExecHash": "хеш нового FHE-ключа",
  "al.rotExecB": "Каждый клиент с пином на старый хеш теперь отказывается шифровать — так и должно быть. Но ровно так же выглядит подмена ключа, так что сверься по своему каналу, прежде чем верить.",
  "al.verPropT": "Предложена ротация верифаера",
  "al.verPropB": "Контракт, решающий все выплаты, скоро сменится.",
  "al.verPropNew": "новый верифаер",
  "al.verPropEta": "исполнимо с",
  "al.verPropWait": "Пока не вступило. Изменение отлёживается 7-дневное окно и до тех пор может быть отменено. Если не ждал — подними вопрос в канале, который владеет деплоем.",
  "al.verExecT": "Верифаер сменён",
  "al.verExecB": "Выплаты теперь проверяются новым верифаером.",
  "al.verExecFrom": "было",
  "al.verExecTo": "стало",
  "al.verExecCheck": "Сверь новый верифаер с аудированной реализацией: всеядный верифаер платит мошенникам, и цепь этого не палит.",
  "al.verCancelT": "Ротация верифаера отменена",
  "al.verCancelB": "Верифаер из очереди никогда не активируется.",
  "al.verCancelDrop": "снятый кандидат",
  "al.trePropT": "Предложена смена казны",
  "al.trePropB": "Казна получает срезанные бонды контрибьюторов и каждый комитети-лег.",
  "al.trePropNew": "новая казна",
  "al.trePropEta": "исполнимо с",
  "al.trePropWait": "Пока не вступило. Изменение отлёживается окно и до тех пор может быть отменено. Если не ждал — подними вопрос в канале, который владеет деплоем.",
  "al.treExecT": "Казна сменена",
  "al.treExecB": "Казна теперь получает срезанные бонды контрибьюторов и каждый комитети-лег.",
  "al.treExecFrom": "было",
  "al.treExecTo": "стало",
  "al.treExecCheck": "Сверь новый адрес со своими записями: что уже ушло в старую казну — там и осталось, а следующие слэши и комитети-леги пойдут в новую.",
  "al.treCancelT": "Смена казны отменена",
  "al.treCancelB": "Запланированная смена казны не случилась, казна прежняя.",
  "al.treCancelDrop": "снятый кандидат",

  // --- menu / hub -----------------------------------------------------------------
  "menu.t": "Shroud — меню",
  "menu.leadSimple": "Читаю цепь за тебя. Задачи, эпохи, споры, ключи, казна — простыми словами.",
  "menu.leadGeek": "Read-only доступ к CipherTask · PaymentVault · NetworkParams. Только eth_call и eth_getLogs, без ключей и подписей.",
  "menu.read": "Смотреть",
  "menu.build": "Собрать",
  "menu.trust": "Доверие",
  "menu.you": "Ты здесь как кто?",
  "menu.hint": "Жми кнопку — или набери /task 12 для карточки любого таска.",
  "menu.modeSimple": "сейчас: просто · жми для гик-деталей",
  "menu.modeGeek": "сейчас: гик · жми для простых слов",

  // --- how it works -----------------------------------------------------------------
  "how.t": "Как работает Shroud — за 60 секунд",
  "how.leadSimple": "Покупатель запирает деньги, люди приносят зашифрованные данные, узлы учат не видя их, цепь платит всем.",
  "how.leadGeek": "Escrow → зашифрованные взносы → закрытый ctRoot → FHE-исполнение по эпохам → transcript-bound коммит → кворум споров → постраничный расчёт + пороговая расшифровка.",
  "how.s1t": "Покупатель запирает бюджет",
  "how.s1dSimple": "Деньги уходят в сейф на цепи (эскроу-токен) + спек модели. Пока никто не платит.",
  "how.s1dGeek": "createTask(budget, params) — ровно названная сумма в CipherTask. CID спека + эпохи, окна, pricePerRow.",
  "how.s2t": "Люди приносят данные, зашифрованными",
  "how.s2dSimple": "Строки шифруются у тебя на устройстве. Наружу уходит только шифротекст.",
  "how.s2dGeek": "Шифруй под s_pub (FHEWasm в браузере или @shroud/sdk/relayer; дефолтный NoopEncryptor в SDK — dev-only, без конфиденциальности). submitContribution{...} — обычная транзакция, один шард на адрес.",
  "how.s3t": "Набор закрывается",
  "how.s3dSimple": "Набор закрыт — замок. Дальше правила уже не поменять посреди игры.",
  "how.s3dGeek": "sealTask фиксирует ctRoot и закрывает окно взносов (открылось при createTask). Контрибьюторы/шарды зафиксированы.",
  "how.s4t": "Узлы учат вслепую",
  "how.s4dSimple": "Узлы считают обучение по шифротекстам. Твои строки они не видят.",
  "how.s4dGeek": "openEpoch(taskId, ...) на каждую эпоху — только покупатель или updateManager (owner не может). Узел: TFHE SIMD matmul + SGD, hash-chain трейс.",
  "how.s5t": "Все оставляют отпечаток",
  "how.s5dSimple": "Каждый публикует дайджест того, что посчитал. Один вход — один отпечаток.",
  "how.s5dGeek": "commitEpoch{traceDigest, proofRef STAR*} — транскрипт keccak('SHROUD/PoC/v1', chainId, CipherTask, task, epoch, ctRoot, веса, трейс, узел). На цепи — сэмпл, полная проверка — off-chain.",
  "how.s6t": "Расхождение — это спор",
  "how.s6dSimple": "Дайджесты не сошлись — кто-то пересчитывает, и 3 репортера решают, кто прав. За отклонённую эпоху победителю не платят ничего; репортеры получают баунти за переисполнение.",
  "how.s6dGeek": "commitDispute → reportDisputeWithSalt (commit-reveal против фронтранна). Sortition-взвешенный сет, плоский кворум 3, бонд победителя → возврат покупателю.",
  "how.s7t": "Расчёт раздаёт деньги",
  "how.s7dSimple": "Контрибьюторы, узлы, комитет получают из сейфа. Сдача — назад покупателю.",
  "how.s7dGeek": "settleFrom(cursor) платит по 200 контрибьюторов за вызов, последний — комитету + возврат. Каналы PaymentVault EIP-712, гейт ChannelsImmature.",
  "how.foot": "Полная спека: /protocol. Честные ограничения: /limits.",

  // --- protocol (geek) ----------------------------------------------------------------
  "proto.t": "Спека протокола — версия для гиков",
  "proto.lead": "Что к чему привязано, кто кого проверяет, где лежат деньги. Бот только читает — двигать средства он не умеет.",
  "proto.b1t": "Привязка",
  "proto.b1d": "Транскрипт keccak('SHROUD/PoC/v1', chainId, CipherTask, task, epoch, ctRoot, веса, трейс, узел). Коммиты сравнимы только внутри одного (task, epoch); сам трейс связывает гиперпараметры + листья шардов со следующими весами.",
  "proto.b2t": "Вычисления",
  "proto.b2d": "reference-cpu — детерминированный движок (golden-тесты); tfhe-rs за фичей prover. STARK доказывает порядок шардов + линейное отображение, а не корректность TFHE — она держится на кворуме переисполнения.",
  "proto.b3t": "Споры",
  "proto.b3d": "Первое действие спора фиксирует сид (nodeSetHash + prevrandao). Дальше репортят только вытянутые, соль привязана к репортеру. 3 разных дайджеста отклоняют эпоху; репортеры своё сохраняют, бонд победителя → возврат покупателю.",
  "proto.b4t": "Деньги",
  "proto.b4d": "Эскроу CipherTask, стриминговые каналы PaymentVault (слайсы EIP-712). settleFrom — страницами по 200, комитет + возврат на последней. Срезанные бонды → казна.",
  "proto.b5t": "Ключи и казна",
  "proto.b5d": "NetworkParams пинит хеш s_pub (keccak от s_pub) + комитет. Ротация: owner предлагает (timelock от 7 дней) + approver подтверждает, исполнить может кто угодно после; отмена — только owner. Казна: предлагает/отменяет owner, исполняет кто угодно после 7 дней. Верифаер: то же окно без аппрувера — исполняет кто угодно, отменяет только owner.",
  "proto.b6t": "Что НЕ доказывается",
  "proto.b6d": "Нет Sybil-устойчивого кворума (плоские 3), нет полной проверки STARK на цепи, большинство комитета может расшифровать строки, внешнего аудита нет. См. /limits перед реальными деньгами.",
  "proto.foot": "Код: packages/contracts · packages/sdk · node/. Цифры: /status. Таски: /pool.",

  // --- settings -----------------------------------------------------------------------
  "settings.t": "Настройки",
  "settings.depth": "Глубина",
  "settings.depthHintSimple": "Простые слова, главное сначала. Для ML/web3-деталей жми гик.",
  "settings.depthHintGeek": "Каждый дайджест, окно и счёт кворума. Для простых слов жми просто.",
  "settings.langHint": "Язык всех экранов и алертов.",
  "settings.alertsHint": "Флаги этого чата. Глобальные алерты ротации вотчлист игнорируют.",
  "settings.foot": "Вотчлист: /watchlist. Все команды: /help.",

  // --- task human states ----------------------------------------------------------------
  "task.humanCollecting": "сбор данных",
  "task.humanTraining": "идёт обучение",
  "task.humanSettling": "выплаты",
  "task.humanRevealing": "раскрытие ключей",
  "task.humanDone": "готово",
  "task.humanStopped": "остановлен",
  "task.humanOpen": "открыт",

  // --- buttons ------------------------------------------------------------------
  "btn.refresh": "⟳ обновить",
  "btn.pool": "пул",
  "btn.prev": "‹ назад",
  "btn.next": "дальше ›",
  "btn.watch": "☆ следить",
  "btn.unwatch": "★ не следить",
  "btn.status": "статус",
  "btn.viewTask": "таск #{id}",
  "btn.viewStatus": "статус",
  "btn.modeSimple": "режим: просто",
  "btn.modePro": "режим: гик",
  "btn.roleBuyer": "Покупатель",
  "btn.roleContrib": "Контрибьютор",
  "btn.roleNode": "Узел",
  "btn.roleWatcher": "Наблюдатель",
  "btn.menu": "⌂ меню",
  "btn.how": "✦ как это работает",
  "btn.proto": "◈ протокол",
  "btn.settings": "⚙ настройки",
  "btn.limits": "🛡 честность",
  "btn.statusLong": "📊 статус",
  "btn.poolLong": "📋 таски",
  "btn.alertsLong": "🔔 алерты",
  // --- simple role guides (mode=simple) ---
  "role.buyerS": "<b>Покупатель — 3 шага.</b>\n\n1. Выбери таск в /pool — бюджет и статус простыми словами.\n2. Запри бюджет на цепи (это делает SDK: <code>createTask</code> → <code>sealTask</code>), затем открывай каждую эпоху (<code>openEpoch</code>) — без твоей транзакции эпоха не стартует.\n3. Следи за эпохами в /task, сдачу вернёт расчёт.\n\nГик-детали: /pro и переоткрой гайд.",
  "role.contribS": "<b>Контрибьютор — 3 шага.</b>\n\n1. Выбери открытый таск в /pool.\n2. Зашифруй строки у себя (это делает приложение) — наружу только шифротекст.\n3. Получи выплату при расчёте: твои строки × живость.\n\nОдин адрес = один шард на таск. Гик-детали: /pro.",
  "role.nodeS": "<b>Оператор узла — 3 шага.</b>\n\n1. Проверь /status — цепь, пин ключа, нет ли ротации, которой ты не ждал.\n2. Зарегистрируйся раз на таск, дальше софт сам считает и коммитит эпохи.\n3. Следи за /alerts: расхождение дайджестов — остановить и разобраться.\n\nНе гоняй под ротацией, которую не проверил. Гик-детали: /pro.",
  "role.watchS": "<b>Наблюдатель — 2 шага.</b>\n\n1. /watch &lt;id&gt; сужает алерты до одного таска. Пусто = всё.\n2. /alerts переключает расхождение коммита / споры / ротации / казну.\n\nДва главных: расхождение дайджестов и любое предложение ротации.",
};

const DICT = { en: EN, ru: RU };

/** Fill `{vars}` into a template. Values are inserted raw — the caller escapes. */
function fill(tpl, vars) {
  if (!vars) return tpl;
  return String(tpl).replace(/\{([a-zA-Z0-9_]+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}

/**
 * Translate a key. Falls back to English, then to a visible `!key!` marker —
 * a missing translation must shout in the chat (and in tests), never render
 * an empty line that looks intentional.
 */
export function t(lang, key, vars) {
  const l = isLang(lang) ? lang : "en";
  const d = DICT[l] || EN;
  if (Object.hasOwn(d, key)) return fill(d[key], vars);
  if (Object.hasOwn(EN, key)) return fill(EN[key], vars);
  return `!${key}!`;
}

/** All keys that must exist in every language (checked in tests). */
export function allKeys() {
  return Object.keys(EN);
}
