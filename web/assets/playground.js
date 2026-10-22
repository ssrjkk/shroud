/* Shroud Lab — протокол целиком в браузере.
   Математика — только web/assets/crypto.js (node/src/fhe.rs, packages/sdk).
   Сервера нет: всё считается локально. Строки — через window.I18N.
   Все выводы хранятся в S.view как данные и перерисовываются при смене языка. */
(function () {
  "use strict";
  var C = null;
  try { C = window.ShroudCrypto || null; } catch (e) { C = null; }
  function t(k) {
    try { if (window.I18N) return window.I18N.t(k); } catch (e) {}
    return k;
  }

  var S = {
    rows: [], features: 3, scale: 1000,
    shardBytes: null, cid: "", ctDigest: "",
    budget: 10000, epochs: 3, lr: 0.05, l2: 0.0, minibatch: 8,
    chainId: 31337, taskId: 1, cipherTask: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    seed: 42, prevDigest: "",
    epoch: 0, prevLanes: [], prevTrace: "0x" + "00".repeat(32), lastLoss: "0",
    lastProof: "", leaves: [],
    view: { preview: null, enc: null, task: null, exec: null, proof: null, settle: null, simple: null }
  };

  var PRESETS = {
    housing: { features: 3, csv: "1.2,3,2.1\n1.8,3,2.8\n2.0,2,3.0\n1.1,4,2.4\n2.4,3,3.6\n1.6,2,2.5\n2.9,4,4.2\n1.4,3,2.3" },
    medical: { features: 4, csv: "0.8,1.2,0.5,1.1\n1.4,0.9,1.1,2.0\n0.6,1.8,0.4,1.3\n2.0,1.1,1.6,2.9\n1.1,1.4,0.9,1.9\n1.9,2.0,1.2,3.1" },
    credit: { features: 5, csv: "1.0,0.5,1.2,0.8,2.2\n2.1,1.0,0.9,1.4,3.8\n0.7,1.6,1.8,0.6,2.9\n1.8,0.8,1.1,1.9,4.1\n1.2,1.2,1.0,1.0,3.0" }
  };

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function short(h) {
    if (!h) return "—";
    return h.length > 22 ? h.slice(0, 12) + "…" + h.slice(-8) : h;
  }
  function err(box, msg) {
    var el = $(box); if (!el) return;
    el.innerHTML = msg ? '<div class="err">' + esc(msg) + "</div>" : "";
  }
  function ok(box, msg) {
    var el = $(box); if (!el) return;
    el.innerHTML = msg ? '<div class="okmsg">' + esc(msg) + "</div>" : "";
  }
  function keccakHex(bytes) { return "0x" + C.hex(C.keccak256Bytes(bytes)); }
  function asciiBytes(s) {
    var o = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 0xff;
    return o;
  }
  function zeros(f) { var a = []; for (var i = 0; i < f; i++) a.push(0); return a; }

  function toNum(cell, ln, i) {
    // Strict decimal only: Number() would silently accept "0x10" (16), "0b101" (5)
    // or "1e3" as a user meaning something else, and train on numbers the user never
    // typed. Scientific notation stays allowed — it is decimal, just compact.
    if (!/^-?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(cell)) {
      throw new Error(t("lab.e.rowline") + (i + 1) + t("lab.e.notnum") + ln + "»");
    }
    return Number(cell);
  }

  function splitRow(ln) {
    // Excel-стиль: колонки через ";", десятичная запятая внутри чисел.
    // Без ";" — старый формат: запятая/пробел/табуляция, точка в дробях.
    if (ln.indexOf(";") !== -1) {
      return ln.split(";").map(function (p) {
        var s = p.trim().replace(/\s+/g, "");
        if (/^-?\d+,\d+$/.test(s)) s = s.replace(",", ".");
        return s;
      }).filter(function (x) { return x !== ""; });
    }
    return ln.split(/[,\t ]+/).filter(function (x) { return x !== ""; });
  }

  function parseCsv(text) {
    var rows = [];
    var lines = String(text).replace(/^﻿/, "").split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i].trim();
      if (!ln || ln[0] === "#") continue;
      var parts = splitRow(ln);
      var nums = parts.map(function (p) { return toNum(p, ln, i); });
      if (nums.some(function (x) { return !isFinite(x); })) {
        throw new Error(t("lab.e.rowline") + (i + 1) + t("lab.e.notnum") + ln + "»");
      }
      rows.push(nums);
    }
    if (!rows.length) throw new Error(t("lab.e.norows"));
    if (rows.length > 2000) throw new Error(t("lab.e.toomany"));
    var f = rows[0].length;
    if (f < 2) throw new Error(t("lab.e.min2"));
    rows.forEach(function (r, k) {
      if (r.length !== f) throw new Error(t("lab.e.rowline") + (k + 1) + ": " + r.length + t("lab.e.cols") + f);
      r.forEach(function (v) { if (v < 0) throw new Error(t("lab.e.rowline") + (k + 1) + t("lab.e.neg") + v + t("lab.e.neg2")); });
    });
    return { rows: rows, features: f };
  }

  /* --- журнал --- */

  function renderLedger() {
    var n = S.rows.length;
    var w0 = S.prevLanes.length ? S.prevLanes : zeros(S.features);
    var wd = "—";
    try { wd = C.weightsDigest(w0); } catch (e) {}
    var html = "";
    html += "<h2>" + esc(t("lab.j.set")) + "</h2><table class=\"ltable\">" +
      "<tr><td>" + esc(t("lab.j.rows")) + "</td><td>" + n + " / " + S.features + "</td></tr>" +
      "<tr><td>scale</td><td>" + S.scale + "</td></tr>" +
      "<tr><td>" + esc(t("lab.j.commit")) + "</td><td>" + esc(short(S.ctDigest)) + "</td></tr>" +
      "<tr><td>" + esc(t("lab.j.shard")) + "</td><td>" + esc(short(S.cid)) + "</td></tr>" +
      "<tr><td>" + esc(t("lab.j.pin")) + "</td><td>" + esc(short(S.pin)) + "</td></tr>" +
      "<tr><td>" + esc(t("lab.j.bytes")) + "</td><td>" + (S.shardBytes ? S.shardBytes.length : "—") + "</td></tr></table>";
    html += "<h2>" + esc(t("lab.j.task")) + "</h2><table class=\"ltable\">" +
      "<tr><td>" + esc(t("lab.j.te")) + "</td><td>" + S.taskId + " / " + S.epoch + " " + esc(t("lab.j.of")) + " " + S.epochs + "</td></tr>" +
      "<tr><td>" + esc(t("lab.j.budget")) + "</td><td>" + S.budget + " USDC</td></tr>" +
      "<tr><td>" + esc(t("lab.j.pools")) + "</td><td>" + Math.floor(S.budget * 0.8) + " / " + Math.floor(S.budget * 0.15) + " / " + (S.budget - Math.floor(S.budget * 0.8) - Math.floor(S.budget * 0.15)) + "</td></tr>" +
      "<tr><td>" + esc(t("lab.j.weights")) + "</td><td>[" + w0.join(", ") + "]</td></tr>" +
      "<tr><td>" + esc(t("lab.j.wd")) + "</td><td>" + esc(short(wd)) + "</td></tr>" +
      "<tr><td>" + esc(t("lab.j.trace")) + "</td><td>" + esc(short(S.prevTrace)) + "</td></tr></table>";
    html += "<h2>" + esc(t("lab.j.how")) + "</h2><div class=\"lout\">" + esc(t("lab.j.howv")) + "</div>";
    $("ledger").innerHTML = html;
  }

  /* --- выводы: данные отдельно, текст отдельно --- */

  function renderPreview() {
    var v = S.view.preview; if (!v) return;
    var el = $("preview"); if (!el) return;
    el.textContent = v.n + " × " + v.f + "\n" + v.head + (v.rest > 0 ? "\n… +" + v.rest : "");
  }
  function renderEnc() {
    var v = S.view.enc; if (!v) return;
    var el = $("encOut"); if (!el) return;
    el.textContent =
      t("lab.o.layout") + ":  shroud/noop/v1\nbytes:   " + v.bytes + "\ncommit:  " + v.commit + "\ncid:     " + v.cid +
      "\n\n" + t("lab.o.demo");
  }
  function renderTask() {
    var v = S.view.task; if (!v) return;
    var el = $("taskOut"); if (!el) return;
    el.textContent =
      "createTask(budget=" + v.budget + ") → " + t("lab.o.escrow") + "\ncontributors 80%: " + v.c + t("lab.o.contrib") +
      "\nnodes 15%:        " + v.nd + t("lab.o.nodes") + v.perEpoch +
      "\ntreasury:      " + v.tm + "\nsettleFrom(taskId, cursor): " + t("lab.o.settle");
  }
  function renderExec() {
    var v = S.view.exec; if (!v) return;
    var el = $("execOut"); if (!el) return;
    el.textContent =
      t("lab.o.epoch") + " " + v.done + "/" + v.of + t("lab.o.rows") + v.nRows +
      "\nlossMeanQ: " + v.loss + "\nlanes: [" + v.lanes.join(", ") + "]" +
      "\nweightsDigest: " + v.dg + "\nweights file: shroud/weights/v1 · " + v.fileLen + " bytes · head " + v.head + "…";
  }
  function renderProof() {
    var v = S.view.proof; if (!v) return;
    var po = $("proofOut");
    if (po) po.textContent =
      "traceDigest: " + v.td + "\nproofRef:    " + v.pr + "  (0x53544152 = «STAR»)" +
      "\n\n" + t("lab.o.checks") +
      "\n[✓] chainId + CipherTask — digest" +
      "\n[✓] ctRoot + leaf order — dataset" +
      "\n[✓] prevDigest → nextDigest — chain" +
      "\n[!] on-chain — sampled; full STARK — off-chain";
    var ro = $("rawOut");
    if (ro) ro.textContent = JSON.stringify(v.input, null, 1);
  }
  function renderSettle() {
    var v = S.view.settle; if (!v) return;
    var el = $("settleOut"); if (!el) return;
    el.textContent =
      "task " + v.taskId + " · epochs " + v.epochs +
      "\ncontributor: rows=" + v.rows + " → sqrt=" + v.w + " → ≈" + v.c + " USDC" +
      "\nwinner node: " + v.perEpoch + " USDC × " + v.epochs +
      "\ncommittee/treasury: " + v.tm + " USDC" +
      "\nPaymentVault: EIP-712 slices, disjoint pools.";
  }
  function renderSimple() {
    var v = S.view.simple; if (!v) return;
    var el = $("simpleOut"); if (!el) return;
    var lines = [];
    lines.push("✓ " + v.rows + " " + t("lab.s.rows") + " — " + t("lab.s.ok1"));
    lines.push("✓ " + t("lab.s.ok2") + " " + v.loss);
    lines.push("✓ " + t("lab.s.ok3") + " [" + v.lanes.join(", ") + "]");
    lines.push("✓ " + t("lab.s.ok4") + " " + short(v.pr));
    lines.push("✓ " + t("lab.s.ok5") + v.c + " USDC, " + t("lab.s.ok5b") + v.perEpoch + " USDC");
    lines.push("");
    lines.push(t("lab.s.done"));
    el.textContent = lines.join("\n");
  }
  function renderAllViews() {
    renderPreview(); renderEnc(); renderTask(); renderExec(); renderProof(); renderSettle(); renderSimple();
  }

  function download(name, text, type) {
    var blob = new Blob([text], { type: type || "application/octet-stream" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 800);
  }

  /* --- шаги --- */

  function doParse() {
    var parsed = parseCsv($("csv").value);
    var fWant = parseInt($("features").value, 10);
    if (fWant && fWant !== parsed.features) {
      throw new Error(t("lab.e.featmis") + parsed.features + t("lab.e.featmis2") + fWant + t("lab.e.featmis3"));
    }
    S.rows = parsed.rows; S.features = parsed.features;
    S.scale = Math.max(1, parseInt($("scale").value, 10) || 1000);
    S.prevLanes = zeros(S.features); S.epoch = 0;
    S.prevTrace = "0x" + "00".repeat(32); S.lastProof = "";
    var head = S.rows.slice(0, 8).map(function (r) { return r.join(", "); }).join("\n");
    S.view.preview = { n: S.rows.length, f: S.features, head: head, rest: Math.max(0, S.rows.length - 8) };
    renderPreview(); renderLedger();
    return true;
  }

  function doEncrypt() {
    if (!S.rows.length) throw new Error(t("lab.m.nodata"));
    S.scale = Math.max(1, parseInt($("scale").value, 10) || 1000);
    var bytes = C.encodeNoopShard(S.features, S.rows, S.scale);
    var commit = C.noopRowCommitment(S.rows, S.scale);
    // The contribution as the chain records it: the transport address the SDK's
    // store gives the payload (sha256) and the on-chain pin (keccak256). The node
    // reads both from the chain, and the leaf it puts into the trace digest is
    // exactly these two values - the row commitment is a third thing and is not
    // part of the leaf.
    var cid = "0x" + C.hex(C.sha256Bytes(bytes));
    var pin = keccakHex(bytes);
    // The chain's running root over (leafIndex, ciphertextCid).
    var ctRoot = "0x" + C.hex(C.keccak256Bytes(
      (function () {
        var b = new Uint8Array(68);
        b.set(C.keccak256Bytes(asciiBytes("SHROUD/CTROOT/v1")), 0);
        b[32] = 0; b[33] = 0; b[34] = 0; b[35] = 0; // leaf index, u32 big-endian
        var t = cid.slice(2);
        for (var i = 0; i < 32; i++) b[36 + i] = parseInt(t.substr(i * 2, 2), 16);
        return b;
      })()
    ));
    S.shardBytes = bytes; S.ctDigest = commit; S.cid = cid; S.pin = pin; S.ctRoot = ctRoot;
    S.leaves = [{ index: 0, cid: cid, ct: pin }];
    S.view.enc = { bytes: bytes.length, commit: commit, cid: cid, pin: pin, ctRoot: ctRoot };
    renderEnc(); renderLedger();
    return true;
  }

  function readTaskInputs() {
    S.budget = Math.max(1, parseInt($("budget").value, 10) || 10000);
    S.epochs = Math.min(20, Math.max(1, parseInt($("epochs").value, 10) || 3));
    S.chainId = parseInt($("chainId").value, 10) || 31337;
    S.taskId = Math.max(1, parseInt($("taskId").value, 10) || 1);
    S.cipherTask = ($("cipherTask").value || "").trim() || S.cipherTask;
    var seedEl = $("seed");
    S.seed = seedEl ? (Math.max(0, parseInt(seedEl.value, 10)) || 0) : 42;
    var pdEl = $("prevDigest");
    var raw = pdEl ? (pdEl.value || "").trim().replace(/^0x/, "") : "";
    if (raw && !/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error(t("lab.e.prev"));
    S.prevDigest = raw ? ("0x" + raw.toLowerCase()) : ("0x" + "00".repeat(32));
  }

  function doTask() {
    readTaskInputs();
    var c = Math.floor(S.budget * 0.8), nd = Math.floor(S.budget * 0.15), tm = S.budget - c - nd;
    S.view.task = { budget: S.budget, c: c, nd: nd, perEpoch: (nd / S.epochs).toFixed(2), tm: tm };
    renderTask(); renderLedger();
    return true;
  }

  function hyper() {
    return {
      lrQ16: Math.round((parseFloat($("lr").value) || 0.05) * 65536),
      l2Q16: Math.round((parseFloat($("l2").value) || 0) * 65536),
      mb: Math.max(1, parseInt($("minibatch").value, 10) || 8)
    };
  }

  function doExec() {
    if (!S.rows.length) throw new Error(t("lab.m.noexecdata"));
    var h = hyper();
    var flat = [];
    S.rows.forEach(function (r) {
      r.forEach(function (v) { flat.push(Math.round(v * S.scale)); });
    });
    var res = C.referenceStep({
      features: S.features, scale: S.scale, lrQ16: h.lrQ16, l2Q16: h.l2Q16,
      minibatch: h.mb, prevLanes: S.prevLanes.slice(), shards: [flat]
    });
    S.prevLanes = res.lanes; S.lastLoss = res.lossMeanQ;
    var dg = C.weightsDigest(res.lanes);
    var file = C.encodeWeights(S.features, res.lanes);
    var head = Array.prototype.slice.call(file.slice(0, 48)).map(function (b) { return (b < 16 ? "0" : "") + b.toString(16); }).join("");
    S.epoch = Math.min(S.epochs, S.epoch + 1);
    S.view.exec = { done: S.epoch, of: S.epochs, nRows: res.nRows, loss: res.lossMeanQ, lanes: res.lanes.slice(), dg: dg, fileLen: file.length, head: head };
    renderExec(); renderLedger();
    return true;
  }

  function doProof() {
    if (!S.cid) throw new Error(t("lab.m.nocid"));
    if (!S.epoch) throw new Error(t("lab.m.noepoch"));
    readTaskInputs();
    var h = hyper();
    var taskHex = "0x" + C.hex(C.keccak256Bytes(asciiBytes("demo-task-" + S.taskId))).slice(0, 64);
    var nextD = C.weightsDigest(S.prevLanes);
    var input = {
      taskId: taskHex, epoch: Math.max(0, S.epoch - 1), chainId: S.chainId,
      cipherTask: S.cipherTask, ctRoot: S.ctRoot || S.cid, prevDigest: S.prevDigest,
      features: S.features, scale: S.scale, lrQ16: h.lrQ16, l2Q16: h.l2Q16,
      minibatch: h.mb, seed: S.seed, nRows: S.rows.length,
      lossMeanQ: S.lastLoss, leaves: S.leaves, nextDigest: nextD
    };
    var td = C.traceDigest(input);
    var pr = C.proofReference(td);
    S.prevTrace = td; S.lastProof = pr;
    S.view.proof = { td: td, pr: pr, input: input };
    renderProof(); renderLedger();
    return { td: td, pr: pr };
  }

  function doSettle() {
    if (!S.epoch) throw new Error(t("lab.m.noepoch"));
    readTaskInputs();
    var c = Math.floor(S.budget * 0.8), nd = Math.floor(S.budget * 0.15), tm = S.budget - c - nd;
    var perEpoch = nd / S.epochs;
    var w = Math.sqrt(Math.max(1, S.rows.length));
    S.view.settle = { taskId: S.taskId, epochs: S.epochs, rows: S.rows.length, w: w.toFixed(2), c: c, perEpoch: perEpoch.toFixed(2), tm: tm };
    renderSettle();
    return { c: c, perEpoch: perEpoch };
  }

  function doSimple() {
    doParse(); doEncrypt(); doTask(); doExec();
    var proof = doProof(); var pay = doSettle();
    S.view.simple = { rows: S.rows.length, loss: S.lastLoss, lanes: S.prevLanes.slice(), pr: proof.pr, c: pay.c, perEpoch: pay.perEpoch.toFixed(2) };
    renderSimple();
    return true;
  }

  function boot() {
    if (!C) {
      err("msg1", t("lab.e.nocrypto"));
      return;
    }
    S.prevLanes = zeros(S.features);
    renderLedger();
    document.addEventListener("shroud:lang", function () { renderLedger(); renderAllViews(); });

    var presetEl = $("preset");
    if (presetEl) presetEl.addEventListener("change", function () {
      var p = PRESETS[presetEl.value];
      if (!p) return;
      $("csv").value = p.csv;
      $("features").value = p.features;
    });

    function wrap(msgBox, okMsg, fn) {
      err(msgBox, ""); ok(msgBox, "");
      try {
        var r = fn();
        if (okMsg) ok(msgBox, okMsg);
        return r;
      } catch (e) { err(msgBox, e.message); return null; }
    }

    var runAll = $("runAll");
    if (runAll) runAll.addEventListener("click", function () {
      err("msg0", "");
      ["msg1", "msg2", "msg3", "msg4", "msg5", "msg6"].forEach(function (m) { err(m, ""); });
      try { doSimple(); }
      catch (e) { err("msg0", e.message); }
    });

    $("parseBtn").addEventListener("click", function () {
      var r = wrap("msg1", null, doParse);
      if (r) ok("msg1", t("lab.m.parsed") + S.rows.length + t("lab.m.rowsx") + S.features + t("lab.m.next"));
    });
    $("encBtn").addEventListener("click", function () {
      wrap("msg2", t("lab.m.encok"), doEncrypt);
    });
    $("dlShard").addEventListener("click", function () {
      if (!S.shardBytes) { err("msg2", t("lab.m.nodl")); return; }
      var hex = Array.prototype.map.call(S.shardBytes, function (b) { return (b < 16 ? "0" : "") + b.toString(16); }).join("");
      download("shard.hex", hex, "text/plain");
    });
    $("taskBtn").addEventListener("click", function () {
      wrap("msg3", t("lab.m.taskok"), doTask);
    });
    $("execBtn").addEventListener("click", function () {
      wrap("msg4", t("lab.m.execok"), doExec);
    });
    $("dlWeights").addEventListener("click", function () {
      try {
        if (!S.prevLanes.length) throw new Error(t("lab.m.noweights"));
        var file = C.encodeWeights(S.features, S.prevLanes);
        var hex = Array.prototype.map.call(file, function (b) { return (b < 16 ? "0" : "") + b.toString(16); }).join("");
        download("weights-demo.hex", "features=" + S.features + "\nlanes=" + S.prevLanes.join(",") + "\ndigest=" + C.weightsDigest(S.prevLanes) + "\nhex=" + hex + "\n", "text/plain");
      } catch (e) { err("msg4", e.message); }
    });
    $("resetEpochs").addEventListener("click", function () {
      S.prevLanes = zeros(S.features); S.epoch = 0; S.prevTrace = "0x" + "00".repeat(32); S.lastProof = "";
      ok("msg4", t("lab.m.reset")); renderLedger();
    });
    $("proofBtn").addEventListener("click", function () {
      wrap("msg5", t("lab.m.proofok"), doProof);
    });
    $("settleBtn").addEventListener("click", function () {
      wrap("msg6", t("lab.m.settleok"), doSettle);
    });
    $("reportBtn").addEventListener("click", function () {
      var report = {
        project: "shroud-demo-report",
        features: S.features, rows: S.rows.length, scale: S.scale,
        cid: S.cid, ctDigest: S.ctDigest,
        taskId: S.taskId, chainId: S.chainId, cipherTask: S.cipherTask,
        budget: S.budget, epochs: S.epochs, epochDone: S.epoch,
        lanes: S.prevLanes, weightsDigest: null, trace: S.prevTrace,
        proofRef: S.lastProof, seed: S.seed,
        note: "reference-cpu demo; mock-verifier proof ref; not audited"
      };
      try { report.weightsDigest = C.weightsDigest(S.prevLanes); } catch (e) {}
      download("shroud-report.json", JSON.stringify(report, null, 2), "application/json");
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
