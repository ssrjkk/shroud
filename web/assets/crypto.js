/* ==========================================================================
   Shroud workshop crypto — dependency-free protocol math for the site.
   --------------------------------------------------------------------------
   Mirrors `node/src/fhe.rs` (Weights encode/decode/digest, noop shard layout,
   trace digest, reference fixed-point SGD) and `packages/sdk` (quantization,
   row commitment) byte for byte. Anything here that drifts from those sources
   produces digests no node reproduces, so every layout below is pinned by
   cross-checks, not by comments.

   Works in browsers and in node (CommonJS guard at the bottom) so the same
   file is unit-tested with `node` against the SDK's own encoders.
   ========================================================================== */
(function (root, factory) {
  var api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ShroudCrypto = api;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* keccak-256 (Keccak-f[1600], pad10*1, rate 1088). Public domain logic,
     written out rather than vendored so this file stays dependency-free. */
  /* ------------------------------------------------------------------ */

  // Keccak-f round constants, (lo, hi) 32-bit pairs from the spec table.
  var RC = [
    0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000,
    0x80008000, 0x80000000, 0x0000808b, 0x00000000, 0x80000001, 0x00000000,
    0x80008081, 0x80000000, 0x00008009, 0x80000000, 0x0000008a, 0x00000000,
    0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000,
    0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000,
    0x00008003, 0x80000000, 0x00008002, 0x80000000, 0x00000080, 0x80000000,
    0x0000800a, 0x00000000, 0x8000000a, 0x80000000, 0x80008081, 0x80000000,
    0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000,
  ];
  var RHO = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
  ];
  // pi: lane j = x+5y moves to y+5*((2x+3y)%5) — the Keccak-f permutation.
  var PI = [0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4];

  function rotl64(lo, hi, n) {
    n %= 64;
    if (n === 0) return [lo >>> 0, hi >>> 0];
    if (n < 32) {
      return [((lo << n) | (hi >>> (32 - n))) >>> 0, ((hi << n) | (lo >>> (32 - n))) >>> 0];
    }
    n -= 32;
    if (n === 0) return [hi >>> 0, lo >>> 0];
    return [((hi << n) | (lo >>> (32 - n))) >>> 0, ((lo << n) | (hi >>> (32 - n))) >>> 0];
  }

  function keccakf(s) {
    // s: 50 uint32 words, [lane0.lo, lane0.hi, lane1.lo, ...]
    var C = new Array(10);
    var D = new Array(10);
    var B = new Array(50);
    for (var round = 0; round < 24; round++) {
      for (var x = 0; x < 5; x++) {
        C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
        C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
      }
      // Theta: D[x] = C[x-1] XOR ROTL(C[x+1], 1), then A[x,y] ^= D[x].
      for (var x2 = 0; x2 < 5; x2++) {
        var t = rotl64(C[2 * ((x2 + 1) % 5)], C[2 * ((x2 + 1) % 5) + 1], 1);
        D[2 * x2] = (C[2 * ((x2 + 4) % 5)] ^ t[0]) >>> 0;
        D[2 * x2 + 1] = (C[2 * ((x2 + 4) % 5) + 1] ^ t[1]) >>> 0;
      }
      for (var i = 0; i < 50; i += 2) {
        s[i] = (s[i] ^ D[i % 10]) >>> 0;
        s[i + 1] = (s[i + 1] ^ D[(i % 10) + 1]) >>> 0;
      }
      for (var j = 0; j < 25; j++) {
        var src = 2 * j;
        var dst = 2 * PI[j];
        var r = rotl64(s[src], s[src + 1], RHO[j]);
        B[dst] = r[0];
        B[dst + 1] = r[1];
      }
      for (var k = 0; k < 25; k++) {
        var k2 = 2 * k;
        var k1 = 2 * ((k + 1) % 5 + 5 * Math.floor(k / 5));
        var k22 = 2 * ((k + 2) % 5 + 5 * Math.floor(k / 5));
        s[k2] = (B[k2] ^ (~B[k1] & B[k22])) >>> 0;
        s[k2 + 1] = (B[k2 + 1] ^ (~B[k1 + 1] & B[k22 + 1])) >>> 0;
      }
      s[0] = (s[0] ^ RC[2 * round]) >>> 0;
      s[1] = (s[1] ^ RC[2 * round + 1]) >>> 0;
    }
  }

  function keccak256Bytes(msg) {
    var rate = 136; // 1088 bits
    var s = new Array(50).fill(0);
    var off = 0;
    while (off < msg.length) {
      var block = Math.min(rate, msg.length - off);
      for (var i = 0; i < block; i++) {
        // lanes are little-endian: byte i is lane (i>>3), lane-byte (i&7).
        var lane = i >> 3, lb = i & 7;
        var w = 2 * lane + (lb >> 2);
        s[w] = (s[w] ^ (msg[off + i] << (8 * (lb & 3)))) >>> 0;
      }
      off += block;
      if (block === rate) keccakf(s);
    }
    // pad10*1 with domain 0x01: last byte shared when the message filled the block.
    var lastByte = rate - 1; // 135 → lane 16, lane-byte 7, hi word 33
    var wLast = 2 * (lastByte >> 3) + (((lastByte & 7) >> 2));
    if (msg.length % rate === rate - 1) {
      // 0x01 and 0x80 collide on the same byte — use combined 0x81.
      s[wLast] = (s[wLast] ^ (0x81 << (8 * (lastByte & 3)))) >>> 0;
      keccakf(s);
    } else {
      var padPos = msg.length % rate;
      var wPad = 2 * (padPos >> 3) + (((padPos & 7) >> 2));
      s[wPad] = (s[wPad] ^ (0x01 << (8 * (padPos & 3)))) >>> 0;
      s[wLast] = (s[wLast] ^ (0x80 << (8 * (lastByte & 3)))) >>> 0;
      keccakf(s);
    }
    var out = new Uint8Array(32);
    for (var b = 0; b < 32; b++) {
      var laneB = b >> 3, lbB = b & 7;
      out[b] = (s[2 * laneB + (lbB >> 2)] >>> (8 * (lbB & 3))) & 0xff;
    }
    return out;
  }

  function hex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) {
      s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    }
    return s;
  }

  function unhex(h) {
    if (typeof h !== "string" || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
      throw new Error("expected even-length hex");
    }
    var out = new Uint8Array(h.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(2 * i, 2), 16);
    return out;
  }

  function ascii(str) {
    var out = new Uint8Array(str.length + 1);
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c > 127) throw new Error("magic must be ASCII");
      out[i] = c;
    }
    out[str.length] = 0;
    return out;
  }

  function concat(parts) {
    var len = 0;
    for (var i = 0; i < parts.length; i++) len += parts[i].length;
    var out = new Uint8Array(len);
    var o = 0;
    for (var j = 0; j < parts.length; j++) {
      out.set(parts[j], o);
      o += parts[j].length;
    }
    return out;
  }

  function u32le(n) {
    if (!Number.isInteger(n) || n < 0 || n > 4294967295) throw new Error("not a u32: " + n);
    return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
  }

  function u32be(n) {
    if (!Number.isInteger(n) || n < 0 || n > 4294967295) throw new Error("not a u32: " + n);
    return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  }

  function u64be(b) {
    // b: BigInt, exactly 8 bytes big-endian
    if (typeof b !== "bigint" || b < 0n || b > 0xffffffffffffffffn) throw new Error("not a u64");
    var out = new Uint8Array(8);
    for (var i = 7; i >= 0; i--) {
      out[i] = Number(b & 0xffn);
      b >>= 8n;
    }
    return out;
  }

  function u256be(hexstr) {
    var raw = unhex(hexstr.replace(/^0x/, ""));
    if (raw.length !== 32) throw new Error("not 32 bytes");
    return raw;
  }

  function addr20(hexstr) {
    var raw = unhex(hexstr.replace(/^0x/, ""));
    if (raw.length !== 20) throw new Error("not 20 bytes");
    return raw;
  }

  /* ------------------------------------------------------------------ */
  /* weights files: shroud/weights/v1 — mirrors node Weights::{encode,
     decode, digest} and packages/sdk/src/weights.ts. */
  /* ------------------------------------------------------------------ */

  var WEIGHTS_MAGIC = "shroud/weights/v1";

  function checkedLane(v, index) {
    if (typeof v !== "number" || !Number.isInteger(v)) {
      throw new Error("lane " + index + " is not an integer");
    }
    if (v < -2147483648 || v > 2147483647) {
      throw new Error("lane " + index + " outside the i32 lane range");
    }
    return v >>> 0;
  }

  function encodeWeights(features, lanes) {
    if (!Number.isInteger(features) || features < 2) throw new Error("features must be >= 2");
    if (lanes.length !== features) throw new Error("got " + lanes.length + " lanes for " + features + " features");
    var words = [ascii(WEIGHTS_MAGIC), u32le(features), u32le(lanes.length)];
    for (var i = 0; i < lanes.length; i++) words.push(u32le(checkedLane(lanes[i], i)));
    return concat(words);
  }

  function decodeWeights(bytes, expectedFeatures) {
    var head = ascii(WEIGHTS_MAGIC);
    if (bytes.length < head.length + 8) throw new Error("shorter than the header");
    for (var i = 0; i < head.length; i++) {
      if (bytes[i] !== head[i]) throw new Error("bad weights magic");
    }
    var dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    var features = dv.getUint32(head.length, true);
    var count = dv.getUint32(head.length + 4, true);
    if (features !== expectedFeatures) throw new Error("holds " + features + " features");
    if (count !== features) throw new Error("holds " + count + " lanes");
    if (bytes.length !== head.length + 8 + count * 4) throw new Error("trailing bytes");
    var lanes = [];
    for (var j = 0; j < count; j++) {
      lanes.push(dv.getUint32(head.length + 8 + j * 4, true) | 0);
    }
    return { features: features, lanes: lanes };
  }

  function weightsDigest(lanes) {
    var buf = new Uint8Array(lanes.length * 4);
    var dv = new DataView(buf.buffer);
    for (var i = 0; i < lanes.length; i++) dv.setUint32(i * 4, checkedLane(lanes[i], i), true);
    return "0x" + hex(keccak256Bytes(buf));
  }

  /* ------------------------------------------------------------------ */
  /* noop shards: shroud/noop/v1 — mirrors NoopEncryptor + decode_noop_shard,
     quantization mirrors SDK quantizeRows (round(v*scale), unsigned). */
  /* ------------------------------------------------------------------ */

  var NOOP_MAGIC = "shroud/noop/v1";

  function quantize(v, scale) {
    if (!isFinite(v)) throw new Error("not finite");
    if (v < 0) throw new Error("negative: TFHE encrypts unsigned integers");
    var q = Math.round(v * scale);
    if (q >= 18446744073709551616) throw new Error("overflows uint64");
    return q;
  }

  function encodeNoopShard(features, rows, scale) {
    // rows: array of arrays of floats, last lane of each row is the label.
    if (!Number.isInteger(features) || features < 2) throw new Error("features must be >= 2");
    for (var i = 0; i < rows.length; i++) {
      if (!Array.isArray(rows[i]) || rows[i].length !== features) {
        throw new Error("row " + i + " is not " + features + " lanes");
      }
    }
    var head = ascii(NOOP_MAGIC);
    var meta = new TextEncoder().encode(features + "\0" + rows.length + "\0");
    var body = new Uint8Array(rows.length * features * 8);
    var dv = new DataView(body.buffer);
    var k = 0;
    for (var r = 0; r < rows.length; r++) {
      for (var j = 0; j < features; j++) {
        quantize(rows[r][j], scale); // reject first, exactly like the node
        dv.setFloat64(k * 8, rows[r][j], true);
        k++;
      }
    }
    return concat([head, meta, body]);
  }

  function noopRowCommitment(rows, scale) {
    // keccak256("shroud/relayer-row/v1\0" — no: the NOOP commitment mirrors
    // noopRowCommitment: keccak256("shroud/noop-row/v1\0" + f64 matrix bytes).
    var tag = ascii("shroud/noop-row/v1");
    var matrix = new Uint8Array(rows.length * rows[0].length * 8);
    var dv = new DataView(matrix.buffer);
    var k = 0;
    for (var r = 0; r < rows.length; r++) {
      for (var j = 0; j < rows[r].length; j++) {
        dv.setFloat64(k * 8, rows[r][j], true);
        k++;
      }
    }
    return "0x" + hex(keccak256Bytes(concat([tag, matrix])));
  }

  /* ------------------------------------------------------------------ */
  /* trace digest + proof reference — mirrors node trace_digest() and
     proof_reference() byte for byte (all integers big-endian on the wire). */
  /* ------------------------------------------------------------------ */

  var TRACE_MAGIC = "SHROUD/TRACE/v1";
  var PROOF_REF_MAGIC = "SHROUD/PROOF-REF/v1";

  function traceDigest(p) {
    // p: {taskId, epoch, chainId, cipherTask, ctRoot, prevDigest, features, scale,
    //     lrQ16, l2Q16, minibatch, seed, nRows, lossMeanQ|null, leaves:[{index,cid,ct}],
    //     nextDigest} — hex strings with 0x, integers as numbers/BigInts.
    var parts = [ascii(TRACE_MAGIC)];
    parts.push(u256be(p.taskId));
    parts.push(u32be(p.epoch));
    parts.push(u64be(BigInt(p.chainId)));
    parts.push(addr20(p.cipherTask));
    parts.push(u256be(p.ctRoot));
    parts.push(u256be(p.prevDigest));
    parts.push(u32be(p.features));
    parts.push(u32be(p.scale));
    parts.push(u32be(p.lrQ16));
    parts.push(u32be(p.l2Q16));
    parts.push(u64be(BigInt(p.minibatch)));
    parts.push(u64be(BigInt(p.seed)));
    parts.push(u64be(BigInt(p.nRows)));
    var loss = p.lossMeanQ === null || p.lossMeanQ === undefined ? 0n : BigInt(p.lossMeanQ);
    if (loss < 0) loss = (1n << 128n) + loss; // two's complement i128
    var lb = new Uint8Array(16);
    for (var i = 15; i >= 0; i--) {
      lb[i] = Number(loss & 0xffn);
      loss >>= 8n;
    }
    parts.push(lb);
    var leaves = p.leaves.slice().sort(function (a, b) { return a.index - b.index; });
    for (var l = 0; l < leaves.length; l++) {
      parts.push(u32be(leaves[l].index));
      parts.push(u256be(leaves[l].cid));
      parts.push(u256be(leaves[l].ct));
    }
    parts.push(u256be(p.nextDigest));
    return "0x" + hex(keccak256Bytes(concat(parts)));
  }

  function proofReference(traceDigest) {
    var h = keccak256Bytes(concat([ascii(PROOF_REF_MAGIC).slice(0, 19), u256be(traceDigest)]));
    // 0x53544152 ("STAR") + hash[0..28]
    var out = "53544152";
    for (var i = 0; i < 28; i++) out += (h[i] < 16 ? "0" : "") + h[i].toString(16);
    return "0x" + out;
  }

  /* ------------------------------------------------------------------ */
  /* reference fixed-point SGD — mirrors ReferenceCpuEngine::execute_epoch
     (i128 checked math becomes checked BigInt; lane updates clamp to i64;
     division truncates toward zero in both). */
  /* ------------------------------------------------------------------ */

  var I128_MIN = -(1n << 127n);
  var I128_MAX = (1n << 127n) - 1n;
  var I64_MIN = -(1n << 63n);
  var I64_MAX = (1n << 63n) - 1n;

  // Overflow is an error, never a wrap — like the node's checked i128 arithmetic.
  // The taxonomy mirrors the node (`Overflow` vs `Diverged` vs lane range): an input
  // that overflows i128 must throw here exactly where the node throws there.
  function checkedI128(v, ctx) {
    if (v < I128_MIN || v > I128_MAX) throw new Error("overflow: " + ctx);
    return v;
  }

  // Lane updates saturate at i64 — like the node's apply_update — instead of throwing.
  function clampI64(v) {
    if (v < I64_MIN) return I64_MIN;
    if (v > I64_MAX) return I64_MAX;
    return v;
  }

  function referenceStep(o) {
    // o: {features, scale, lrQ16, l2Q16, minibatch, prevLanes, shards:[{values:[u64]}]}
    // returns {lanes, lossMeanQ, nRows}
    var f = o.features;
    if (f < 2) throw new Error("need >= 2 features");
    if (o.prevLanes.length !== f) throw new Error("prev weights shape");
    if (o.scale <= 0 || o.minibatch <= 0) throw new Error("scale/minibatch must be > 0");
    var S = BigInt(o.scale);
    var w = o.prevLanes.map(function (x) { return BigInt(x); }); // i32 as signed BigInt
    var grad = [];
    for (var g = 0; g < f; g++) grad.push(0n);
    var inBatch = 0;
    var nRows = 0;
    var loss = 0n;
    function apply(m) {
      var denom = 65536n * S * BigInt(m);
      for (var j = 0; j < f; j++) {
        // Like the node (plain `*`, then clamp): the product is unchecked, the lane
        // saturates instead of wrapping. Only accumulators are checked (see above).
        var delta = (BigInt(o.lrQ16) * grad[j]) / denom; // truncates toward zero, like i128 /
        w[j] = clampI64(w[j] - delta);
        grad[j] = 0n;
      }
    }
    for (var s = 0; s < o.shards.length; s++) {
      var v = o.shards[s];
      if (v.length % f !== 0) throw new Error("shard length");
      for (var r = 0; r < v.length / f; r++) {
        var dot = 0n;
        for (var j = 0; j < f - 1; j++) {
          var prod = checkedI128(w[j] * BigInt(v[r * f + j]), "dot product");
          dot = checkedI128(dot + prod, "dot product");
        }
        var pred = dot / S + w[f - 1];
        var err = pred - BigInt(v[r * f + f - 1]);
        var sq = checkedI128(err * err, "loss");
        loss = checkedI128(loss + sq, "loss");
        for (var k = 0; k < f - 1; k++) {
          var g = checkedI128(err * BigInt(v[r * f + k]), "gradient");
          grad[k] = checkedI128(grad[k] + g, "gradient");
        }
        grad[f - 1] = checkedI128(grad[f - 1] + checkedI128(err * S, "gradient"), "gradient"); // bias rides the constant-1.0 input quantised as S
        inBatch++;
        nRows++;
        if (inBatch >= o.minibatch) {
          apply(inBatch);
          inBatch = 0;
        }
      }
    }
    if (nRows === 0) throw new Error("no rows");
    if (inBatch > 0) apply(inBatch);
    if (o.l2Q16 !== 0) {
      for (var q = 0; q < f; q++) {
        var shrink = (BigInt(o.l2Q16) * w[q]) / 65536n;
        w[q] = clampI64(w[q] - shrink);
      }
    }
    var mean = loss / BigInt(nRows);
    // Divergence guard, mirrors the node (DIVERGENCE_LOSS_CAP = 1e12 on the
    // true loss): exploding hyperparameters are an error, never silent syrup.
    var lossTrue = Number(mean) / Math.pow(o.scale, 2);
    if (!(lossTrue <= 1e12)) throw new Error("diverged: true loss " + lossTrue + " exceeds 1e12");
    var lanes = w.map(function (x) {
      if (x < -2147483648n || x > 2147483647n) throw new Error("lane out of i32 range");
      return Number(x);
    });
    return { lanes: lanes, lossMeanQ: mean.toString(), nRows: nRows };
  }

  return {
    keccak256Bytes: keccak256Bytes,
    hex: hex,
    unhex: unhex,
    ascii: ascii,
    encodeWeights: encodeWeights,
    decodeWeights: decodeWeights,
    weightsDigest: weightsDigest,
    quantize: quantize,
    encodeNoopShard: encodeNoopShard,
    noopRowCommitment: noopRowCommitment,
    traceDigest: traceDigest,
    proofReference: proofReference,
    referenceStep: referenceStep,
  };
});
