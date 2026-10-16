/**
 * keccak-256 (Keccak-f[1600], pad10*1 domain 0x01, rate 1088).
 *
 * Ported from `web/assets/crypto.js` (same constants, same padding) so the
 * ShardStore addresses objects with the exact digest the chain pins
 * (`ethers.keccak256`, `node/src/fhe.rs`, `web/tests/equiv.mjs` — the latter
 * cross-checks this logic against ethers byte-for-byte, including the
 * 135/136/137/272 padding boundaries).
 *
 * Written out rather than vendored so this service stays dependency-free.
 * Standard vectors: keccak256("") =
 *   0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470,
 * keccak256("abc") =
 *   0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45.
 * NOTE: this is NOT NIST SHA3-256 (different padding); `node:crypto`
 * `sha3-256` gives a different digest and must not be used here.
 */

// Keccak-f round constants, (lo, hi) 32-bit pairs from the spec table.
const RC = [
  0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000,
  0x80008000, 0x80000000, 0x0000808b, 0x00000000, 0x80000001, 0x00000000,
  0x80008081, 0x80000000, 0x00008009, 0x80000000, 0x0000008a, 0x00000000,
  0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000,
  0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000,
  0x00008003, 0x80000000, 0x00008002, 0x80000000, 0x00000080, 0x80000000,
  0x0000800a, 0x00000000, 0x8000000a, 0x80000000, 0x80008081, 0x80000000,
  0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000,
];
const RHO = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];
// pi: lane j = x+5y moves to y+5*((2x+3y)%5) — the Keccak-f permutation.
const PI = [0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4];

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
  const C = new Array(10);
  const D = new Array(10);
  const B = new Array(50);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) {
      C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
      C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
    }
    // Theta: D[x] = C[x-1] XOR ROTL(C[x+1], 1), then A[x,y] ^= D[x].
    for (let x2 = 0; x2 < 5; x2++) {
      const t = rotl64(C[2 * ((x2 + 1) % 5)], C[2 * ((x2 + 1) % 5) + 1], 1);
      D[2 * x2] = (C[2 * ((x2 + 4) % 5)] ^ t[0]) >>> 0;
      D[2 * x2 + 1] = (C[2 * ((x2 + 4) % 5) + 1] ^ t[1]) >>> 0;
    }
    for (let i = 0; i < 50; i += 2) {
      s[i] = (s[i] ^ D[i % 10]) >>> 0;
      s[i + 1] = (s[i + 1] ^ D[(i % 10) + 1]) >>> 0;
    }
    for (let j = 0; j < 25; j++) {
      const src = 2 * j;
      const dst = 2 * PI[j];
      const r = rotl64(s[src], s[src + 1], RHO[j]);
      B[dst] = r[0];
      B[dst + 1] = r[1];
    }
    for (let k = 0; k < 25; k++) {
      const k2 = 2 * k;
      const k1 = 2 * ((k + 1) % 5 + 5 * Math.floor(k / 5));
      const k22 = 2 * ((k + 2) % 5 + 5 * Math.floor(k / 5));
      s[k2] = (B[k2] ^ (~B[k1] & B[k22])) >>> 0;
      s[k2 + 1] = (B[k2 + 1] ^ (~B[k1 + 1] & B[k22 + 1])) >>> 0;
    }
    s[0] = (s[0] ^ RC[2 * round]) >>> 0;
    s[1] = (s[1] ^ RC[2 * round + 1]) >>> 0;
  }
}

/** keccak-256 over bytes. Accepts Uint8Array/Buffer. Returns Uint8Array(32). */
export function keccak256Bytes(msg) {
  const rate = 136; // 1088 bits
  const s = new Array(50).fill(0);
  let off = 0;
  while (off < msg.length) {
    const block = Math.min(rate, msg.length - off);
    for (let i = 0; i < block; i++) {
      // lanes are little-endian: byte i is lane (i>>3), lane-byte (i&7).
      const lane = i >> 3, lb = i & 7;
      const w = 2 * lane + (lb >> 2);
      s[w] = (s[w] ^ (msg[off + i] << (8 * (lb & 3)))) >>> 0;
    }
    off += block;
    if (block === rate) keccakf(s);
  }
  // pad10*1 with domain 0x01: last byte shared when the message filled the block.
  const lastByte = rate - 1; // 135 → lane 16, lane-byte 7, hi word 33
  const wLast = 2 * (lastByte >> 3) + ((lastByte & 7) >> 2);
  if (msg.length % rate === rate - 1) {
    // 0x01 and 0x80 collide on the same byte — use combined 0x81.
    s[wLast] = (s[wLast] ^ (0x81 << (8 * (lastByte & 3)))) >>> 0;
    keccakf(s);
  } else {
    const padPos = msg.length % rate;
    const wPad = 2 * (padPos >> 3) + (((padPos & 7) >> 2));
    s[wPad] = (s[wPad] ^ (0x01 << (8 * (padPos & 3)))) >>> 0;
    s[wLast] = (s[wLast] ^ (0x80 << (8 * (lastByte & 3)))) >>> 0;
    keccakf(s);
  }
  const out = new Uint8Array(32);
  for (let b = 0; b < 32; b++) {
    const laneB = b >> 3, lbB = b & 7;
    out[b] = (s[2 * laneB + (lbB >> 2)] >>> (8 * (lbB & 3))) & 0xff;
  }
  return out;
}

/** keccak-256 over bytes as `0x`-hex. */
export function keccak256Hex(msg) {
  const out = keccak256Bytes(msg);
  let s = "";
  for (let i = 0; i < out.length; i++) s += (out[i] < 16 ? "0" : "") + out[i].toString(16);
  return "0x" + s;
}
