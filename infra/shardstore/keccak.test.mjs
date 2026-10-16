/**
 * keccak.mjs — дифференциальные доказательства против оригинала.
 *
 * `web/assets/crypto.js` проверен побайтово против ethers (`node
 * web/tests/equiv.mjs`, §4, включая границы паддинга 135/136/137/272).
 * Этот файл доказывает, что порт даёт те же байты на всех длинах вокруг
 * границ блоков, плюс фиксирует векторы из спецификации Keccak.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { keccak256Bytes, keccak256Hex } from "./keccak.mjs";

const require = createRequire(import.meta.url);
const WebCrypto = require("../../web/assets/crypto.js");

const VECTORS = [
  ["", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"],
  ["abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"],
];

describe("keccak.mjs", () => {
  for (const [input, hex] of VECTORS) {
    it(`matches the Keccak spec vector for ${JSON.stringify(input)}`, () => {
      assert.equal(keccak256Hex(Buffer.from(input)), "0x" + hex);
    });
  }

  it("matches web/assets/crypto.js on every length around the block boundaries", () => {
    const lengths = [0, 1, 2, 31, 32, 33, 63, 64, 65, 119, 120, 134, 135, 136, 137, 138, 200, 271, 272, 273, 300];
    for (const n of lengths) {
      const msg = new Uint8Array(n);
      for (let i = 0; i < n; i++) msg[i] = (i * 31 + 7) & 0xff;
      assert.deepEqual(
        Buffer.from(keccak256Bytes(msg)),
        Buffer.from(WebCrypto.keccak256Bytes(msg)),
        `length ${n}`
      );
    }
  });

  it("differs from NIST SHA3-256 (wrong padding must never pass silently)", async () => {
    const { createHash } = await import("node:crypto");
    const msg = Buffer.from("hello-shard");
    const sha3 = "0x" + createHash("sha3-256").update(msg).digest("hex");
    assert.notEqual(keccak256Hex(msg), sha3);
  });
});
