/* ============================================================
   DLMS 安全算法工作台 · AES-GCM / GMAC
   WebCrypto AES-CTR 提供 AES 分组运算；GHASH 用 BigInt 实现，
   因此可以校验 DLMS 的 96-bit（12 字节）tag。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;

  var ZERO16 = new Uint8Array(16);
  var R = 0xE1000000000000000000000000000000n;

  function subtle() {
    if (!global.crypto || !global.crypto.subtle) throw new Error("当前浏览器不支持 WebCrypto（请使用现代浏览器或 localhost）");
    return global.crypto.subtle;
  }

  function assertKey(key) {
    if (!(key instanceof Uint8Array) || (key.length !== 16 && key.length !== 32)) {
      throw new Error("AES 密钥必须是 16 B 或 32 B，当前 " + (key ? key.length : 0) + " B");
    }
  }

  function assertIv(iv) {
    if (!(iv instanceof Uint8Array) || iv.length !== 12) {
      throw new Error("GCM IV 必须是 12 B（DLMS 为 System Title 8 B ‖ IC 4 B），当前 " + (iv ? iv.length : 0) + " B");
    }
  }

  async function aesCtr(key, counterBlock, data) {
    if (!data.length) return new Uint8Array(0);
    var k = await subtle().importKey("raw", key, { name: "AES-CTR" }, false, ["encrypt", "decrypt"]);
    var buf = await subtle().encrypt({ name: "AES-CTR", counter: counterBlock, length: 32 }, k, data);
    return new Uint8Array(buf);
  }

  async function aesBlock(key, block) {
    if (block.length !== 16) throw new Error("AES 分组必须是 16 B");
    return aesCtr(key, block, new Uint8Array(16));
  }

  function inc32(block) {
    var out = new Uint8Array(block);
    var n = B.readU32be(out, 12);
    n = (n + 1) >>> 0;
    out[12] = (n >>> 24) & 255;
    out[13] = (n >>> 16) & 255;
    out[14] = (n >>> 8) & 255;
    out[15] = n & 255;
    return out;
  }

  function gfMul(x, y) {
    var z = 0n;
    var v = y;
    for (var i = 0; i < 128; i++) {
      if ((x >> BigInt(127 - i)) & 1n) z ^= v;
      if (v & 1n) v = (v >> 1n) ^ R;
      else v >>= 1n;
    }
    return z;
  }

  function blockToBigInt(bytes, offset) {
    var hex = "";
    for (var i = 0; i < 16; i++) {
      var b = bytes[offset + i] || 0;
      hex += (b < 16 ? "0" : "") + b.toString(16);
    }
    return BigInt("0x" + hex);
  }

  function padBlocks(bytes) {
    var out = [];
    for (var i = 0; i < bytes.length; i += 16) {
      var block = new Uint8Array(16);
      block.set(bytes.subarray(i, Math.min(i + 16, bytes.length)));
      out.push(block);
    }
    return out;
  }

  function ghash(hBytes, aad, ciphertext) {
    var H = B.bytesToBigInt(hBytes);
    var y = 0n;
    var blocks = padBlocks(aad);
    for (var i = 0; i < blocks.length; i++) y = gfMul(y ^ blockToBigInt(blocks[i], 0), H);
    blocks = padBlocks(ciphertext);
    for (var j = 0; j < blocks.length; j++) y = gfMul(y ^ blockToBigInt(blocks[j], 0), H);
    var aadBits = BigInt(aad.length) * 8n;
    var ctBits = BigInt(ciphertext.length) * 8n;
    var lenBlock = (aadBits << 64n) | ctBits;
    y = gfMul(y ^ lenBlock, H);
    return B.bigIntToBytes(y, 16);
  }

  function j0For(iv) {
    assertIv(iv);
    return B.concat(iv, new Uint8Array([0, 0, 0, 1]));
  }

  function normalizeTagLength(n) {
    n = n == null ? 12 : Number(n);
    if (!(n >= 4 && n <= 16)) throw new Error("tag 长度必须在 4..16 B 之间");
    return n;
  }

  async function gcmEncrypt(opts) {
    var key = opts.key, iv = opts.iv;
    var aad = opts.aad || new Uint8Array(0);
    var plaintext = opts.plaintext || new Uint8Array(0);
    var tagLength = normalizeTagLength(opts.tagLength);
    assertKey(key); assertIv(iv);
    if (plaintext.length > 1024 * 1024) throw new Error("单次输入超过 1 MB，已拒绝");

    var H = await aesBlock(key, ZERO16);
    var j0 = j0For(iv);
    var ciphertext = await aesCtr(key, inc32(j0), plaintext);
    var s = ghash(H, aad, ciphertext);
    var ej0 = await aesBlock(key, j0);
    var tagFull = B.xor(ej0, s);
    return {
      ciphertext: ciphertext,
      tag: tagFull.slice(0, tagLength),
      tagFull: tagFull,
      h: H,
      j0: j0,
      iv: iv,
      aad: aad
    };
  }

  async function gcmDecrypt(opts) {
    var key = opts.key, iv = opts.iv;
    var aad = opts.aad || new Uint8Array(0);
    var ciphertext = opts.ciphertext || new Uint8Array(0);
    var tag = opts.tag;
    var tagLength = normalizeTagLength(opts.tagLength);
    assertKey(key); assertIv(iv);
    if (!tag) throw new Error("缺少认证 tag；A=1 的报文必须提供 12 B tag");

    var H = await aesBlock(key, ZERO16);
    var j0 = j0For(iv);
    var s = ghash(H, aad, ciphertext);
    var ej0 = await aesBlock(key, j0);
    var tagFull = B.xor(ej0, s);
    var expected = tagFull.slice(0, tagLength);
    if (!B.constantTimeEqual(expected, tag)) {
      var err = new Error("认证失败：tag 不匹配");
      err.code = "AUTH_FAILED";
      err.expected = expected;
      err.actual = tag;
      throw err;
    }
    var plaintext = await aesCtr(key, inc32(j0), ciphertext);
    return { plaintext: plaintext, tagFull: tagFull, valid: true };
  }

  async function gcmDecryptNoVerify(opts) {
    var key = opts.key, iv = opts.iv;
    var ciphertext = opts.ciphertext || new Uint8Array(0);
    assertKey(key); assertIv(iv);
    var j0 = j0For(iv);
    var plaintext = await aesCtr(key, inc32(j0), ciphertext);
    return { plaintext: plaintext, valid: null };
  }

  async function gmac(opts) {
    var result = await gcmEncrypt({
      key: opts.key,
      iv: opts.iv,
      aad: opts.aad,
      plaintext: new Uint8Array(0),
      tagLength: opts.tagLength
    });
    return { tag: result.tag, tagFull: result.tagFull, h: result.h, j0: result.j0 };
  }

  DLMS.GCM = {
    aesCtr: aesCtr,
    aesBlock: aesBlock,
    inc32: inc32,
    gfMul: gfMul,
    ghash: ghash,
    j0For: j0For,
    gcmEncrypt: gcmEncrypt,
    gcmDecrypt: gcmDecrypt,
    gcmDecryptNoVerify: gcmDecryptNoVerify,
    gmac: gmac
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.GCM;
})(typeof globalThis !== "undefined" ? globalThis : this);
