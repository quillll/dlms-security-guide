/* ============================================================
   DLMS 安全算法工作台 · 哈希
   SHA-1/256/384/512 走 WebCrypto；MD5 为纯 JS（HLS-3 兼容）。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;

  function md5(bytes) {
    var msg = bytes instanceof Uint8Array ? bytes : B.hexToBytes(bytes);
    var len = msg.length;
    var bitLenLo = (len * 8) >>> 0;
    var bitLenHi = Math.floor(len / 0x20000000) >>> 0; // len*8 / 2^32
    var padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
    padded.set(msg);
    padded[len] = 0x80;
    var dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bitLenLo, true);
    dv.setUint32(padded.length - 4, bitLenHi, true);

    var a0 = 0x67452301, b0 = 0xEFCDAB89, c0 = 0x98BADCFE, d0 = 0x10325476;
    var S = [
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];
    var K = new Uint32Array(64);
    for (var i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;

    for (var off = 0; off < padded.length; off += 64) {
      var X = new Uint32Array(16);
      for (var j = 0; j < 16; j++) X[j] = dv.getUint32(off + j * 4, true);
      var A = a0, Bv = b0, C = c0, D = d0;
      for (var k = 0; k < 64; k++) {
        var F, g;
        if (k < 16) { F = (Bv & C) | (~Bv & D); g = k; }
        else if (k < 32) { F = (D & Bv) | (~D & C); g = (5 * k + 1) & 15; }
        else if (k < 48) { F = Bv ^ C ^ D; g = (3 * k + 5) & 15; }
        else { F = C ^ (Bv | ~D); g = (7 * k) & 15; }
        F = (F + A + K[k] + X[g]) >>> 0;
        A = D;
        D = C;
        C = Bv;
        Bv = (Bv + ((F << S[k]) | (F >>> (32 - S[k])))) >>> 0;
      }
      a0 = (a0 + A) >>> 0;
      b0 = (b0 + Bv) >>> 0;
      c0 = (c0 + C) >>> 0;
      d0 = (d0 + D) >>> 0;
    }

    var out = new Uint8Array(16);
    var odv = new DataView(out.buffer);
    odv.setUint32(0, a0, true);
    odv.setUint32(4, b0, true);
    odv.setUint32(8, c0, true);
    odv.setUint32(12, d0, true);
    return out;
  }

  function subtle() {
    if (!global.crypto || !global.crypto.subtle) throw new Error("当前浏览器不支持 WebCrypto（请使用现代浏览器或 localhost）");
    return global.crypto.subtle;
  }

  function normalizeAlgo(algo) {
    var a = String(algo || "SHA-256").toUpperCase().replace("-", "");
    if (a === "SHA1") return "SHA-1";
    if (a === "SHA256") return "SHA-256";
    if (a === "SHA384") return "SHA-384";
    if (a === "SHA512") return "SHA-512";
    if (a === "MD5") return "MD5";
    throw new Error("不支持的哈希算法：" + algo);
  }

  async function hash(algo, data) {
    var a = normalizeAlgo(algo);
    var bytes = data instanceof Uint8Array ? data : B.utf8ToBytes(data || "");
    if (a === "MD5") return md5(bytes);
    var buf = await subtle().digest(a, bytes);
    return new Uint8Array(buf);
  }

  async function hmac(algo, key, data) {
    var a = normalizeAlgo(algo);
    if (a === "MD5") throw new Error("HMAC-MD5 未提供；DLMS 不使用它");
    var keyBytes = key instanceof Uint8Array ? key : B.hexToBytes(key);
    var dataBytes = data instanceof Uint8Array ? data : B.utf8ToBytes(data || "");
    var k = await subtle().importKey("raw", keyBytes, { name: "HMAC", hash: a }, false, ["sign"]);
    var sig = await subtle().sign("HMAC", k, dataBytes);
    return new Uint8Array(sig);
  }

  DLMS.Hash = {
    md5: md5,
    hash: hash,
    hmac: hmac,
    normalizeAlgo: normalizeAlgo
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.Hash;
})(typeof globalThis !== "undefined" ? globalThis : this);
