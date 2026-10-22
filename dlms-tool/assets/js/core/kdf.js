/* ============================================================
   DLMS 安全算法工作台 · KDF
   NIST SP 800-56A Concatenation KDF（SHA-256 / SHA-384）。
   注意：DLMS 的 KDF 不是 AES-CMAC。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;
  var H = DLMS.Hash;

  function normalizeHash(name) {
    var v = String(name || "SHA-256").toUpperCase().replace("-", "");
    if (v === "SHA256") return "SHA-256";
    if (v === "SHA384") return "SHA-384";
    throw new Error("DLMS KDF 只支持 SHA-256（Suite 1）或 SHA-384（Suite 2）");
  }

  function algorithmId(suite, purpose) {
    var s = Number(suite);
    var p = String(purpose || "GUEK").toUpperCase();
    var last;
    if (p === "GUEK" || p === "GAK" || p === "ENCRYPTION" || p === "AUTHENTICATION") last = "00";
    else if (p === "KEK" || p === "WRAP") last = "02";
    else throw new Error("未知 AlgID 用途：" + purpose);
    if (s === 1) return B.hexToBytes("608574050803" + last);
    if (s === 2) return B.hexToBytes("608574050803" + (Number(last) + 1));
    throw new Error("KDF 只适用于 Suite 1 / 2；Suite 0 没有 ECDH/KDF");
  }

  function buildOtherInfo(opts) {
    var algId = opts.algId instanceof Uint8Array ? opts.algId : B.hexToBytes(opts.algId);
    if (!algId || algId.length !== 7) throw new Error("AlgID 必须是 7 B");
    var partyU = opts.partyU instanceof Uint8Array ? opts.partyU : B.hexToBytes(opts.partyU);
    var partyV = opts.partyV instanceof Uint8Array ? opts.partyV : B.hexToBytes(opts.partyV);
    if (partyU.length !== 8 || partyV.length !== 8) throw new Error("PartyU / PartyV 必须是 8 B system title");
    var parts = [algId, partyU];
    if (opts.nonceU && opts.nonceU.length) parts.push(new Uint8Array([opts.nonceU.length]), opts.nonceU);
    parts.push(partyV);
    return B.concat.apply(B, parts);
  }

  async function concatKdf(opts) {
    var z = opts.z instanceof Uint8Array ? opts.z : B.hexToBytes(opts.z);
    if (!z.length) throw new Error("缺少共享秘密 Z");
    var hashName = normalizeHash(opts.hash);
    var keydatalen = Number(opts.keydatalenBits || (hashName === "SHA-384" ? 256 : 128));
    if (keydatalen <= 0 || keydatalen % 8 !== 0) throw new Error("keydatalen 必须为正的 8 的倍数（bit）");
    var otherInfo = opts.otherInfo instanceof Uint8Array ? opts.otherInfo : buildOtherInfo(opts);
    var needed = Math.ceil(keydatalen / 8);
    var blocks = [];
    var chunks = [];
    var i = 1;
    var total = 0;
    while (total < needed) {
      if (i > 0xFFFFFFFF) throw new Error("KDF 计数器溢出");
      var input = B.concat(B.u32be(i), z, otherInfo);
      var digest = await H.hash(hashName, input);
      blocks.push({ counter: i, digest: digest, input: input });
      chunks.push(digest);
      total += digest.length;
      i++;
    }
    var all = B.concat.apply(B, chunks);
    return {
      key: all.slice(0, needed),
      full: all,
      blocks: blocks,
      hash: hashName,
      keydatalenBits: keydatalen,
      otherInfo: otherInfo
    };
  }

  DLMS.KDF = {
    concatKdf: concatKdf,
    buildOtherInfo: buildOtherInfo,
    algorithmId: algorithmId,
    normalizeHash: normalizeHash
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.KDF;
})(typeof globalThis !== "undefined" ? globalThis : this);
