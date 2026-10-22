/* ============================================================
   DLMS 安全算法工作台 · AES Key Wrap（RFC 3394）
   优先使用 WebCrypto AES-KW；失败时给出明确错误。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;

  function subtle() {
    if (!global.crypto || !global.crypto.subtle) throw new Error("当前浏览器不支持 WebCrypto");
    return global.crypto.subtle;
  }

  function checkKek(kek) {
    if (!(kek instanceof Uint8Array) || (kek.length !== 16 && kek.length !== 32)) {
      throw new Error("KEK 必须是 16 B 或 32 B，当前 " + (kek ? kek.length : 0) + " B");
    }
  }

  function checkKey(key) {
    if (!(key instanceof Uint8Array) || key.length < 16 || key.length % 8 !== 0) {
      throw new Error("被包装的密钥必须 ≥16 B 且为 8 B 的整数倍，当前 " + (key ? key.length : 0) + " B");
    }
  }

  async function wrap(kek, key) {
    checkKek(kek); checkKey(key);
    try {
      var kekKey = await subtle().importKey("raw", kek, { name: "AES-KW" }, false, ["wrapKey"]);
      var target = await subtle().importKey("raw", key, { name: "AES-GCM" }, true, ["encrypt"]);
      var wrapped = await subtle().wrapKey("raw", target, kekKey, "AES-KW");
      return new Uint8Array(wrapped);
    } catch (e) {
      throw new Error("AES-KW 包装失败：" + (e && e.message ? e.message : e));
    }
  }

  async function unwrap(kek, wrapped) {
    checkKek(kek);
    if (!(wrapped instanceof Uint8Array) || wrapped.length < 24 || wrapped.length % 8 !== 0) {
      throw new Error("AES-KW 密文长度不合法（应为 24/32/40 B…），当前 " + (wrapped ? wrapped.length : 0) + " B");
    }
    try {
      var kekKey = await subtle().importKey("raw", kek, { name: "AES-KW" }, false, ["unwrapKey"]);
      var target = await subtle().unwrapKey("raw", wrapped, kekKey, "AES-KW", { name: "AES-GCM" }, true, ["encrypt"]);
      var raw = await subtle().exportKey("raw", target);
      return new Uint8Array(raw);
    } catch (e) {
      var err = new Error("AES-KW 解包失败：KEK 不对，或密文被改动");
      err.code = "KW_UNWRAP_FAILED";
      throw err;
    }
  }

  DLMS.AESKW = { wrap: wrap, unwrap: unwrap };
  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.AESKW;
})(typeof globalThis !== "undefined" ? globalThis : this);
