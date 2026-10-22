/* ============================================================
   DLMS 安全算法工作台 · 字节工具
   零依赖；浏览器与 Node(>=18) 通用。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};

  function HexError(message, position) {
    var e = new Error(message);
    e.name = "HexError";
    e.code = "HEX_INVALID";
    e.position = position;
    return e;
  }

  function hexToBytes(input) {
    if (input == null) return new Uint8Array(0);
    if (input instanceof Uint8Array) return new Uint8Array(input);
    if (Array.isArray(input)) return new Uint8Array(input);
    var s = String(input).replace(/0x/gi, "").replace(/[\s:\-_,]/g, "");
    if (!s) return new Uint8Array(0);
    if (!/^[0-9a-fA-F]+$/.test(s)) {
      var bad = s.search(/[^0-9a-fA-F]/);
      throw HexError("HEX 中有非法字符“" + s.charAt(bad) + "”（第 " + (bad + 1) + " 个字符）", bad);
    }
    if (s.length % 2 !== 0) {
      throw HexError("HEX 字符数为奇数（" + s.length + "），最后一个字节只有半个字节", s.length - 1);
    }
    var out = new Uint8Array(s.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(bytes, sep) {
    if (sep === undefined) sep = " ";
    var out = [];
    for (var i = 0; i < bytes.length; i++) out.push((bytes[i] < 16 ? "0" : "") + bytes[i].toString(16).toUpperCase());
    return out.join(sep);
  }

  function bytesToHexCompact(bytes) {
    return bytesToHex(bytes, "");
  }

  function utf8ToBytes(str) {
    if (global.TextEncoder) return new TextEncoder().encode(String(str));
    var utf8 = unescape(encodeURIComponent(String(str)));
    var out = new Uint8Array(utf8.length);
    for (var i = 0; i < utf8.length; i++) out[i] = utf8.charCodeAt(i);
    return out;
  }

  function bytesToUtf8(bytes) {
    if (global.TextDecoder) return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    try { return decodeURIComponent(escape(s)); } catch (e) { return s; }
  }

  function bytesToBase64(bytes) {
    if (typeof global.btoa === "function") {
      var s = "";
      for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return global.btoa(s);
    }
    if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
    throw new Error("当前环境没有 Base64 编码器");
  }

  function base64ToBytes(str) {
    var s = String(str).replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/");
    if (!s) return new Uint8Array(0);
    while (s.length % 4) s += "=";
    if (typeof global.atob === "function") {
      var bin = global.atob(s);
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(s, "base64"));
    throw new Error("当前环境没有 Base64 解码器");
  }

  function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64UrlToBytes(str) {
    var s = String(str).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return base64ToBytes(s);
  }

  function concat() {
    var total = 0, i;
    for (i = 0; i < arguments.length; i++) total += arguments[i] ? arguments[i].length : 0;
    var out = new Uint8Array(total), pos = 0;
    for (i = 0; i < arguments.length; i++) {
      if (!arguments[i]) continue;
      out.set(arguments[i], pos);
      pos += arguments[i].length;
    }
    return out;
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function constantTimeEqual(a, b) {
    return bytesEqual(a, b);
  }

  function u32be(n) {
    n = Number(n) >>> 0;
    return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  }

  function readU32be(bytes, offset) {
    offset = offset || 0;
    return (((bytes[offset] << 24) >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0;
  }

  function u64be(n) {
    var hi = Math.floor(n / 0x100000000);
    var lo = n >>> 0;
    return concat(u32be(hi), u32be(lo));
  }

  function parseUint32(input) {
    var s = String(input == null ? "" : input).trim();
    if (!s) throw new Error("请输入 4 字节计数器（HEX 或十进制）");
    var n;
    if (/^0x/i.test(s)) n = parseInt(s.slice(2), 16);
    else if (/^[0-9]+$/.test(s)) n = parseInt(s, 10);
    else if (/^[0-9a-fA-F]{8}$/.test(s)) n = parseInt(s, 16);
    else throw new Error("计数器格式不对：请输入 8 位 HEX（如 01234567）或十进制整数");
    if (!isFinite(n) || n < 0 || n > 0xFFFFFFFF) throw new Error("计数器必须在 0 .. 4294967295 之间");
    return n >>> 0;
  }

  function bigIntToBytes(value, length) {
    var hex = value.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    while (length && hex.length < length * 2) hex = "00" + hex;
    if (length && hex.length > length * 2) hex = hex.slice(hex.length - length * 2);
    return hexToBytes(hex);
  }

  function bytesToBigInt(bytes) {
    if (!bytes.length) return 0n;
    return BigInt("0x" + bytesToHexCompact(bytes));
  }

  function randomBytes(n) {
    var out = new Uint8Array(n);
    if (global.crypto && global.crypto.getRandomValues) global.crypto.getRandomValues(out);
    else if (typeof require === "function") {
      var nodeCrypto = require("crypto");
      var buf = nodeCrypto.randomBytes(n);
      out.set(buf);
    } else throw new Error("当前环境没有安全随机源");
    return out;
  }

  function isPrintableByte(b) {
    return b >= 0x20 && b <= 0x7E;
  }

  function bytesToAscii(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += isPrintableByte(bytes[i]) ? String.fromCharCode(bytes[i]) : "·";
    return s;
  }

  function isProbablyPrintable(bytes) {
    if (!bytes.length) return false;
    var printable = 0;
    for (var i = 0; i < bytes.length; i++) if (isPrintableByte(bytes[i]) || bytes[i] === 0x09 || bytes[i] === 0x0A || bytes[i] === 0x0D) printable++;
    return printable / bytes.length > 0.85;
  }

  function xor(a, b) {
    var n = Math.min(a.length, b.length);
    var out = new Uint8Array(n);
    for (var i = 0; i < n; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  function zero(bytes) {
    if (bytes && bytes.fill) bytes.fill(0);
  }

  function formatBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / 1024 / 1024).toFixed(2) + " MB";
  }

  DLMS.Bytes = {
    HexError: HexError,
    hexToBytes: hexToBytes,
    bytesToHex: bytesToHex,
    bytesToHexCompact: bytesToHexCompact,
    utf8ToBytes: utf8ToBytes,
    bytesToUtf8: bytesToUtf8,
    bytesToBase64: bytesToBase64,
    base64ToBytes: base64ToBytes,
    bytesToBase64Url: bytesToBase64Url,
    base64UrlToBytes: base64UrlToBytes,
    concat: concat,
    bytesEqual: bytesEqual,
    constantTimeEqual: constantTimeEqual,
    u32be: u32be,
    readU32be: readU32be,
    u64be: u64be,
    parseUint32: parseUint32,
    bigIntToBytes: bigIntToBytes,
    bytesToBigInt: bytesToBigInt,
    randomBytes: randomBytes,
    bytesToAscii: bytesToAscii,
    isPrintableByte: isPrintableByte,
    isProbablyPrintable: isProbablyPrintable,
    xor: xor,
    zero: zero,
    formatBytes: formatBytes
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.Bytes;
})(typeof globalThis !== "undefined" ? globalThis : this);
