/* ============================================================
   DLMS 安全算法工作台 · DLMS 安全层
   SC / 封装 / 解析 / GMAC / HLS / HDLC FCS。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;
  var G = DLMS.GCM;
  var H = DLMS.Hash;
  var CRC = DLMS.CRC;

  var TAG_NAMES = {
    0x60: "AARQ", 0x61: "AARE", 0x62: "RLRQ", 0x63: "RLRE",
    0xC0: "GET-REQUEST", 0xC1: "SET-REQUEST", 0xC2: "ACTION-REQUEST",
    0xC3: "GET-RESPONSE", 0xC4: "SET-RESPONSE", 0xC5: "ACTION-RESPONSE",
    0xC6: "DATA-NOTIFICATION", 0xC7: "EVENT-NOTIFICATION-REQUEST",
    0xDB: "GENERAL-GLO-CIPHERING", 0xDC: "GENERAL-DED-CIPHERING",
    0xDD: "GENERAL-CIPHERING", 0xDF: "GENERAL-SIGNING"
  };

  function tagName(tag) {
    if (TAG_NAMES[tag]) return TAG_NAMES[tag];
    if (tag >= 0xC8 && tag <= 0xCF) return "GLO-" + (TAG_NAMES[tag - 8] || "0x" + tag.toString(16));
    if (tag >= 0xD0 && tag <= 0xD7) return "DED-" + (TAG_NAMES[tag - 16] || "0x" + tag.toString(16));
    return "0x" + tag.toString(16).toUpperCase().padStart(2, "0");
  }

  function buildSC(opts) {
    var suite = Number(opts.suite || 0);
    if (suite < 0 || suite > 15) throw new Error("Suite 必须在 0..15 之间");
    var b = suite & 0x0F;
    if (opts.auth) b |= 0x10;
    if (opts.enc) b |= 0x20;
    if (opts.keySet) b |= 0x40;
    if (opts.compression) b |= 0x80;
    return b;
  }

  function parseSC(b) {
    return {
      byte: b,
      suite: b & 0x0F,
      auth: !!(b & 0x10),
      enc: !!(b & 0x20),
      keySet: !!(b & 0x40),
      compression: !!(b & 0x80)
    };
  }

  function scText(b) {
    var s = parseSC(b);
    var parts = [];
    parts.push("Suite " + s.suite);
    parts.push(s.auth ? "A=1" : "A=0");
    parts.push(s.enc ? "E=1" : "E=0");
    if (s.keySet) parts.push("Key_Set=1");
    if (s.compression) parts.push("Compression=1");
    return parts.join(" · ");
  }

  function encodeLength(n) {
    if (n < 0) throw new Error("长度不能为负");
    if (n < 0x80) return new Uint8Array([n]);
    if (n <= 0xFF) return new Uint8Array([0x81, n]);
    if (n <= 0xFFFF) return new Uint8Array([0x82, (n >>> 8) & 255, n & 255]);
    if (n <= 0xFFFFFF) return new Uint8Array([0x83, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
    throw new Error("长度太大");
  }

  function decodeLength(bytes, offset) {
    offset = offset || 0;
    if (offset >= bytes.length) throw new Error("长度字段被截断");
    var b = bytes[offset];
    if (b < 0x80) return { length: b, bytes: 1, next: offset + 1 };
    if (b === 0x80) throw new Error("不支持 0x80 不定长");
    var n = b & 0x7F;
    if (n < 1 || n > 3) throw new Error("长度字段字节数不支持：" + n);
    if (offset + 1 + n > bytes.length) throw new Error("长度字段被截断");
    var len = 0;
    for (var i = 0; i < n; i++) len = len * 256 + bytes[offset + 1 + i];
    return { length: len, bytes: 1 + n, next: offset + 1 + n };
  }

  function writeOctetString(bytes) {
    return B.concat(encodeLength(bytes.length), bytes);
  }

  function readOctetString(bytes, offset) {
    var li = decodeLength(bytes, offset);
    var start = li.next;
    var end = start + li.length;
    if (end > bytes.length) throw new Error("OCTET STRING 长度超出范围（偏移 " + offset + "）");
    return {
      value: bytes.slice(start, end),
      length: li.length,
      lengthBytes: li.bytes,
      start: start,
      end: end,
      next: end,
      offset: offset
    };
  }

  var CERT_ENTITY_LABEL = { 0: "server", 1: "client", 2: "certification authority", 3: "other" };
  var CERT_TYPE_LABEL = { 0: "digital signature", 1: "key agreement", 2: "TLS", 3: "other" };

  /* Security setup（class_id 64）方法 8 remove_certificate(data) 的 data 参数：
     certificate_identification（蓝皮书 §4.4.7.3.7 / §4.4.7.3.8）。
     A-XDR 里 CHOICE 分支不加标签字节，靠 certificate_identification_type 区分；
     与 Gurux C# / Java 的编码一致。 */
  function encodeCertificateIdentification(opts) {
    opts = opts || {};
    var byEntity = opts.mode === "entity" || opts.mode === 0;
    var parts = [], fields = [], pos = 0;
    function push(name, bytes, note, color) {
      parts.push(bytes);
      fields.push({
        name: name, offset: pos, length: bytes.length,
        value: B.bytesToHexCompact(bytes), note: note || "", color: color || "plain"
      });
      pos += bytes.length;
    }
    push("structure", new Uint8Array([0x02, 0x02]), "certificate_identification：2 个元素", "tag");
    if (byEntity) {
      var st = opts.systemTitle;
      if (!(st instanceof Uint8Array) || st.length !== 8) throw new Error("System Title 必须是 8 字节（16 位 HEX）");
      var entity = Number(opts.entity);
      var certType = Number(opts.certType);
      if (!(entity >= 0 && entity <= 3)) throw new Error("certificate_entity 只能是 0..3");
      if (!(certType >= 0 && certType <= 3)) throw new Error("certificate_type 只能是 0..3");
      push("identification_type", new Uint8Array([0x16, 0x00]), "enum 0 = by_entity", "ct");
      push("options", new Uint8Array([0x02, 0x03]), "certificate_identification_by_entity：3 个元素", "tag");
      push("certificate_entity", new Uint8Array([0x16, entity]), "enum " + entity + " = " + (CERT_ENTITY_LABEL[entity] || "?"), "ct");
      push("certificate_type", new Uint8Array([0x16, certType]), "enum " + certType + " = " + (CERT_TYPE_LABEL[certType] || "?"), "ct");
      push("system_title", B.concat(new Uint8Array([0x09]), encodeLength(st.length), st), "octet-string " + st.length + " B", "plain");
    } else {
      var serialDer = opts.serialDer;
      var issuerDer = opts.issuerDer;
      if (!serialDer || !serialDer.length) throw new Error("缺少序列号的 DER INTEGER TLV");
      if (!issuerDer || !issuerDer.length) throw new Error("缺少签发者 Name 的 DER TLV");
      push("identification_type", new Uint8Array([0x16, 0x01]), "enum 1 = by_serial", "ct");
      push("options", new Uint8Array([0x02, 0x02]), "certificate_identification_by_serial：2 个元素", "tag");
      push("serial_number", B.concat(new Uint8Array([0x09]), encodeLength(serialDer.length), serialDer), "octet-string 里放 serial 的 DER INTEGER TLV（不是裸序号）", "plain");
      push("issuer", B.concat(new Uint8Array([0x09]), encodeLength(issuerDer.length), issuerDer), "octet-string 里放 issuer 的 DER Name TLV", "plain");
    }
    return { bytes: B.concat.apply(B, parts), fields: fields };
  }

  function ivFor(st, ic) {
    if (!st || st.length !== 8) throw new Error("System Title 必须是 8 B");
    if (!ic || ic.length !== 4) throw new Error("IC 必须是 4 B");
    return B.concat(st, ic);
  }

  function aadFor(sc, ak, content, auth, enc) {
    if (!auth) return new Uint8Array(0);
    if (!ak || !ak.length) throw new Error("A=1 时必须提供 AK");
    if (enc) return B.concat(new Uint8Array([sc]), ak);
    return B.concat(new Uint8Array([sc]), ak, content);
  }

  function normalizeKey(key, label) {
    if (!(key instanceof Uint8Array)) key = B.hexToBytes(key);
    if (key.length !== 16 && key.length !== 32) throw new Error((label || "密钥") + " 必须是 16 B 或 32 B，当前 " + key.length + " B");
    return key;
  }

  function inferTags(innerTag, family) {
    if (innerTag == null) return { inner: null, outer: null };
    if (innerTag < 0xC0 || innerTag > 0xC7) throw new Error("内层 APDU 标签应为 C0–C7，当前 0x" + innerTag.toString(16));
    if (family === "service-glo") return { inner: innerTag, outer: innerTag + 8 };
    if (family === "service-ded") return { inner: innerTag, outer: innerTag + 16 };
    return { inner: innerTag, outer: null };
  }

  async function protect(opts) {
    var plaintext = opts.plaintext instanceof Uint8Array ? opts.plaintext : B.hexToBytes(opts.plaintext);
    var st = opts.st instanceof Uint8Array ? opts.st : B.hexToBytes(opts.st);
    var ic = opts.ic instanceof Uint8Array ? opts.ic : B.hexToBytes(opts.ic);
    var ek = normalizeKey(opts.ek, "EK");
    var ak = opts.ak ? normalizeKey(opts.ak, "AK") : null;
    var suite = Number(opts.suite == null ? 0 : opts.suite);
    var auth = opts.auth !== false;
    var enc = opts.enc !== false;
    var family = opts.family || "service-glo";
    if (!plaintext.length) throw new Error("明文 APDU 不能为空");
    if (!auth && !enc) throw new Error("A=0 且 E=0 没有安全保护；请选择仅认证 / 仅加密 / 认证+加密");
    if (auth && !ak) throw new Error("A=1 时必须提供 AK");

    var sc = buildSC({ suite: suite, auth: auth, enc: enc, keySet: opts.keySet, compression: opts.compression });
    var iv = ivFor(st, ic);
    var aad = aadFor(sc, ak, plaintext, auth, enc);
    var result;
    if (auth) {
      result = await G.gcmEncrypt({ key: ek, iv: iv, aad: aad, plaintext: enc ? plaintext : new Uint8Array(0), tagLength: 12 });
    } else {
      result = await G.gcmEncrypt({ key: ek, iv: iv, aad: new Uint8Array(0), plaintext: plaintext, tagLength: 12 });
    }
    var ciphertext = result.ciphertext;
    var carried = enc ? ciphertext : plaintext;
    var tag = auth ? result.tag : new Uint8Array(0);
    var sh = B.concat(new Uint8Array([sc]), ic);
    var payload = B.concat(sh, carried, tag);
    var inner = null, outer = null, apdu;

    if (family === "service-glo" || family === "service-ded") {
      var inferred = inferTags(plaintext[0], family);
      inner = opts.innerTag != null ? Number(opts.innerTag) : inferred.inner;
      outer = opts.outerTag != null ? Number(opts.outerTag) : inferred.outer;
      if (inner == null || outer == null) throw new Error("无法从明文首字节推断 APDU 标签，请手动指定外层标签");
      apdu = B.concat(new Uint8Array([outer]), encodeLength(payload.length), payload);
    } else if (family === "general-glo" || family === "general-ded") {
      var outerTag = family === "general-glo" ? 0xDB : 0xDC;
      apdu = B.concat(new Uint8Array([outerTag]), writeOctetString(st), writeOctetString(payload));
    } else if (family === "general-ciphering") {
      throw new Error("general-ciphering 的构建在 v1 暂未开放；v1 支持解析。");
    } else {
      throw new Error("未知封装家族：" + family);
    }

    var parsed = parse(apdu);
    return {
      apdu: apdu,
      sc: sc,
      scInfo: parseSC(sc),
      ek: ek,
      st: st,
      ic: ic,
      iv: iv,
      aad: aad,
      ciphertext: carried,
      gcmCiphertext: ciphertext,
      tag: tag,
      tagFull: result.tagFull,
      sh: sh,
      payload: payload,
      family: family,
      innerTag: inner,
      outerTag: outer,
      parsed: parsed
    };
  }

  function parsePayload(payload, baseOffset) {
    baseOffset = baseOffset || 0;
    if (payload.length < 5) throw new Error("安全载荷不足 5 B（SC + IC）");
    var sc = payload[0];
    var info = parseSC(sc);
    var ic = payload.slice(1, 5);
    var rest = payload.slice(5);
    var tag = null;
    var ciphertext = rest;
    if (info.auth) {
      if (rest.length < 12) throw new Error("A=1 但载荷不足 12 B tag");
      tag = rest.slice(rest.length - 12);
      ciphertext = rest.slice(0, rest.length - 12);
    }
    return {
      sc: sc, scInfo: info, ic: ic, ciphertext: ciphertext, tag: tag,
      fields: [
        { name: "SC", offset: baseOffset, length: 1, value: B.bytesToHex(new Uint8Array([sc])), note: scText(sc), color: "sc" },
        { name: "IC", offset: baseOffset + 1, length: 4, value: B.bytesToHex(ic), note: "调用计数器", color: "ic" },
        { name: info.auth ? "密文/内容" : "密文", offset: baseOffset + 5, length: ciphertext.length, value: B.bytesToHex(ciphertext), note: info.enc ? "AES-GCM 密文" : "明文内容（进 AAD）", color: info.enc ? "ct" : "plain" },
        info.auth ? { name: "认证 tag", offset: baseOffset + 5 + ciphertext.length, length: 12, value: B.bytesToHex(tag), note: "GCM 16 B tag 的前 12 B", color: "auth" } : null
      ].filter(Boolean)
    };
  }

  function parse(apdu) {
    if (!(apdu instanceof Uint8Array)) apdu = B.hexToBytes(apdu);
    if (!apdu.length) throw new Error("报文为空");
    var tag = apdu[0];
    var fields = [];

    if (tag >= 0xC8 && tag <= 0xCF || tag >= 0xD0 && tag <= 0xD7) {
      var li = decodeLength(apdu, 1);
      var bodyStart = li.next;
      var bodyEnd = bodyStart + li.length;
      if (bodyEnd > apdu.length) throw new Error("Len=" + li.length + " 超出报文长度");
      var body = apdu.slice(bodyStart, bodyEnd);
      var pp = parsePayload(body, bodyStart);
      fields.push({ name: "APDU tag", offset: 0, length: 1, value: B.bytesToHex(new Uint8Array([tag])), note: tagName(tag), color: "tag" });
      fields.push({ name: "Len", offset: 1, length: li.bytes, value: B.bytesToHex(apdu.slice(1, 1 + li.bytes)), note: li.length + " B，从 SC 起算", color: "len" });
      fields = fields.concat(pp.fields);
      return {
        family: tag <= 0xCF ? "service-glo" : "service-ded",
        tag: tag, tagName: tagName(tag), length: li.length, lengthOk: bodyEnd === apdu.length,
        sc: pp.sc, scInfo: pp.scInfo, ic: pp.ic, ciphertext: pp.ciphertext, tagBytes: pp.tag,
        fields: fields, apdu: apdu
      };
    }

    if (tag === 0xDB || tag === 0xDC) {
      var stOs = readOctetString(apdu, 1);
      var contentOs = readOctetString(apdu, stOs.next);
      var pp2 = parsePayload(contentOs.value, contentOs.start);
      fields.push({ name: "tag", offset: 0, length: 1, value: B.bytesToHex(new Uint8Array([tag])), note: tag === 0xDB ? "general-glo" : "general-ded", color: "tag" });
      fields.push({ name: "system-title", offset: 1, length: stOs.lengthBytes + stOs.length, value: B.bytesToHex(stOs.value), note: "发送方 ST", color: "ic" });
      fields.push({ name: "ciphered-content", offset: stOs.next, length: contentOs.lengthBytes + contentOs.length, value: "", note: contentOs.length + " B", color: "len" });
      fields = fields.concat(pp2.fields);
      return {
        family: tag === 0xDB ? "general-glo" : "general-ded",
        tag: tag, tagName: tagName(tag), systemTitle: stOs.value,
        sc: pp2.sc, scInfo: pp2.scInfo, ic: pp2.ic, ciphertext: pp2.ciphertext, tagBytes: pp2.tag,
        fields: fields, lengthOk: contentOs.next === apdu.length, apdu: apdu
      };
    }

    if (tag === 0xDD) {
      var tx = readOctetString(apdu, 1);
      var org = readOctetString(apdu, tx.next);
      var rec = readOctetString(apdu, org.next);
      var dt = readOctetString(apdu, rec.next);
      var other = readOctetString(apdu, dt.next);
      var pos = other.next;
      var keyInfo = null;
      if (apdu[pos] === 0x01) {
        var presentAt = pos;
        pos++;
        var choice = apdu[pos++];
        var parts = [];
        if (choice === 0) {
          var kid = readOctetString(apdu, pos); parts.push({ name: "key-id", value: B.bytesToHex(kid.value), next: kid.next }); pos = kid.next;
        } else if (choice === 1) {
          var kekId = readOctetString(apdu, pos); parts.push({ name: "kek-id", value: B.bytesToHex(kekId.value), next: kekId.next }); pos = kekId.next;
          var wrapped = readOctetString(apdu, pos); parts.push({ name: "key-ciphered-data", value: B.bytesToHex(wrapped.value), next: wrapped.next }); pos = wrapped.next;
        } else if (choice === 2) {
          var kp = readOctetString(apdu, pos); parts.push({ name: "key-parameters", value: B.bytesToHex(kp.value), next: kp.next }); pos = kp.next;
          var agreed = readOctetString(apdu, pos); parts.push({ name: "key-ciphered-data", value: B.bytesToHex(agreed.value), next: agreed.next }); pos = agreed.next;
        } else {
          throw new Error("未知 key-info CHOICE：" + choice);
        }
        keyInfo = { present: true, choice: choice, choiceName: choice === 0 ? "identified" : choice === 1 ? "wrapped" : "agreed", parts: parts, offset: presentAt };
      }
      var content = readOctetString(apdu, pos);
      var pp3 = parsePayload(content.value, content.start);
      fields.push({ name: "tag", offset: 0, length: 1, value: "DD", note: "general-ciphering", color: "tag" });
      fields.push({ name: "transaction-id", offset: 1, length: tx.lengthBytes + tx.length, value: B.bytesToHex(tx.value), note: tx.length + " B", color: "len" });
      fields.push({ name: "originator ST", offset: tx.next, length: org.lengthBytes + org.length, value: B.bytesToHex(org.value), note: "发送方", color: "ic" });
      fields.push({ name: "recipient ST", offset: org.next, length: rec.lengthBytes + rec.length, value: B.bytesToHex(rec.value), note: "接收方", color: "ic" });
      fields.push({ name: "date-time", offset: rec.next, length: dt.lengthBytes + dt.length, value: B.bytesToHex(dt.value), note: dt.length ? "已携带" : "空", color: "len" });
      fields.push({ name: "other-info", offset: dt.next, length: other.lengthBytes + other.length, value: B.bytesToHex(other.value), note: other.length ? "已携带" : "空", color: "len" });
      if (keyInfo) fields.push({ name: "key-info", offset: keyInfo.offset, length: pos - keyInfo.offset, value: keyInfo.choiceName, note: "密钥来源", color: "sc" });
      fields.push({ name: "ciphered-content", offset: pos, length: content.lengthBytes + content.length, value: "", note: content.length + " B", color: "len" });
      fields = fields.concat(pp3.fields);
      return {
        family: "general-ciphering", tag: tag, tagName: tagName(tag),
        transactionId: tx.value, originatorSystemTitle: org.value, recipientSystemTitle: rec.value,
        dateTime: dt.value, otherInfo: other.value, keyInfo: keyInfo,
        sc: pp3.sc, scInfo: pp3.scInfo, ic: pp3.ic, ciphertext: pp3.ciphertext, tagBytes: pp3.tag,
        fields: fields, lengthOk: content.next === apdu.length, apdu: apdu
      };
    }

    if (tag === 0xDF) {
      var tx2 = readOctetString(apdu, 1);
      var org2 = readOctetString(apdu, tx2.next);
      var rec2 = readOctetString(apdu, org2.next);
      var dt2 = readOctetString(apdu, rec2.next);
      var other2 = readOctetString(apdu, dt2.next);
      var content2 = readOctetString(apdu, other2.next);
      var sig2 = readOctetString(apdu, content2.next);
      fields.push({ name: "tag", offset: 0, length: 1, value: "DF", note: "general-signing", color: "tag" });
      fields.push({ name: "transaction-id", offset: 1, length: tx2.lengthBytes + tx2.length, value: B.bytesToHex(tx2.value), note: tx2.length + " B", color: "len" });
      fields.push({ name: "originator ST", offset: tx2.next, length: org2.lengthBytes + org2.length, value: B.bytesToHex(org2.value), note: "发送方", color: "ic" });
      fields.push({ name: "recipient ST", offset: org2.next, length: rec2.lengthBytes + rec2.length, value: B.bytesToHex(rec2.value), note: "接收方", color: "ic" });
      fields.push({ name: "content", offset: other2.next, length: content2.lengthBytes + content2.length, value: B.bytesToHex(content2.value), note: content2.length + " B", color: "plain" });
      fields.push({ name: "signature", offset: content2.next, length: sig2.lengthBytes + sig2.length, value: B.bytesToHex(sig2.value), note: sig2.length + " B", color: "auth" });
      return {
        family: "general-signing", tag: tag, tagName: tagName(tag),
        transactionId: tx2.value, originatorSystemTitle: org2.value, recipientSystemTitle: rec2.value,
        dateTime: dt2.value, otherInfo: other2.value, content: content2.value, signature: sig2.value,
        fields: fields, lengthOk: sig2.next === apdu.length, apdu: apdu
      };
    }

    return {
      family: "plain", tag: tag, tagName: tagName(tag), plain: apdu,
      fields: [{ name: "APDU tag", offset: 0, length: 1, value: B.bytesToHex(new Uint8Array([tag])), note: tagName(tag), color: "tag" }],
      lengthOk: true, apdu: apdu
    };
  }

  async function decrypt(opts) {
    var apdu = opts.apdu instanceof Uint8Array ? opts.apdu : B.hexToBytes(opts.apdu);
    var parsed = opts.parsed || parse(apdu);
    if (parsed.family === "plain") throw new Error("这是明文 APDU，没有安全层可解");
    if (parsed.family === "general-signing") throw new Error("general-signing 只签名不加密；请用签名验证");
    var ek = normalizeKey(opts.ek, "EK");
    var ak = opts.ak ? normalizeKey(opts.ak, "AK") : null;
    var st = opts.st instanceof Uint8Array ? opts.st : B.hexToBytes(opts.st || "");
    if (parsed.family === "general-glo" || parsed.family === "general-ded") st = parsed.systemTitle;
    if (parsed.family === "general-ciphering") st = parsed.originatorSystemTitle;
    if (!st || st.length !== 8) throw new Error("解密需要发送方 System Title（8 B）");
    var sc = parsed.sc;
    var info = parsed.scInfo;
    var iv = ivFor(st, parsed.ic);
    var aad = aadFor(sc, ak, parsed.ciphertext, info.auth, info.enc);
    var result;
    if (info.auth) {
      result = await G.gcmDecrypt({ key: ek, iv: iv, aad: aad, ciphertext: parsed.ciphertext, tag: parsed.tagBytes, tagLength: 12 });
    } else {
      result = await G.gcmDecryptNoVerify({ key: ek, iv: iv, ciphertext: parsed.ciphertext });
    }
    var plaintext = (info.auth && !info.enc) ? parsed.ciphertext : result.plaintext;
    return {
      plaintext: plaintext,
      parsed: parsed,
      sc: sc,
      ic: parsed.ic,
      iv: iv,
      aad: aad,
      verified: info.auth ? true : null,
      warning: info.auth ? "" : "仅加密：没有完整性保护，无法证明报文未被改动"
    };
  }

  async function gmacPayload(opts) {
    var ek = normalizeKey(opts.ek, "EK");
    var ak = normalizeKey(opts.ak, "AK");
    var st = opts.st instanceof Uint8Array ? opts.st : B.hexToBytes(opts.st);
    var ic = opts.ic instanceof Uint8Array ? opts.ic : B.hexToBytes(opts.ic);
    var content = opts.content instanceof Uint8Array ? opts.content : B.hexToBytes(opts.content);
    var suite = Number(opts.suite == null ? 0 : opts.suite);
    var sc = buildSC({ suite: suite, auth: true, enc: false });
    var iv = ivFor(st, ic);
    var aad = B.concat(new Uint8Array([sc]), ak, content);
    var r = await G.gmac({ key: ek, iv: iv, aad: aad, tagLength: 12 });
    return { sc: sc, iv: iv, aad: aad, tag: r.tag, packet: B.concat(new Uint8Array([sc]), ic, r.tag) };
  }

  async function hls3(opts) {
    var challenge = opts.challenge instanceof Uint8Array ? opts.challenge : B.hexToBytes(opts.challenge);
    var secret = opts.secret instanceof Uint8Array ? opts.secret : B.hexToBytes(opts.secret);
    return H.md5(B.concat(challenge, secret));
  }
  async function hls4(opts) {
    var challenge = opts.challenge instanceof Uint8Array ? opts.challenge : B.hexToBytes(opts.challenge);
    var secret = opts.secret instanceof Uint8Array ? opts.secret : B.hexToBytes(opts.secret);
    return H.hash("SHA-1", B.concat(challenge, secret));
  }
  async function hls5(opts) {
    var ek = normalizeKey(opts.ek, "EK");
    var ak = normalizeKey(opts.ak, "AK");
    var st = opts.st instanceof Uint8Array ? opts.st : B.hexToBytes(opts.st);
    var ic = opts.ic instanceof Uint8Array ? opts.ic : B.hexToBytes(opts.ic);
    var challenge = opts.challenge instanceof Uint8Array ? opts.challenge : B.hexToBytes(opts.challenge);
    var suite = Number(opts.suite == null ? 0 : opts.suite);
    var sc = buildSC({ suite: suite, auth: true, enc: false });
    var iv = ivFor(st, ic);
    var aad = B.concat(new Uint8Array([sc]), ak, challenge);
    var r = await G.gmac({ key: ek, iv: iv, aad: aad, tagLength: 12 });
    return { sc: sc, ic: ic, iv: iv, aad: aad, tag: r.tag, output: B.concat(new Uint8Array([sc]), ic, r.tag) };
  }
  async function hls6(opts) {
    var secret = opts.secret instanceof Uint8Array ? opts.secret : B.hexToBytes(opts.secret);
    var ownST = opts.ownST instanceof Uint8Array ? opts.ownST : B.hexToBytes(opts.ownST);
    var peerST = opts.peerST instanceof Uint8Array ? opts.peerST : B.hexToBytes(opts.peerST);
    var ownCh = opts.ownChallenge instanceof Uint8Array ? opts.ownChallenge : B.hexToBytes(opts.ownChallenge);
    var peerCh = opts.peerChallenge instanceof Uint8Array ? opts.peerChallenge : B.hexToBytes(opts.peerChallenge);
    return H.hash("SHA-256", B.concat(secret, ownST, peerST, ownCh, peerCh));
  }
  function hls7Message(opts) {
    var ownST = opts.ownST instanceof Uint8Array ? opts.ownST : B.hexToBytes(opts.ownST);
    var peerST = opts.peerST instanceof Uint8Array ? opts.peerST : B.hexToBytes(opts.peerST);
    var ownCh = opts.ownChallenge instanceof Uint8Array ? opts.ownChallenge : B.hexToBytes(opts.ownChallenge);
    var peerCh = opts.peerChallenge instanceof Uint8Array ? opts.peerChallenge : B.hexToBytes(opts.peerChallenge);
    return B.concat(ownST, peerST, ownCh, peerCh);
  }
  async function hls7(opts) {
    var msg = hls7Message(opts);
    var sig = await DLMS.EC.sign({ privateKey: opts.privateKey, hash: opts.hash || "SHA-256", message: msg });
    return { message: msg, signature: sig };
  }

  function parseHdlcFrame(frame) {
    var f = frame instanceof Uint8Array ? frame : B.hexToBytes(frame);
    if (f.length < 12) throw new Error("HDLC 帧太短");
    var start = 0, end = f.length;
    if (f[0] === 0x7E) start = 1;
    if (f[end - 1] === 0x7E) end--;
    var body = f.slice(start, end);
    var unescaped = [];
    for (var i = 0; i < body.length; i++) {
      if (body[i] === 0x7D && i + 1 < body.length) {
        unescaped.push(body[i + 1] ^ 0x20);
        i++;
      } else unescaped.push(body[i]);
    }
    var raw = new Uint8Array(unescaped);
    if (raw.length < 4) throw new Error("HDLC 帧太短");
    var withoutFcs = raw.slice(0, raw.length - 2);
    var fcsValue = CRC.crc16(CRC.CRC16.X25, withoutFcs);
    var fcsOnWire = raw[raw.length - 2] | (raw[raw.length - 1] << 8);
    var fcsOk = fcsValue === fcsOnWire;
    var apdu = null;
    if (withoutFcs.length >= 10 && (withoutFcs[0] === 0xA0 || withoutFcs[0] === 0xA8) && withoutFcs[7] === 0xE6 && withoutFcs[8] === 0xE6 && withoutFcs[9] === 0x00) {
      apdu = withoutFcs.slice(10);
    } else {
      apdu = withoutFcs.slice(3);
    }
    return { type: "HDLC", fcsOk: fcsOk, fcsValue: fcsValue, fcsOnWire: fcsOnWire, apdu: apdu, raw: raw, withoutFcs: withoutFcs };
  }

  function parseWrapperFrame(frame) {
    var f = frame instanceof Uint8Array ? frame : B.hexToBytes(frame);
    if (f.length < 8) throw new Error("wrapper 帧太短");
    var len = (f[6] << 8) | f[7];
    var apdu = f.slice(8, 8 + len);
    return { type: "WRAPPER", apdu: apdu, declaredLength: len, lengthOk: 8 + len === f.length, raw: f };
  }

  function parseAnyFrame(frame) {
    var f = frame instanceof Uint8Array ? frame : B.hexToBytes(frame);
    if (f[0] === 0x7E) return parseHdlcFrame(f);
    if (f.length >= 8 && f[0] === 0x00 && f[1] === 0x01) return parseWrapperFrame(f);
    return { type: "APDU", apdu: f, raw: f };
  }

  DLMS.DLMS = {
    TAG_NAMES: TAG_NAMES,
    tagName: tagName,
    buildSC: buildSC,
    parseSC: parseSC,
    scText: scText,
    encodeLength: encodeLength,
    decodeLength: decodeLength,
    readOctetString: readOctetString,
    writeOctetString: writeOctetString,
    encodeCertificateIdentification: encodeCertificateIdentification,
    ivFor: ivFor,
    aadFor: aadFor,
    protect: protect,
    parse: parse,
    decrypt: decrypt,
    gmacPayload: gmacPayload,
    hls3: hls3,
    hls4: hls4,
    hls5: hls5,
    hls6: hls6,
    hls7: hls7,
    hls7Message: hls7Message,
    parseHdlcFrame: parseHdlcFrame,
    parseWrapperFrame: parseWrapperFrame,
    parseAnyFrame: parseAnyFrame
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.DLMS;
})(typeof globalThis !== "undefined" ? globalThis : this);
