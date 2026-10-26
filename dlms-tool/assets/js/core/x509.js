/* ============================================================
   DLMS 安全算法工作台 · X.509
   轻量 ASN.1 DER 解析、证书字段/扩展、签名与链式校验、公钥提取。
   不做信任锚、CRL、OCSP。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;
  var EC = DLMS.EC;

  var OID = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC"
  };

  var SIGNATURE_ALGS = {
    "1.2.840.10045.4.3.2": { name: "ecdsa-with-SHA256", keyType: "EC", hash: "SHA-256" },
    "1.2.840.10045.4.3.3": { name: "ecdsa-with-SHA384", keyType: "EC", hash: "SHA-384" },
    "1.2.840.10045.4.3.4": { name: "ecdsa-with-SHA512", keyType: "EC", hash: "SHA-512" },
    "1.2.840.10045.4.1": { name: "ecdsa-with-SHA1", keyType: "EC", hash: "SHA-1" },
    "1.2.840.113549.1.1.11": { name: "sha256WithRSAEncryption", keyType: "RSA", hash: "SHA-256" },
    "1.2.840.113549.1.1.12": { name: "sha384WithRSAEncryption", keyType: "RSA", hash: "SHA-384" },
    "1.2.840.113549.1.1.13": { name: "sha512WithRSAEncryption", keyType: "RSA", hash: "SHA-512" },
    "1.2.840.113549.1.1.5": { name: "sha1WithRSAEncryption", keyType: "RSA", hash: "SHA-1" }
  };

  var PUBLIC_KEY_ALGS = {
    "1.2.840.10045.2.1": { name: "id-ecPublicKey", keyType: "EC" },
    "1.2.840.113549.1.1.1": { name: "rsaEncryption", keyType: "RSA" }
  };

  var CURVES = {
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521"
  };

  function readTLV(bytes, offset, end) {
    offset = offset || 0;
    end = end == null ? bytes.length : end;
    if (offset + 2 > end) throw new Error("DER 被截断（偏移 " + offset + "）");
    var start = offset;
    var tag = bytes[offset++];
    var lenByte = bytes[offset++];
    var len;
    if (lenByte < 0x80) {
      len = lenByte;
    } else if (lenByte === 0x80) {
      throw new Error("不支持 DER 不定长（偏移 " + start + "）");
    } else {
      var n = lenByte & 0x7F;
      if (n > 4) throw new Error("DER 长度字段过长（偏移 " + start + "）");
      len = 0;
      for (var i = 0; i < n; i++) len = len * 256 + bytes[offset++];
    }
    var valueStart = offset;
    var valueEnd = offset + len;
    if (valueEnd > end) throw new Error("DER 长度超出范围（偏移 " + start + "，长度 " + len + "）");
    return {
      tag: tag,
      length: len,
      headerLen: offset - start,
      start: start,
      valueStart: valueStart,
      valueEnd: valueEnd,
      value: bytes.slice(valueStart, valueEnd),
      raw: bytes.slice(start, valueEnd)
    };
  }

  function children(bytes) {
    var out = [];
    var pos = 0;
    while (pos < bytes.length) {
      var t = readTLV(bytes, pos, bytes.length);
      out.push(t);
      pos = t.valueEnd;
    }
    return out;
  }

  function expect(tlv, tag, label) {
    if (tlv.tag !== tag) throw new Error((label || "DER 字段") + " 标签应为 0x" + tag.toString(16) + "，实际 0x" + tlv.tag.toString(16));
    return tlv;
  }

  function decodeOid(bytes) {
    if (!bytes.length) return "";
    var first = bytes[0];
    var parts = [Math.floor(first / 40), first % 40];
    var value = 0;
    for (var i = 1; i < bytes.length; i++) {
      value = value * 128 + (bytes[i] & 0x7F);
      if (!(bytes[i] & 0x80)) {
        parts.push(value);
        value = 0;
      }
    }
    return parts.join(".");
  }

  function decodeString(tag, bytes) {
    if (tag === 0x1E) {
      var s = "";
      for (var i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
      return s;
    }
    if (tag === 0x0C) return B.bytesToUtf8(bytes);
    if (tag === 0x13 || tag === 0x16 || tag === 0x1A) {
      var out = "";
      for (var j = 0; j < bytes.length; j++) out += String.fromCharCode(bytes[j]);
      return out;
    }
    if (tag === 0x14) {
      var latin = "";
      for (var k = 0; k < bytes.length; k++) latin += String.fromCharCode(bytes[k]);
      return latin;
    }
    return B.bytesToHex(bytes);
  }

  function decodeTime(tag, bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    var year, month, day, hour, minute, second = 0;
    var m;
    if (tag === 0x17) {
      m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/);
      if (!m) throw new Error("UTCTime 格式不支持：" + s);
      year = parseInt(m[1], 10);
      year = year >= 50 ? 1900 + year : 2000 + year;
      month = parseInt(m[2], 10); day = parseInt(m[3], 10);
      hour = parseInt(m[4], 10); minute = parseInt(m[5], 10);
      second = m[6] ? parseInt(m[6], 10) : 0;
    } else if (tag === 0x18) {
      m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/);
      if (!m) throw new Error("GeneralizedTime 格式不支持：" + s);
      year = parseInt(m[1], 10); month = parseInt(m[2], 10); day = parseInt(m[3], 10);
      hour = parseInt(m[4], 10); minute = parseInt(m[5], 10);
      second = m[6] ? parseInt(m[6], 10) : 0;
    } else {
      throw new Error("未知时间标签 0x" + tag.toString(16));
    }
    var date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
    return {
      iso: date.toISOString().replace(".000Z", "Z"),
      date: date,
      text: s
    };
  }

  function parseIntTlv(tlv) {
    expect(tlv, 0x02, "INTEGER");
    var v = 0n;
    for (var i = 0; i < tlv.value.length; i++) v = (v << 8n) | BigInt(tlv.value[i]);
    return v;
  }

  function parseName(tlv) {
    expect(tlv, 0x30, "Name");
    var parts = [];
    var sets = children(tlv.value);
    sets.forEach(function (set) {
      expect(set, 0x31, "RDN");
      children(set.value).forEach(function (atv) {
        expect(atv, 0x30, "AttributeTypeAndValue");
        var kids = children(atv.value);
        if (kids.length < 2) return;
        var oid = decodeOid(kids[0].value);
        var value = decodeString(kids[1].tag, kids[1].value);
        parts.push({ oid: oid, name: OID[oid] || oid, value: value });
      });
    });
    var text = parts.map(function (p) { return p.name + "=" + p.value; }).join(", ");
    var canonical = parts.map(function (p) { return p.oid + "=" + p.value.toLowerCase(); }).sort().join("|");
    return { text: text, parts: parts, canonical: canonical, raw: tlv.raw };
  }

  function parseAlgorithm(tlv) {
    expect(tlv, 0x30, "AlgorithmIdentifier");
    var kids = children(tlv.value);
    if (!kids.length) throw new Error("AlgorithmIdentifier 为空");
    var oid = decodeOid(kids[0].value);
    var sig = SIGNATURE_ALGS[oid];
    var pub = PUBLIC_KEY_ALGS[oid];
    var info = {
      oid: oid,
      name: sig ? sig.name : (pub ? pub.name : oid),
      keyType: sig ? sig.keyType : (pub ? pub.keyType : null),
      hash: sig ? sig.hash : null,
      params: kids[1] ? kids[1].raw : null
    };
    if (pub && pub.keyType === "EC" && kids[1] && kids[1].tag === 0x06) {
      info.curveOid = decodeOid(kids[1].value);
      info.curveName = CURVES[info.curveOid] || info.curveOid;
    }
    return info;
  }

  function bitStringBytes(tlv) {
    expect(tlv, 0x03, "BIT STRING");
    if (!tlv.value.length) return new Uint8Array(0);
    return tlv.value.slice(1);
  }

  function bitSet(bytes, index) {
    var byteIndex = Math.floor(index / 8);
    if (byteIndex >= bytes.length) return false;
    return (bytes[byteIndex] & (0x80 >> (index % 8))) !== 0;
  }

  var KEY_USAGE = [
    "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
    "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
  ];

  function parseGeneralNames(tlv) {
    expect(tlv, 0x30, "GeneralNames");
    var out = [];
    children(tlv.value).forEach(function (gn) {
      var tag = gn.tag;
      var text;
      if (tag === 0x82 || tag === 0x81 || tag === 0x86) {
        text = decodeString(0x16, gn.value);
      } else if (tag === 0x87) {
        text = Array.prototype.map.call(gn.value, function (b) { return b.toString(10); }).join(".");
      } else if (tag === 0xA4) {
        try {
          var nameTlv = readTLV(gn.value, 0, gn.value.length);
          text = parseName(nameTlv).text;
        } catch (e) { text = B.bytesToHex(gn.value); }
      } else {
        text = B.bytesToHex(gn.value);
      }
      var type = tag === 0x81 ? "rfc822Name" : tag === 0x82 ? "dNSName" : tag === 0x86 ? "URI" : tag === 0x87 ? "iPAddress" : tag === 0xA4 ? "directoryName" : "tag" + tag;
      out.push({ type: type, value: text });
    });
    return out;
  }

  function parseExtensions(tlv) {
    var out = {};
    if (!tlv) return out;
    var wrapper = expect(tlv, 0xA3, "Extensions");
    var listTlv = readTLV(wrapper.value, 0, wrapper.value.length);
    expect(listTlv, 0x30, "Extensions");
    children(listTlv.value).forEach(function (ext) {
      expect(ext, 0x30, "Extension");
      var kids = children(ext.value);
      if (kids.length < 2) return;
      var oid = decodeOid(kids[0].value);
      var idx = 1;
      var critical = false;
      if (kids[idx].tag === 0x01) {
        critical = kids[idx].value[0] !== 0;
        idx++;
      }
      var valueTlv = kids[idx];
      if (!valueTlv || valueTlv.tag !== 0x04) return;
      var der = valueTlv.value;
      var parsed = null;
      try {
        if (oid === "2.5.29.19") {
          var bc = readTLV(der, 0, der.length);
          var bkids = children(bc.value);
          var ca = false, pathLen = null, bi = 0;
          if (bkids[bi] && bkids[bi].tag === 0x01) { ca = bkids[bi].value[0] !== 0; bi++; }
          if (bkids[bi] && bkids[bi].tag === 0x02) { pathLen = Number(parseIntTlv(bkids[bi])); }
          parsed = { ca: ca, pathLen: pathLen };
        } else if (oid === "2.5.29.15") {
          var ku = readTLV(der, 0, der.length);
          var bits = bitStringBytes(ku);
          var usages = [];
          KEY_USAGE.forEach(function (name, i) { if (bitSet(bits, i)) usages.push(name); });
          parsed = { bits: B.bytesToHex(bits), usages: usages };
        } else if (oid === "2.5.29.37") {
          var eku = readTLV(der, 0, der.length);
          parsed = { usages: children(eku.value).map(function (t) { return decodeOid(t.value); }) };
        } else if (oid === "2.5.29.17") {
          var san = readTLV(der, 0, der.length);
          parsed = { names: parseGeneralNames(san) };
        } else if (oid === "2.5.29.14") {
          var ski = readTLV(der, 0, der.length);
          parsed = { hex: B.bytesToHexCompact(ski.value) };
        } else if (oid === "2.5.29.35") {
          var aki = readTLV(der, 0, der.length);
          var akids = children(aki.value);
          var keyId = null;
          akids.forEach(function (t) { if (t.tag === 0x80) keyId = B.bytesToHexCompact(t.value); });
          parsed = { keyIdentifier: keyId };
        }
      } catch (e) {
        parsed = { error: e.message, raw: B.bytesToHex(der) };
      }
      out[oid] = {
        oid: oid,
        critical: critical,
        raw: B.bytesToHex(der),
        value: parsed
      };
    });
    return out;
  }

  function parseCertificate(der) {
    if (!(der instanceof Uint8Array)) der = B.hexToBytes(der);
    var root = readTLV(der, 0, der.length);
    expect(root, 0x30, "Certificate");
    var rootKids = children(root.value);
    if (rootKids.length < 3) throw new Error("Certificate 结构不完整");
    var tbs = expect(rootKids[0], 0x30, "TBSCertificate");
    var outerSigAlg = parseAlgorithm(rootKids[1]);
    var sigBits = expect(rootKids[2], 0x03, "signatureValue");
    var signature = sigBits.value.slice(1);

    var kids = children(tbs.value);
    var i = 0;
    var version = 1;
    if (kids[i] && kids[i].tag === 0xA0) {
      var vTlv = readTLV(kids[i].value, 0, kids[i].value.length);
      version = Number(parseIntTlv(vTlv)) + 1;
      i++;
    }
    var serialTlv = kids[i++];
    var serial = parseIntTlv(serialTlv);
    var tbsSigAlg = parseAlgorithm(kids[i++]);
    var issuer = parseName(kids[i++]);
    var validityTlv = expect(kids[i++], 0x30, "Validity");
    var validityKids = children(validityTlv.value);
    var notBefore = decodeTime(validityKids[0].tag, validityKids[0].value);
    var notAfter = decodeTime(validityKids[1].tag, validityKids[1].value);
    var subject = parseName(kids[i++]);
    var spkiTlv = expect(kids[i++], 0x30, "SubjectPublicKeyInfo");
    var spkiKids = children(spkiTlv.value);
    var spkiAlg = parseAlgorithm(spkiKids[0]);
    var pubBits = bitStringBytes(spkiKids[1]);
    var extensions = {};
    for (; i < kids.length; i++) {
      if (kids[i].tag === 0xA3) extensions = parseExtensions(kids[i]);
    }

    var publicKeyBytes = pubBits;
    if (spkiAlg.keyType === "EC" && pubBits.length === 64) publicKeyBytes = B.concat(new Uint8Array([0x04]), pubBits);

    return {
      der: der,
      tbsDer: tbs.raw,
      version: version,
      serial: B.bytesToHexCompact(serialToBytes(serial)),
      serialDer: serialTlv.raw,
      serialBigInt: serial,
      signatureAlgorithm: outerSigAlg,
      tbsSignatureAlgorithm: tbsSigAlg,
      signature: signature,
      issuer: issuer,
      subject: subject,
      notBefore: notBefore,
      notAfter: notAfter,
      spki: {
        raw: spkiTlv.raw,
        algorithm: spkiAlg,
        curveOid: spkiAlg.curveOid,
        curveName: spkiAlg.curveName,
        publicKeyBytes: publicKeyBytes,
        publicKeyBits: pubBits
      },
      extensions: extensions
    };
  }

  function serialToBytes(v) {
    if (v === 0n) return new Uint8Array([0]);
    var hex = v.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    return B.hexToBytes(hex);
  }

  function parsePem(text) {
    var out = [];
    var re = /-----BEGIN ([^-]+)-----([\s\S]*?)-----END \1-----/g;
    var m;
    while ((m = re.exec(String(text)))) {
      var label = m[1].trim();
      var b64 = m[2].replace(/[^A-Za-z0-9+/=]/g, "");
      if (!b64) continue;
      out.push({ label: label, der: B.base64ToBytes(b64) });
    }
    if (!out.length) throw new Error("没有找到 PEM 块（需要 BEGIN/END 行）");
    return out;
  }

  function toPem(der, label) {
    var b64 = B.bytesToBase64(der);
    var lines = b64.match(/.{1,64}/g) || [b64];
    return "-----BEGIN " + (label || "CERTIFICATE") + "-----\n" + lines.join("\n") + "\n-----END " + (label || "CERTIFICATE") + "-----";
  }

  async function fingerprint(der, hash) {
    return DLMS.Hash.hash(hash || "SHA-256", der);
  }

  async function verifyCertificate(cert, issuerCert) {
    var sigAlg = cert.signatureAlgorithm;
    if (!sigAlg || !sigAlg.keyType) return { ok: false, reason: "不支持的签名算法：" + (sigAlg ? sigAlg.oid : "?") };
    try {
      if (sigAlg.keyType === "EC") {
        var curve = issuerCert.spki.curveName;
        if (!curve || !/^P-/.test(curve)) return { ok: false, reason: "签发者公钥曲线不支持：" + curve };
        var pub = await EC.importPublicKey({
          format: "raw",
          curve: curve,
          usage: "ECDSA",
          data: issuerCert.spki.publicKeyBytes
        });
        var rawSig = EC.derToRaw(cert.signature, curve);
        var ok = await EC.verify({ publicKey: pub, hash: sigAlg.hash, message: cert.tbsDer, signature: rawSig, curve: curve });
        return { ok: ok, reason: ok ? "" : "签名不匹配（tbsCertificate 或公钥不符）", algorithm: sigAlg.name };
      }
      if (sigAlg.keyType === "RSA") {
        var key = await global.crypto.subtle.importKey(
          "spki", issuerCert.spki.raw,
          { name: "RSASSA-PKCS1-v1_5", hash: sigAlg.hash },
          false, ["verify"]
        );
        var okRsa = await global.crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, cert.signature, cert.tbsDer);
        return { ok: okRsa, reason: okRsa ? "" : "RSA 签名不匹配", algorithm: sigAlg.name };
      }
      return { ok: false, reason: "不支持的签名算法：" + sigAlg.name };
    } catch (e) {
      return { ok: false, reason: e.message || String(e), algorithm: sigAlg.name };
    }
  }

  function checkValidity(cert, now) {
    var n = now ? (now instanceof Date ? now : new Date(now)) : new Date();
    if (n < cert.notBefore.date) return { ok: false, reason: "证书尚未生效（notBefore " + cert.notBefore.iso + "）" };
    if (n > cert.notAfter.date) return { ok: false, reason: "证书已过期（notAfter " + cert.notAfter.iso + "）" };
    return { ok: true, reason: "" };
  }

  function checkKeyUsage(cert, usage) {
    var ext = cert.extensions["2.5.29.15"];
    if (!ext || !ext.value || !ext.value.usages) return { ok: true, reason: "", note: "证书未声明 keyUsage" };
    var ok = ext.value.usages.indexOf(usage) >= 0;
    return { ok: ok, reason: ok ? "" : "keyUsage 不含 " + usage + "（实际：" + ext.value.usages.join(", ") + "）" };
  }

  function basicConstraints(cert) {
    var ext = cert.extensions["2.5.29.19"];
    return ext && ext.value ? ext.value : { ca: false, pathLen: null };
  }

  async function verifyChain(certs, now) {
    if (!certs || !certs.length) throw new Error("证书链为空");
    var links = [];
    var warnings = [];
    for (var i = 0; i < certs.length - 1; i++) {
      var cert = certs[i];
      var issuer = certs[i + 1];
      var nameOk = cert.issuer.canonical === issuer.subject.canonical;
      var sig = await verifyCertificate(cert, issuer);
      var val = checkValidity(cert, now);
      var ca = basicConstraints(issuer);
      if (!ca.ca) warnings.push("第 " + (i + 2) + " 张证书未声明 CA=TRUE");
      links.push({
        index: i,
        subject: cert.subject.text,
        issuer: issuer.subject.text,
        nameMatch: nameOk,
        signature: sig,
        validity: val,
        issuerCa: ca,
        ok: nameOk && sig.ok && val.ok
      });
    }
    var root = certs[certs.length - 1];
    var rootSig = await verifyCertificate(root, root);
    var rootVal = checkValidity(root, now);
    var rootSelf = root.subject.canonical === root.issuer.canonical;
    var rootLink = {
      index: certs.length - 1,
      subject: root.subject.text,
      issuer: root.issuer.text,
      nameMatch: rootSelf,
      signature: rootSig,
      validity: rootVal,
      issuerCa: basicConstraints(root),
      selfSigned: rootSelf,
      ok: rootSelf && rootSig.ok && rootVal.ok
    };
    var ok = links.every(function (l) { return l.ok; }) && rootLink.ok;
    return { ok: ok, links: links, root: rootLink, warnings: warnings };
  }

  function extractPublicKey(cert) {
    var raw = cert.spki.publicKeyBytes;
    if (raw.length && raw[0] === 0x04) raw = raw.slice(1);
    var curve = cert.spki.curveName;
    var jwk = null;
    if (/^P-/.test(curve || "") && (raw.length === 64 || raw.length === 96)) {
      var size = raw.length / 2;
      jwk = {
        kty: "EC",
        crv: curve,
        x: B.bytesToBase64Url(raw.slice(0, size)),
        y: B.bytesToBase64Url(raw.slice(size))
      };
    }
    return {
      rawXY: B.bytesToHex(raw),
      uncompressed: B.bytesToHex(B.concat(new Uint8Array([0x04]), raw)),
      spkiDer: cert.spki.raw,
      spkiPem: toPem(cert.spki.raw, "PUBLIC KEY"),
      jwk: jwk,
      curve: curve
    };
  }

  DLMS.X509 = {
    OID: OID,
    SIGNATURE_ALGS: SIGNATURE_ALGS,
    readTLV: readTLV,
    children: children,
    decodeOid: decodeOid,
    decodeString: decodeString,
    decodeTime: decodeTime,
    parseName: parseName,
    parseAlgorithm: parseAlgorithm,
    parseExtensions: parseExtensions,
    parseCertificate: parseCertificate,
    parsePem: parsePem,
    toPem: toPem,
    fingerprint: fingerprint,
    verifyCertificate: verifyCertificate,
    verifyChain: verifyChain,
    checkValidity: checkValidity,
    checkKeyUsage: checkKeyUsage,
    basicConstraints: basicConstraints,
    extractPublicKey: extractPublicKey
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.X509;
})(typeof globalThis !== "undefined" ? globalThis : this);
