/* ============================================================
   DLMS 安全算法工作台 · X.509 证书签发
   生成 DLMS/COSEM 风格的 Root-CA / Sub-CA / 终端证书。
   零依赖；浏览器与 Node(>=18) 通用。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;
  var EC = DLMS.EC;
  var H = DLMS.Hash;
  var X509 = DLMS.X509;

  var OID = {
    CN: "2.5.4.3",
    C: "2.5.4.6",
    O: "2.5.4.10",
    OU: "2.5.4.11"
  };

  var CURVE_OID = {
    "P-256": "1.2.840.10045.3.1.7",
    "P-384": "1.3.132.0.34"
  };

  var SIG_OID = {
    "P-256": "1.2.840.10045.4.3.2",
    "P-384": "1.2.840.10045.4.3.3"
  };

  var SIG_NAME = {
    "P-256": "ecdsa-with-SHA256",
    "P-384": "ecdsa-with-SHA384"
  };

  var HASH = {
    "P-256": "SHA-256",
    "P-384": "SHA-384"
  };

  var EKU = {
    server: "1.3.6.1.5.5.7.3.1",
    client: "1.3.6.1.5.5.7.3.2"
  };

  function asciiBytes(s) {
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
    return out;
  }

  function lengthBytes(n) {
    if (n < 0x80) return new Uint8Array([n]);
    var bytes = [];
    while (n > 0) { bytes.unshift(n & 0xff); n = Math.floor(n / 256); }
    return new Uint8Array([0x80 | bytes.length].concat(bytes));
  }

  function tlv(tag, value) {
    var v = value instanceof Uint8Array ? value : new Uint8Array(value || []);
    return B.concat(new Uint8Array([tag]), lengthBytes(v.length), v);
  }

  function seq() {
    return tlv(0x30, B.concat.apply(null, Array.prototype.slice.call(arguments)));
  }

  function set() {
    return tlv(0x31, B.concat.apply(null, Array.prototype.slice.call(arguments)));
  }

  function bool(v) {
    return tlv(0x01, new Uint8Array([v ? 0xFF : 0x00]));
  }

  function integerFromBytes(bytes) {
    var i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    var v = bytes.slice(i);
    if (v[0] & 0x80) v = B.concat(new Uint8Array([0]), v);
    return tlv(0x02, v);
  }

  function integerFromNumber(n) {
    var hex = Math.max(0, Math.floor(n)).toString(16);
    if (hex.length % 2) hex = "0" + hex;
    return integerFromBytes(B.hexToBytes(hex));
  }

  function encodeOid(text) {
    var parts = String(text).split(".").map(function (x) { return parseInt(x, 10); });
    var out = [40 * parts[0] + parts[1]];
    for (var i = 2; i < parts.length; i++) {
      var v = parts[i];
      var tmp = [v & 0x7f];
      while (v >= 0x80) { v = Math.floor(v / 0x80); tmp.unshift((v & 0x7f) | 0x80); }
      out = out.concat(tmp);
    }
    return tlv(0x06, new Uint8Array(out));
  }

  function stringTlv(tag, value) {
    return tlv(tag, tag === 0x13 ? asciiBytes(value) : B.utf8ToBytes(value));
  }

  function encodeName(attrs) {
    var order = [
      ["C", OID.C, 0x13],
      ["O", OID.O, 0x0C],
      ["OU", OID.OU, 0x0C],
      ["CN", OID.CN, 0x0C]
    ];
    var rdns = [];
    order.forEach(function (item) {
      var value = attrs[item[0]];
      if (value == null || value === "") return;
      rdns.push(set(seq(encodeOid(item[1]), stringTlv(item[2], String(value)))));
    });
    if (!rdns.length) throw new Error("证书主题至少需要一个 CN");
    return seq.apply(null, rdns);
  }

  function two(n) { return n < 10 ? "0" + n : String(n); }

  function timeTlv(date) {
    var y = date.getUTCFullYear();
    var base = String(y).padStart(4, "0") + two(date.getUTCMonth() + 1) + two(date.getUTCDate()) +
      two(date.getUTCHours()) + two(date.getUTCMinutes()) + two(date.getUTCSeconds()) + "Z";
    if (y >= 1950 && y <= 2049) return tlv(0x17, asciiBytes(base.slice(2)));
    return tlv(0x18, asciiBytes(base));
  }

  function bitString(bytes) {
    return tlv(0x03, B.concat(new Uint8Array([0]), bytes));
  }

  function keyUsageBits(bits) {
    var max = Math.max.apply(null, bits);
    var len = Math.floor(max / 8) + 1;
    var out = new Uint8Array(len);
    bits.forEach(function (bit) { out[Math.floor(bit / 8)] |= 0x80 >> (bit % 8); });
    return tlv(0x03, B.concat(new Uint8Array([len * 8 - 1 - max]), out));
  }

  function extension(oid, critical, value) {
    var parts = [encodeOid(oid)];
    if (critical) parts.push(bool(true));
    parts.push(tlv(0x04, value));
    return seq.apply(null, parts);
  }

  function buildExtensions(opts, ski, aki) {
    var ext = [];
    if (opts.isCA) {
      var bcParts = [bool(true)];
      if (opts.pathLen != null) bcParts.push(integerFromNumber(opts.pathLen));
      ext.push(extension("2.5.29.19", true, seq.apply(null, bcParts)));
    }
    ext.push(extension("2.5.29.15", true, keyUsageBits(opts.keyUsageBits)));
    ext.push(extension("2.5.29.14", false, tlv(0x04, ski)));
    if (aki) ext.push(extension("2.5.29.35", false, seq(tlv(0x80, aki))));
    if (opts.policyOid) ext.push(extension("2.5.29.32", false, seq(seq(encodeOid(opts.policyOid)))));
    if (opts.ekuOid) ext.push(extension("2.5.29.37", false, seq(encodeOid(opts.ekuOid))));
    return ext;
  }

  function serialBytes() {
    var s = B.randomBytes(16);
    s[0] &= 0x7f;
    if (!s.some(function (b) { return b !== 0; })) s[s.length - 1] = 1;
    return s;
  }

  function parseCsr(der) {
    var root = X509.readTLV(der, 0, der.length);
    if (root.tag !== 0x30) throw new Error("CSR 顶层必须是 SEQUENCE");
    var parts = X509.children(root.value);
    if (parts.length < 3) throw new Error("CSR 结构不完整");
    var cri = parts[0];
    var criParts = X509.children(cri.value);
    if (criParts.length < 3) throw new Error("CertificationRequestInfo 结构不完整");
    var subject = criParts[1];
    var spki = criParts[2];
    var spkiParts = X509.children(spki.value);
    if (spkiParts.length < 2) throw new Error("CSR 公钥结构不完整");
    var keyAlg = X509.parseAlgorithm(spkiParts[0]);
    if (keyAlg.keyType !== "EC" || !keyAlg.curveName) throw new Error("CSR 公钥不是受支持的 EC 曲线");
    var bits = spkiParts[1];
    if (bits.tag !== 0x03) throw new Error("CSR 公钥不是 BIT STRING");
    var sigAlg = X509.parseAlgorithm(parts[1]);
    var sigBits = parts[2];
    if (sigBits.tag !== 0x03) throw new Error("CSR 签名不是 BIT STRING");
    return {
      subjectRaw: subject.raw,
      subject: X509.parseName(subject),
      spkiRaw: spki.raw,
      publicKeyBits: bits.value.slice(1),
      curve: keyAlg.curveName,
      signature: sigBits.value.slice(1),
      signatureHash: sigAlg.hash || EC.hashForCurve(keyAlg.curveName),
      criRaw: cri.raw
    };
  }

  async function buildCertificate(input) {
    var role = input.role || "leaf";
    var curve = input.curve || "P-384";
    if (!CURVE_OID[curve]) throw new Error("只支持 P-256 / P-384");
    var isCA = role === "root" || role === "sub";
    var ski = await H.hash("SHA-1", input.publicKeyBits);
    var subjectName = input.subjectName;
    var issuerCert = input.issuerCert || null;
    var issuerPrivateKey = input.issuerPrivateKey || null;
    var issuerCurve = curve;
    var issuerName = subjectName;
    var aki = null;

    if (issuerCert) {
      issuerCurve = issuerCert.spki.curveName;
      if (!HASH[issuerCurve]) throw new Error("签发者证书曲线不支持：" + issuerCurve);
      issuerName = issuerCert.subject.raw;
      var skiExt = issuerCert.extensions["2.5.29.14"];
      aki = skiExt && skiExt.value && skiExt.value.hex
        ? B.hexToBytes(skiExt.value.hex)
        : await H.hash("SHA-1", issuerCert.spki.publicKeyBits);
    }
    if (!issuerPrivateKey) throw new Error("缺少签发者私钥");

    var hash = HASH[issuerCurve];
    var sigAlg = seq(encodeOid(SIG_OID[issuerCurve]));
    var serial = input.serial || serialBytes();
    var notBefore = input.notBefore || new Date(Date.now() - 24 * 3600 * 1000);
    var notAfter = input.notAfter;
    if (!notAfter) {
      notAfter = input.lifetime
        ? new Date(Date.UTC(9999, 11, 31, 23, 59, 59))
        : new Date(Date.now() + (input.validityDays || 3650) * 24 * 3600 * 1000);
    }

    var keyUsageBits;
    var ekuOid = null;
    if (isCA) keyUsageBits = [5, 6];
    else if (input.usageType === "keyAgreement") keyUsageBits = [4];
    else if (input.usageType === "tls") { keyUsageBits = [0, 4]; ekuOid = EKU[input.tlsRole || "server"]; }
    else keyUsageBits = [0];

    var ext = buildExtensions({
      isCA: isCA,
      pathLen: isCA ? (input.pathLen == null ? (role === "root" ? 1 : 0) : input.pathLen) : null,
      keyUsageBits: keyUsageBits,
      policyOid: input.policyOid,
      ekuOid: ekuOid
    }, ski, aki);

    var tbsParts = [
      tlv(0xA0, integerFromNumber(2)),
      integerFromBytes(serial),
      sigAlg,
      issuerName,
      seq(timeTlv(notBefore), timeTlv(notAfter)),
      subjectName,
      input.spki
    ];
    if (ext.length) tbsParts.push(tlv(0xA3, seq.apply(null, ext)));
    var tbs = seq.apply(null, tbsParts);

    var rawSignature = await EC.sign({ privateKey: issuerPrivateKey, hash: hash, message: tbs });
    var derSignature = EC.rawToDer(rawSignature, issuerCurve);
    var certDer = seq(tbs, sigAlg, bitString(derSignature));
    return {
      der: certDer,
      pem: X509.toPem(certDer, "CERTIFICATE"),
      curve: curve,
      signatureAlgorithm: SIG_NAME[issuerCurve],
      serial: B.bytesToHexCompact(serial),
      ski: B.bytesToHexCompact(ski),
      aki: aki ? B.bytesToHexCompact(aki) : null,
      cert: X509.parseCertificate(certDer)
    };
  }

  async function create(opts) {
    opts = opts || {};
    var role = opts.role || "leaf";
    var curve = opts.curve || "P-384";
    if (!CURVE_OID[curve]) throw new Error("只支持 P-256 / P-384");
    var keyUsage = opts.keyUsage === "ECDH" ? "ECDH" : "ECDSA";
    var keyPair = await EC.generateKeyPair(curve, keyUsage);
    var subjectName = encodeName(opts.subject || {});
    var spki = seq(
      seq(encodeOid("1.2.840.10045.2.1"), encodeOid(CURVE_OID[curve])),
      bitString(keyPair.publicRaw)
    );

    var out = await buildCertificate({
      role: role,
      curve: curve,
      subjectName: subjectName,
      publicKeyBits: keyPair.publicRaw,
      spki: spki,
      issuerCert: opts.issuerCert || null,
      issuerPrivateKey: opts.issuerPrivateKey || (role === "root" ? keyPair.privateKey : null),
      pathLen: opts.pathLen,
      usageType: opts.usageType,
      tlsRole: opts.tlsRole,
      validityDays: opts.validityDays,
      lifetime: opts.lifetime,
      notBefore: opts.notBefore,
      notAfter: opts.notAfter,
      serial: opts.serial,
      policyOid: opts.policyOid
    });

    out.privateKeyPem = keyPair.pkcs8Pem;
    out.privateKey = keyPair.privateKey;
    out.privateKeyRaw = B.base64UrlToBytes(keyPair.privateJwk.d);
    out.publicKeyPem = X509.toPem(new Uint8Array(await global.crypto.subtle.exportKey("spki", keyPair.publicKey)), "PUBLIC KEY");
    out.publicRaw = keyPair.publicRaw;
    out.cert = X509.parseCertificate(out.der);
    return out;
  }

  async function createCsr(opts) {
    opts = opts || {};
    var curve = opts.curve || "P-384";
    if (!CURVE_OID[curve]) throw new Error("只支持 P-256 / P-384");
    var keyPair = opts.keyPair || await EC.generateKeyPair(curve, "ECDSA");
    var subjectName = encodeName(opts.subject || {});
    var spki = seq(
      seq(encodeOid("1.2.840.10045.2.1"), encodeOid(CURVE_OID[curve])),
      bitString(keyPair.publicRaw)
    );
    var cri = seq(integerFromNumber(0), subjectName, spki);
    var sigAlg = seq(encodeOid(SIG_OID[curve]));
    var rawSignature = await EC.sign({ privateKey: keyPair.privateKey, hash: HASH[curve], message: cri });
    var csrDer = seq(cri, sigAlg, bitString(EC.rawToDer(rawSignature, curve)));
    return {
      der: csrDer,
      pem: X509.toPem(csrDer, "CERTIFICATE REQUEST"),
      privateKeyPem: keyPair.pkcs8Pem,
      publicRaw: keyPair.publicRaw,
      curve: curve
    };
  }

  async function signCsr(opts) {
    opts = opts || {};
    var csr = parseCsr(opts.csrDer);
    var pub = await EC.importPublicKey({ format: "raw", data: csr.publicKeyBits, curve: csr.curve, usage: "ECDSA" });
    var selfOk = await EC.verify({
      publicKey: pub,
      hash: csr.signatureHash,
      message: csr.criRaw,
      signature: csr.signature,
      curve: csr.curve
    });
    if (!selfOk) throw new Error("CSR 自签名验证失败：公钥与签名不匹配");

    var out = await buildCertificate({
      role: "leaf",
      curve: csr.curve,
      subjectName: csr.subjectRaw,
      publicKeyBits: csr.publicKeyBits,
      spki: csr.spkiRaw,
      issuerCert: opts.issuerCert,
      issuerPrivateKey: opts.issuerPrivateKey,
      usageType: opts.usageType,
      tlsRole: opts.tlsRole,
      validityDays: opts.validityDays,
      lifetime: opts.lifetime,
      notBefore: opts.notBefore,
      notAfter: opts.notAfter,
      serial: opts.serial,
      policyOid: opts.policyOid
    });
    out.privateKeyPem = null;
    out.privateKeyRaw = null;
    out.publicKeyPem = null;
    out.publicRaw = csr.publicKeyBits;
    out.csrSubject = csr.subject;
    return out;
  }

  async function importIssuerKey(pem, curve) {
    return EC.importPrivateKey({ format: "auto", data: pem, curve: curve, usage: "ECDSA" });
  }

  DLMS.CertGen = {
    OID: OID,
    CURVE_OID: CURVE_OID,
    SIG_OID: SIG_OID,
    SIG_NAME: SIG_NAME,
    HASH: HASH,
    encodeName: encodeName,
    encodeOid: encodeOid,
    create: create,
    createCsr: createCsr,
    parseCsr: parseCsr,
    signCsr: signCsr,
    importIssuerKey: importIssuerKey,
    serialBytes: serialBytes
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.CertGen;
})(typeof globalThis !== "undefined" ? globalThis : this);
