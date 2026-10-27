/* ============================================================
   DLMS 安全算法工作台 · 测试 PKI 密钥包
   一次生成 Suite 1/2 的整套测试证书，并提供可恢复的密钥包。
   零依赖；浏览器与 Node(>=18) 通用。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;
  var EC = DLMS.EC;
  var X509 = DLMS.X509;
  var CG = DLMS.CertGen;
  var CRC = DLMS.CRC;

  var FORMAT = "dlms-testpki";
  var VERSION = 1;

  var SUITES = {
    1: { curve: "P-256", label: "Suite 1", hash: "SHA-256" },
    2: { curve: "P-384", label: "Suite 2", hash: "SHA-384" }
  };

  var KIND_ORDER = ["ca", "client-sign", "client-key-agreement"];

  var KIND_LABEL = {
    "ca": "Root-CA",
    "client-sign": "客户端签名证书",
    "client-key-agreement": "客户端密钥协商证书"
  };

  var KIND_FILE = {
    "ca": "01-root-ca",
    "client-sign": "02-client-sign",
    "client-key-agreement": "03-client-key-agreement"
  };

  var KIND_USAGE = {
    "ca": "keyCertSign",
    "client-sign": "digitalSignature",
    "client-key-agreement": "keyAgreement"
  };

  function pad2(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function normalizeSystemTitle(text) {
    var s = String(text == null ? "" : text).replace(/0x/gi, "").replace(/[\s:_,\-]/g, "");
    if (!/^[0-9A-Fa-f]{16}$/.test(s)) throw new Error("System Title 必须是 16 个十六进制字符（8 字节）");
    return s.toUpperCase();
  }

  function isDate(value) {
    return value instanceof Date && !isNaN(value.getTime());
  }

  function parseSerial(text) {
    var raw = String(text == null ? "" : text).trim();
    if (/^-/.test(raw)) throw new Error("必须是正整数");
    var t = raw.replace(/[\s:_-]/g, "");
    if (!t) return null;
    var hex;
    if (/^0x/i.test(t)) {
      if (!/^0x[0-9a-f]+$/i.test(t)) throw new Error("0x 后只能跟十六进制数字");
      hex = t.slice(2);
    } else if (/^[0-9]+$/.test(t)) {
      var n = BigInt(t);
      if (n <= 0n) throw new Error("必须是正整数");
      hex = n.toString(16);
    } else if (/^[0-9a-f]+$/i.test(t)) {
      hex = t;
    } else {
      throw new Error("只支持十进制、0x 十六进制或纯十六进制");
    }
    if (hex.length % 2) hex = "0" + hex;
    if (hex.length > 40) throw new Error("超过 20 字节（RFC 5280 上限）");
    var bytes = B.hexToBytes(hex);
    if (!bytes.some(function (b) { return b !== 0; })) throw new Error("不能为 0");
    return bytes;
  }

  function serialFor(map, id, label) {
    var raw = map && map[id];
    if (raw == null || String(raw).trim() === "") return undefined;
    if (raw instanceof Uint8Array) return raw;
    try {
      return parseSerial(raw);
    } catch (e) {
      throw new Error(label + " 的序列号：" + (e && e.message ? e.message : e));
    }
  }

  function normalizeSuites(list) {
    if (!Array.isArray(list)) list = list == null ? [] : [list];
    var out = [];
    (list || []).forEach(function (s) {
      var n = Number(s);
      if (n !== 1 && n !== 2) throw new Error("只支持 Suite 1 / Suite 2");
      if (out.indexOf(n) < 0) out.push(n);
    });
    if (!out.length) throw new Error("至少选择一个安全套件");
    return out.sort();
  }

  function keyBytes(curve) {
    return curve === "P-384" ? 48 : 32;
  }

  function padLeft(bytes, n) {
    if (bytes.length === n) return bytes;
    if (bytes.length > n) return bytes.slice(bytes.length - n);
    return B.concat(new Uint8Array(n - bytes.length), bytes);
  }

  function sortEntries(entries) {
    return entries.slice().sort(function (a, b) {
      if (a.suite !== b.suite) return a.suite - b.suite;
      return KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind);
    });
  }

  function bundleSuites(bundle) {
    var suites = [];
    ((bundle && bundle.entries) || []).forEach(function (e) {
      var s = Number(e.suite);
      if ((s === 1 || s === 2) && suites.indexOf(s) < 0) suites.push(s);
    });
    if (!suites.length && bundle && bundle.profile && Array.isArray(bundle.profile.suites)) {
      bundle.profile.suites.forEach(function (s) {
        var n = Number(s);
        if ((n === 1 || n === 2) && suites.indexOf(n) < 0) suites.push(n);
      });
    }
    if (!suites.length) suites = [1, 2];
    return suites.sort();
  }

  function entryId(suite, kind) {
    return "s" + suite + "-" + kind;
  }

  function makeEntry(out, meta) {
    var ext = out.cert.extensions && out.cert.extensions["2.5.29.15"];
    var usages = ext && ext.value && ext.value.usages ? ext.value.usages.slice() : [];
    var pub = out.publicRaw || new Uint8Array(0);
    if (pub.length && pub[0] === 0x04) pub = pub.slice(1);
    return {
      id: entryId(meta.suite, meta.kind),
      suite: meta.suite,
      kind: meta.kind,
      entity: meta.kind === "ca" ? "ca" : "client",
      curve: meta.curve,
      cn: meta.cn,
      subject: meta.subject,
      certPem: out.pem,
      certDerHex: B.bytesToHexCompact(out.der),
      keyPem: out.privateKeyPem,
      privateD: B.bytesToHexCompact(out.privateKeyRaw),
      publicXY: B.bytesToHexCompact(pub),
      serial: out.serial,
      ski: out.ski,
      aki: out.aki || null,
      notBefore: out.cert.notBefore.iso,
      notAfter: out.cert.notAfter.iso,
      signatureAlgorithm: out.signatureAlgorithm,
      keyUsage: usages
    };
  }

  async function generate(opts) {
    opts = opts || {};
    var st = normalizeSystemTitle(opts.systemTitle);
    var suites = normalizeSuites(opts.suites == null ? [1, 2] : opts.suites);
    var subject = opts.subject || {};
    var o = String(subject.O || "").trim();
    var ou = String(subject.OU || "").trim();
    var c = String(subject.C || "").trim().toUpperCase();
    if (c && !/^[A-Z]{2}$/.test(c)) throw new Error("C 必须是 2 位字母（如 CH / CN）");

    var days = parseInt(opts.validityDays, 10);
    if (opts.validityDays != null && (!isFinite(days) || days <= 0)) throw new Error("有效期天数必须大于 0");
    if (isFinite(days) && days > 36500) throw new Error("有效期过长（上限 36500 天）");

    var notBefore = isDate(opts.notBefore)
      ? opts.notBefore
      : (isFinite(days) ? new Date(Date.now() - 86400000) : new Date(Date.UTC(2000, 0, 1, 0, 0, 0)));
    var notAfter;
    if (isDate(opts.notAfter)) notAfter = opts.notAfter;
    else if (isFinite(days)) notAfter = new Date(notBefore.getTime() + days * 86400000);
    else notAfter = new Date(Date.UTC(2099, 0, 1, 0, 0, 0));
    if (notAfter.getTime() <= notBefore.getTime()) throw new Error("结束日期必须晚于起始日期");

    var caBase = String(opts.caNameBase || "Root_CA").trim() || "Root_CA";
    var serials = opts.serials || {};
    var entries = [];

    for (var i = 0; i < suites.length; i++) {
      var suite = suites[i];
      var curve = SUITES[suite].curve;
      var caSubject = { CN: caBase + "_S" + suite, O: o, OU: ou, C: c };
      var leafSubject = { CN: st, O: o, OU: ou, C: c };
      var caId = entryId(suite, "ca");
      var signId = entryId(suite, "client-sign");
      var kaId = entryId(suite, "client-key-agreement");

      var ca = await CG.create({
        role: "root",
        curve: curve,
        subject: caSubject,
        serial: serialFor(serials, caId, caSubject.CN),
        notBefore: notBefore,
        notAfter: notAfter,
        pathLen: 1
      });
      entries.push(makeEntry(ca, { suite: suite, kind: "ca", curve: curve, cn: caSubject.CN, subject: caSubject }));

      var sign = await CG.create({
        role: "leaf",
        curve: curve,
        subject: leafSubject,
        issuerCert: ca.cert,
        issuerPrivateKey: ca.privateKey,
        usageType: "sign",
        serial: serialFor(serials, signId, "Suite " + suite + " 客户端签名证书"),
        notBefore: notBefore,
        notAfter: notAfter
      });
      entries.push(makeEntry(sign, { suite: suite, kind: "client-sign", curve: curve, cn: st, subject: leafSubject }));

      var ka = await CG.create({
        role: "leaf",
        curve: curve,
        subject: leafSubject,
        issuerCert: ca.cert,
        issuerPrivateKey: ca.privateKey,
        usageType: "keyAgreement",
        serial: serialFor(serials, kaId, "Suite " + suite + " 客户端密钥协商证书"),
        notBefore: notBefore,
        notAfter: notAfter
      });
      entries.push(makeEntry(ka, { suite: suite, kind: "client-key-agreement", curve: curve, cn: st, subject: leafSubject }));
    }

    return {
      format: FORMAT,
      version: VERSION,
      createdAt: new Date().toISOString(),
      generator: "DLMS 安全算法工作台",
      profile: {
        entity: "client",
        systemTitle: st,
        subject: { O: o, OU: ou, C: c },
        caNameBase: caBase,
        suites: suites,
        validityDays: isFinite(days) ? days : null,
        notBefore: notBefore.toISOString(),
        notAfter: notAfter.toISOString()
      },
      entries: sortEntries(entries)
    };
  }

  async function deriveKey(passphrase, salt, iterations) {
    if (!global.crypto || !global.crypto.subtle) throw new Error("当前环境不支持 WebCrypto");
    var base = await global.crypto.subtle.importKey(
      "raw", B.utf8ToBytes(passphrase), "PBKDF2", false, ["deriveKey"]
    );
    return global.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function serialize(bundle, opts) {
    opts = opts || {};
    if (!bundle || bundle.format !== FORMAT) throw new Error("不是有效的测试密钥包");
    var passphrase = String(opts.passphrase || "");
    if (!passphrase) {
      var plain = clone(bundle);
      plain.encrypted = false;
      return JSON.stringify(plain, null, 2);
    }

    var salt = B.randomBytes(16);
    var iv = B.randomBytes(12);
    var iterations = 310000;
    var key = await deriveKey(passphrase, salt, iterations);
    var ciphertext = await global.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      B.utf8ToBytes(JSON.stringify(bundle))
    );
    return JSON.stringify({
      format: FORMAT,
      version: VERSION,
      encrypted: true,
      cipher: "AES-256-GCM",
      kdf: {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations: iterations,
        salt: B.bytesToBase64(salt)
      },
      iv: B.bytesToBase64(iv),
      payload: B.bytesToBase64(new Uint8Array(ciphertext))
    }, null, 2);
  }

  async function parse(text, opts) {
    opts = opts || {};
    var obj;
    try {
      obj = JSON.parse(String(text == null ? "" : text).replace(/^\uFEFF/, ""));
    } catch (e) {
      throw new Error("密钥包不是合法 JSON：" + (e && e.message ? e.message : e));
    }
    if (!obj || obj.format !== FORMAT) throw new Error("不是 DLMS 测试密钥包（format 应为 " + FORMAT + "）");
    var version = parseInt(obj.version, 10);
    if (!isFinite(version) || version < 1) throw new Error("密钥包缺少有效版本号");
    if (version > VERSION) throw new Error("密钥包版本 " + version + " 高于当前工具支持的 " + VERSION + "，请升级工具");

    if (obj.encrypted) {
      var passphrase = String(opts.passphrase || "");
      if (!passphrase) throw new Error("密钥包已加密，请填写口令");
      var kdf = obj.kdf || {};
      var salt = B.base64ToBytes(kdf.salt || "");
      var iv = B.base64ToBytes(obj.iv || "");
      var payload = B.base64ToBytes(obj.payload || "");
      if (salt.length < 8 || salt.length > 64) throw new Error("加密密钥包的 salt 长度不在支持范围（8–64 B）");
      if (iv.length !== 12) throw new Error("加密密钥包的 AES-GCM IV 必须是 12 B");
      if (payload.length < 16) throw new Error("加密密钥包的 payload 过短");
      var iterations = parseInt(kdf.iterations, 10);
      if (!isFinite(iterations) || iterations < 100000 || iterations > 1000000) {
        throw new Error("KDF 迭代次数不在支持范围（100000–1000000）");
      }
      var key = await deriveKey(passphrase, salt, iterations);
      var plain;
      try {
        plain = await global.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, payload);
      } catch (e) {
        throw new Error("口令错误，或密钥包已损坏");
      }
      var inner;
      try {
        inner = JSON.parse(B.bytesToUtf8(new Uint8Array(plain)));
      } catch (e) {
        throw new Error("解密后的内容不是合法 JSON");
      }
      if (!inner || inner.format !== FORMAT) throw new Error("解密后的内容不是 DLMS 测试密钥包");
      return inner;
    }

    delete obj.encrypted;
    if (!Array.isArray(obj.entries)) throw new Error("密钥包缺少 entries 数组");
    return obj;
  }

  function entryReport(entry) {
    return {
      id: entry && entry.id ? entry.id : "?",
      suite: entry && entry.suite,
      kind: entry && entry.kind,
      ok: true,
      errors: [],
      warnings: []
    };
  }

  function certFromEntry(entry) {
    if (entry.certDerHex) {
      return X509.parseCertificate(B.hexToBytes(entry.certDerHex));
    }
    if (entry.certPem) {
      var blocks = X509.parsePem(entry.certPem);
      var block = blocks.filter(function (b) { return b.label === "CERTIFICATE"; })[0] || blocks[0];
      return X509.parseCertificate(block.der);
    }
    throw new Error("缺少 certPem / certDerHex");
  }

  function privateHex(entry) {
    var curve = entry.curve || (entry.suite && SUITES[entry.suite] ? SUITES[entry.suite].curve : "");
    var size = curve === "P-384" ? 48 : 32;
    return B.bytesToHexCompact(padLeft(B.hexToBytes(entry.privateD || ""), size));
  }

  function publicHex(entry) {
    var xy = B.hexToBytes(entry.publicXY || "");
    if ((xy.length === 65 || xy.length === 97) && xy[0] === 0x04) xy = xy.slice(1);
    if (!xy.length) {
      var cert = certFromEntry(entry);
      xy = cert.spki.publicKeyBytes;
      if (xy.length && xy[0] === 0x04) xy = xy.slice(1);
    }
    return B.bytesToHexCompact(xy);
  }

  async function validate(bundle) {
    var report = { ok: false, errors: [], warnings: [], entries: [] };
    if (!bundle || bundle.format !== FORMAT) {
      report.errors.push("format 不是 " + FORMAT);
      return report;
    }
    var entries = Array.isArray(bundle.entries) ? bundle.entries : [];
    if (!entries.length) {
      report.errors.push("密钥包里没有证书条目");
      return report;
    }

    var byId = {};
    var parsed = {};
    var seenSerial = {};
    var profileST = bundle.profile && bundle.profile.systemTitle
      ? String(bundle.profile.systemTitle).toUpperCase()
      : "";

    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i] || {};
      var r = entryReport(entry);
      report.entries.push(r);

      if (!entry.id) r.errors.push("缺少 id");
      else if (byId[entry.id]) r.errors.push("id 重复：" + entry.id);
      else byId[entry.id] = entry;

      if (entry.suite !== 1 && entry.suite !== 2) {
        r.errors.push("suite 必须是 1 或 2");
      } else if (!entry.curve) {
        r.errors.push("缺少 curve");
      } else if (entry.curve !== SUITES[entry.suite].curve) {
        r.errors.push("curve 与 Suite 不匹配：" + entry.curve + " ≠ " + SUITES[entry.suite].curve);
      }

      if (KIND_ORDER.indexOf(entry.kind) < 0) r.errors.push("未知的 kind：" + entry.kind);

      if (!entry.privateD) r.errors.push("缺少私钥 d（privateD）");
      if (!entry.keyPem) r.errors.push("缺少私钥 PEM（keyPem）");
      if (!entry.certDerHex) r.errors.push("缺少证书 DER（certDerHex）");
      if (!entry.certPem) r.warnings.push("缺少 certPem，ZIP 导出时会从 DER 重新生成");

      var cert = null;
      try {
        cert = certFromEntry(entry);
        parsed[entry.id] = cert;

        var serialKey = cert.issuer.canonical + "|" + cert.serial;
        if (seenSerial[serialKey]) r.warnings.push("同一签发者下序列号重复：" + cert.serial);
        seenSerial[serialKey] = true;

        if (entry.certDerHex) {
          var derHex = B.bytesToHexCompact(B.hexToBytes(entry.certDerHex));
          if (derHex !== B.bytesToHexCompact(cert.der)) r.errors.push("certDerHex 与证书 DER 不一致");
        }
        if (entry.certPem && entry.certDerHex) {
          var pemBlocks = X509.parsePem(entry.certPem);
          var pemCert = pemBlocks.filter(function (b) { return b.label === "CERTIFICATE"; })[0];
          if (!pemCert) r.errors.push("certPem 里没有 CERTIFICATE 块");
          else if (B.bytesToHexCompact(pemCert.der) !== B.bytesToHexCompact(cert.der)) {
            r.errors.push("certPem 与 certDerHex 不一致");
          }
        }

        if (entry.curve && cert.spki.curveName !== entry.curve) {
          r.errors.push("证书公钥曲线与条目不一致：" + cert.spki.curveName + " ≠ " + entry.curve);
        }

        var cnPart = cert.subject.parts.filter(function (p) { return p.name === "CN"; })[0];
        if (!cnPart) {
          r.errors.push("证书主题缺 CN");
        } else {
          if (entry.cn && cnPart.value !== entry.cn) r.errors.push("条目 CN 与证书不一致");
          if (entry.kind === "client-sign" || entry.kind === "client-key-agreement") {
            if (!/^[0-9A-Fa-f]{16}$/.test(cnPart.value)) {
              r.errors.push("终端证书 CN 不是 16 位 System Title");
            } else if (profileST && cnPart.value.toUpperCase() !== profileST) {
              r.warnings.push("证书 CN 与密钥包 profile.systemTitle 不一致");
            }
          }
        }

        var ku = cert.extensions && cert.extensions["2.5.29.15"];
        var usages = ku && ku.value && ku.value.usages ? ku.value.usages : [];
        var expectedUsage = KIND_USAGE[entry.kind];
        if (expectedUsage && usages.indexOf(expectedUsage) < 0) {
          r.errors.push("keyUsage 缺 " + expectedUsage + "（实际：" + (usages.join(", ") || "无") + "）");
        }
        var bc = X509.basicConstraints(cert);
        if (entry.kind === "ca") {
          if (!bc.ca) r.errors.push("CA 证书缺 CA=TRUE");
        } else if (bc.ca) {
          r.errors.push("终端证书不应声明 CA=TRUE");
        }

        if (entry.privateD && entry.curve) {
          try {
            var size = keyBytes(entry.curve);
            var d = padLeft(B.hexToBytes(entry.privateD), size);
            var pub = EC.derivePublicKey(d, entry.curve);
            var xy = B.concat(pub.x, pub.y);
            var certPub = cert.spki.publicKeyBytes;
            if (certPub.length === xy.length + 1 && certPub[0] === 0x04) certPub = certPub.slice(1);
            if (!B.bytesEqual(xy, certPub)) r.errors.push("私钥 d 推导出的公钥与证书不匹配");
          } catch (e) {
            r.errors.push("私钥 d 检查失败：" + (e && e.message ? e.message : e));
          }
        }

        if (entry.keyPem && entry.curve) {
          try {
            var usage = entry.kind === "client-key-agreement" ? "ECDH" : "ECDSA";
            var key = await EC.importPrivateKey({ format: "pem", data: entry.keyPem, curve: entry.curve, usage: usage });
            var jwk = await global.crypto.subtle.exportKey("jwk", key);
            var dPem = padLeft(B.base64UrlToBytes(jwk.d), keyBytes(entry.curve));
            var dHex = padLeft(B.hexToBytes(entry.privateD || ""), keyBytes(entry.curve));
            if (!B.bytesEqual(dPem, dHex)) r.errors.push("私钥 PEM 与 privateD 不一致");
          } catch (e) {
            r.errors.push("私钥 PEM 无法导入：" + (e && e.message ? e.message : e));
          }
        }

        var validity = X509.checkValidity(cert);
        if (!validity.ok) r.warnings.push(validity.reason);
      } catch (e) {
        r.errors.push("证书解析失败：" + (e && e.message ? e.message : e));
      }

      r.ok = r.errors.length === 0;
    }

    for (var j = 0; j < entries.length; j++) {
      var e = entries[j] || {};
      var rj = report.entries[j];
      if (e.kind !== "client-sign" && e.kind !== "client-key-agreement") continue;
      var caId = entryId(e.suite, "ca");
      var caEntry = byId[caId];
      if (!caEntry) {
        rj.errors.push("缺少 Suite " + e.suite + " 的 CA 证书（" + caId + "）");
        rj.ok = false;
        continue;
      }
      var leafCert = parsed[e.id];
      var caCert = parsed[caId];
      if (!leafCert || !caCert) {
        rj.errors.push("无法验链：证书未成功解析");
        rj.ok = false;
        continue;
      }
      if (leafCert.issuer.canonical !== caCert.subject.canonical) {
        rj.errors.push("issuer 与 CA 的 subject 不一致");
        rj.ok = false;
      }
      var sig = await X509.verifyCertificate(leafCert, caCert);
      if (!sig.ok) {
        rj.errors.push("证书签名验证失败：" + sig.reason);
        rj.ok = false;
      }
      rj.ok = rj.errors.length === 0;
    }

    for (var k = 0; k < entries.length; k++) {
      var ce = entries[k] || {};
      if (ce.kind !== "ca") continue;
      var cr = report.entries[k];
      var cc = parsed[ce.id];
      if (!cc) {
        cr.errors.push("CA 证书未成功解析");
        cr.ok = false;
        continue;
      }
      var self = await X509.verifyCertificate(cc, cc);
      if (!self.ok) {
        cr.errors.push("CA 自签验证失败：" + self.reason);
      }
      if (cc.subject.canonical !== cc.issuer.canonical) {
        cr.errors.push("CA 不是自签（subject ≠ issuer）");
      }
      cr.ok = cr.errors.length === 0;
    }

    report.entries.forEach(function (r) {
      r.errors.forEach(function (msg) { report.errors.push(r.id + "：" + msg); });
      r.warnings.forEach(function (msg) { report.warnings.push(r.id + "：" + msg); });
    });
    report.ok = report.entries.every(function (r) { return r.ok; }) && report.errors.length === 0;
    return report;
  }

  function mergeBundles(base, incoming) {
    if (!base) return incoming;
    if (!incoming) return base;
    var baseST = base.profile && base.profile.systemTitle ? String(base.profile.systemTitle).toUpperCase() : "";
    var incST = incoming.profile && incoming.profile.systemTitle ? String(incoming.profile.systemTitle).toUpperCase() : "";
    if (baseST && incST && baseST !== incST) throw new Error("两次的 System Title 不一致，不能合并");
    var map = {};
    var order = [];
    (base.entries || []).forEach(function (e) {
      map[e.id] = e;
      order.push(e.id);
    });
    (incoming.entries || []).forEach(function (e) {
      map[e.id] = e;
      if (order.indexOf(e.id) < 0) order.push(e.id);
    });
    var merged = clone(incoming);
    merged.entries = sortEntries(order.map(function (id) { return map[id]; }));
    var mergedProfile = clone(base.profile || {});
    var incProfile = incoming.profile || {};
    Object.keys(incProfile).forEach(function (k) { mergedProfile[k] = incProfile[k]; });
    merged.profile = mergedProfile;
    merged.profile.suites = bundleSuites(merged);
    merged.createdAt = base.createdAt || merged.createdAt;
    merged.updatedAt = new Date().toISOString();
    return merged;
  }

  function buildMeterImportText(bundle, suite) {
    var s = Number(suite);
    if (s !== 1 && s !== 2) throw new Error("Suite 必须是 1 或 2");
    var list = sortEntries((bundle.entries || []).filter(function (e) { return e.suite === s; }));
    var curve = SUITES[s] ? SUITES[s].curve : "";
    var lines = [];
    lines.push("# DLMS 测试证书导入清单 · Suite " + s + " (" + curve + ")");
    lines.push("# 生成时间：" + (bundle.createdAt || "—"));
    lines.push("# 客户端 System Title：" + ((bundle.profile && bundle.profile.systemTitle) || "—"));
    lines.push("#");
    lines.push("# 用法：Security setup 方法 6 import_certificate(证书 DER)");
    lines.push("# 顺序：Root-CA 必须先导；终端证书可选（表要在未收到客户端证书时验签才导）");
    lines.push("# 注意：import_certificate 只收证书 DER；私钥不要导入电表");
    lines.push("");
    list.forEach(function (e, i) {
      lines.push("# [" + (i + 1) + "] " + (KIND_LABEL[e.kind] || e.kind));
      lines.push("# CN=" + e.cn + "  Serial=" + e.serial + "  SKI=" + e.ski + "  有效期至 " + e.notAfter);
      lines.push(e.certDerHex);
      lines.push("");
    });
    lines.push("# ===== 纯 HEX（按上面的顺序，每行一张）=====");
    list.forEach(function (e) { lines.push(e.certDerHex); });
    lines.push("");
    return lines.join("\n");
  }

  function buildAllDerText(bundle) {
    var lines = ["# 全部证书 DER HEX · 导入顺序 Root → 终端", "# 生成时间：" + (bundle.createdAt || "—"), ""];
    var suites = bundleSuites(bundle);
    suites.forEach(function (s) {
      lines.push("# Suite " + s);
      sortEntries((bundle.entries || []).filter(function (e) { return e.suite === s; })).forEach(function (e) {
        lines.push(e.certDerHex);
      });
      lines.push("");
    });
    return lines.join("\n");
  }

  function buildHexKeysText(bundle) {
    var lines = ["# 公私钥 HEX 速查（TEST ONLY）", ""];
    sortEntries(bundle.entries || []).forEach(function (e) {
      lines.push("Suite " + e.suite + " / " + (KIND_LABEL[e.kind] || e.kind));
      lines.push("  CN        = " + e.cn);
      lines.push("  Serial    = " + e.serial);
      lines.push("  公钥 X‖Y  = " + publicHex(e));
      lines.push("  私钥 d    = " + privateHex(e));
      lines.push("  SKI       = " + e.ski);
      lines.push("");
    });
    return lines.join("\n");
  }

  function buildReadme(bundle) {
    var profile = bundle.profile || {};
    var lines = [
      "DLMS 测试证书包（TEST ONLY）",
      "========================================",
      "生成时间：" + (bundle.createdAt || "—"),
      "生成工具：DLMS 安全算法工作台",
      "客户端 System Title：" + (profile.systemTitle || "—"),
      "",
      "内容",
      "----------------------------------------",
      "manifest.json                 完整密钥包（含私钥），可在「整套证书」页导入恢复",
      "suiteN/01-root-ca.cert.pem    Root-CA 证书",
      "suiteN/01-root-ca.key.pem     Root-CA 私钥（不要导入电表）",
      "suiteN/02-client-sign.*       客户端签名证书 / 私钥 / DER HEX",
      "suiteN/03-client-key-agreement.*  客户端密钥协商证书 / 私钥 / DER HEX",
      "meter-import/suiteN.txt       电表导入清单（DER HEX，按顺序）",
      "meter-import/all-der.txt      全部证书 DER HEX",
      "hex-keys.txt                  公私钥 HEX 速查",
      "",
      "电表导入顺序",
      "----------------------------------------",
      "1. Root-CA（信任锚，必须先导）",
      "2. 客户端签名证书（可选）",
      "3. 客户端密钥协商证书（可选）",
      "说明：import_certificate 只接收证书 DER；私钥留在客户端。",
      "",
      "恢复",
      "----------------------------------------",
      "打开「整套证书」→ 导入密钥包 → 粘贴 manifest.json 或选择文件。",
      "如果导出时设置了口令，导入时填同一个口令。",
      "",
      "警告",
      "----------------------------------------",
      "本包包含私钥，仅用于实验室测试。不要提交到 git，不要用于生产。",
      ""
    ];
    return lines.join("\n");
  }

  function u16(n) {
    return new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
  }

  function u32(n) {
    return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
  }

  function zipStore(files) {
    var d = new Date();
    var year = Math.max(1980, d.getFullYear());
    var dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2);
    var dosDate = ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    var locals = [];
    var centrals = [];
    var offset = 0;

    files.forEach(function (f) {
      var name = B.utf8ToBytes(f.name);
      var data = f.data instanceof Uint8Array ? f.data : B.utf8ToBytes(String(f.data || ""));
      var crc = CRC.crc32(CRC.CRC32["ISO-HDLC"], data) >>> 0;
      var local = B.concat(
        u32(0x04034b50), u16(20), u16(0x0800), u16(0), u16(dosTime), u16(dosDate),
        u32(crc), u32(data.length), u32(data.length), u16(name.length), u16(0), name, data
      );
      var central = B.concat(
        u32(0x02014b50), u16(20), u16(20), u16(0x0800), u16(0), u16(dosTime), u16(dosDate),
        u32(crc), u32(data.length), u32(data.length), u16(name.length), u16(0), u16(0),
        u16(0), u16(0), u32(0), u32(offset), name
      );
      locals.push(local);
      centrals.push(central);
      offset += local.length;
    });

    var centralSize = centrals.reduce(function (n, c) { return n + c.length; }, 0);
    var eocd = B.concat(
      u32(0x06054b50), u16(0), u16(0), u16(files.length), u16(files.length),
      u32(centralSize), u32(offset), u16(0)
    );
    return B.concat.apply(null, locals.concat(centrals).concat([eocd]));
  }

  function buildZip(bundle) {
    var files = [];
    files.push({ name: "README.txt", data: B.utf8ToBytes(buildReadme(bundle)) });
    var manifest = clone(bundle);
    manifest.encrypted = false;
    files.push({ name: "manifest.json", data: B.utf8ToBytes(JSON.stringify(manifest, null, 2)) });

    sortEntries(bundle.entries || []).forEach(function (e) {
      var dir = "suite" + e.suite + "/";
      var base = KIND_FILE[e.kind] || e.kind;
      var derHex = e.certDerHex || B.bytesToHexCompact(certFromEntry(e).der);
      var certPem = e.certPem || X509.toPem(B.hexToBytes(derHex), "CERTIFICATE");
      files.push({ name: dir + base + ".cert.pem", data: B.utf8ToBytes(certPem + "\n") });
      if (e.keyPem) files.push({ name: dir + base + ".key.pem", data: B.utf8ToBytes(e.keyPem + "\n") });
      files.push({ name: dir + base + ".cert.der.hex", data: B.utf8ToBytes(derHex + "\n") });
    });

    var suites = bundleSuites(bundle);
    suites.forEach(function (s) {
      files.push({
        name: "meter-import/suite" + s + ".txt",
        data: B.utf8ToBytes(buildMeterImportText(bundle, s))
      });
    });
    files.push({ name: "meter-import/all-der.txt", data: B.utf8ToBytes(buildAllDerText(bundle)) });
    files.push({ name: "hex-keys.txt", data: B.utf8ToBytes(buildHexKeysText(bundle)) });
    return zipStore(files);
  }

  function fileName(bundle, ext) {
    var st = (bundle && bundle.profile && bundle.profile.systemTitle || "testpki").replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
    if (!st) st = "testpki";
    var d = bundle && bundle.createdAt ? new Date(bundle.createdAt) : new Date();
    if (isNaN(d.getTime())) d = new Date();
    var stamp = d.getFullYear() + pad2(d.getMonth() + 1) + pad2(d.getDate()) + "-" + pad2(d.getHours()) + pad2(d.getMinutes());
    return "dlms-testpki-" + st + "-" + stamp + "." + (ext || "json");
  }

  DLMS.PKIBundle = {
    FORMAT: FORMAT,
    VERSION: VERSION,
    SUITES: SUITES,
    KIND_ORDER: KIND_ORDER,
    KIND_LABEL: KIND_LABEL,
    KIND_FILE: KIND_FILE,
    bundleSuites: bundleSuites,
    kindId: entryId,
    normalizeSystemTitle: normalizeSystemTitle,
    parseSerial: parseSerial,
    privateHex: privateHex,
    publicHex: publicHex,
    generate: generate,
    serialize: serialize,
    parse: parse,
    validate: validate,
    merge: mergeBundles,
    buildZip: buildZip,
    buildMeterImportText: buildMeterImportText,
    buildAllDerText: buildAllDerText,
    buildReadme: buildReadme,
    fileName: fileName
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.PKIBundle;
})(typeof globalThis !== "undefined" ? globalThis : this);
