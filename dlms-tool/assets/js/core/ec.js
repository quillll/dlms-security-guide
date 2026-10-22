/* ============================================================
   DLMS 安全算法工作台 · 椭圆曲线
   ECDSA / ECDH（P-256 / P-384）、raw ↔ DER、原始私钥 d → 公钥 Q。
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;

  var CURVES = {
    "P-256": {
      name: "P-256",
      size: 32,
      p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
      a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
      b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
      gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
      gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
      n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
    },
    "P-384": {
      name: "P-384",
      size: 48,
      p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
      a: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffcn,
      b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
      gx: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
      gy: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
      n: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n
    }
  };

  function subtle() {
    if (!global.crypto || !global.crypto.subtle) throw new Error("当前浏览器不支持 WebCrypto");
    return global.crypto.subtle;
  }

  function curve(name) {
    var c = CURVES[String(name || "").toUpperCase()];
    if (!c) throw new Error("只支持 P-256 / P-384，当前：" + name);
    return c;
  }

  function mod(x, m) {
    var r = x % m;
    return r >= 0n ? r : r + m;
  }

  function modPow(base, exp, m) {
    var result = 1n;
    base = mod(base, m);
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % m;
      base = (base * base) % m;
      exp >>= 1n;
    }
    return result;
  }

  function inv(x, m) {
    return modPow(x, m - 2n, m);
  }

  function pointDouble(P, c) {
    if (P.z === 0n || P.y === 0n) return { x: 0n, y: 1n, z: 0n };
    var Y2 = (P.y * P.y) % c.p;
    var S = (4n * P.x * Y2) % c.p;
    var M = (3n * P.x * P.x + c.a * ((P.z * P.z) % c.p) % c.p * ((P.z * P.z) % c.p)) % c.p;
    var X3 = mod(M * M - 2n * S, c.p);
    var Y3 = mod(M * (S - X3) - 8n * Y2 * Y2, c.p);
    var Z3 = (2n * P.y * P.z) % c.p;
    return { x: X3, y: Y3, z: Z3 };
  }

  function pointAdd(P, Q, c) {
    if (P.z === 0n) return Q;
    if (Q.z === 0n) return P;
    var Z1Z1 = (P.z * P.z) % c.p;
    var Z2Z2 = (Q.z * Q.z) % c.p;
    var U1 = (P.x * Z2Z2) % c.p;
    var U2 = (Q.x * Z1Z1) % c.p;
    var S1 = (P.y * Q.z % c.p * Z2Z2) % c.p;
    var S2 = (Q.y * P.z % c.p * Z1Z1) % c.p;
    if (U1 === U2) {
      if (S1 !== S2) return { x: 0n, y: 1n, z: 0n };
      return pointDouble(P, c);
    }
    var H = mod(U2 - U1, c.p);
    var I = (2n * H) % c.p;
    I = (I * I) % c.p;
    var J = (H * I) % c.p;
    var r = (2n * (S2 - S1)) % c.p;
    var V = (U1 * I) % c.p;
    var X3 = mod(r * r - J - 2n * V, c.p);
    var Y3 = mod(r * (V - X3) - 2n * S1 * J, c.p);
    var Z3 = mod(((P.z + Q.z) * (P.z + Q.z) - Z1Z1 - Z2Z2) * H, c.p);
    return { x: X3, y: Y3, z: Z3 };
  }

  function scalarMult(k, point, c) {
    var R = { x: 0n, y: 1n, z: 0n };
    var P = point;
    var bits = k.toString(2).length;
    for (var i = bits - 1; i >= 0; i--) {
      R = pointDouble(R, c);
      if ((k >> BigInt(i)) & 1n) R = pointAdd(R, P, c);
    }
    return R;
  }

  function toAffine(P, c) {
    if (P.z === 0n) throw new Error("无穷远点：私钥或公钥不合法");
    var zInv = inv(P.z, c.p);
    var z2 = (zInv * zInv) % c.p;
    var x = (P.x * z2) % c.p;
    var y = (P.y * z2 % c.p * zInv) % c.p;
    return { x: x, y: y };
  }

  function isOnCurve(x, y, c) {
    return mod(y * y - (x * x * x + c.a * x + c.b), c.p) === 0n;
  }

  function derivePublicKey(privateBytes, curveName) {
    var c = curve(curveName);
    var d = B.bytesToBigInt(privateBytes);
    if (d <= 0n || d >= c.n) throw new Error("私钥 d 必须在 1 .. n-1 之间");
    var Q = toAffine(scalarMult(d, { x: c.gx, y: c.gy, z: 1n }, c), c);
    return {
      x: B.bigIntToBytes(Q.x, c.size),
      y: B.bigIntToBytes(Q.y, c.size)
    };
  }

  function validatePublicPoint(qx, qy, curveName) {
    var c = curve(curveName);
    if (!isOnCurve(qx, qy, c)) throw new Error("公钥点不在 " + c.name + " 曲线上");
  }

  function pemToDer(pem) {
    var m = String(pem).match(/-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/);
    if (!m) throw new Error("PEM 格式不正确：找不到 BEGIN/END 行");
    return B.base64ToBytes(m[1]);
  }

  function derToPem(der, label) {
    var b64 = B.bytesToBase64(der);
    var lines = b64.match(/.{1,64}/g) || [b64];
    return "-----BEGIN " + (label || "PRIVATE KEY") + "-----\n" + lines.join("\n") + "\n-----END " + (label || "PRIVATE KEY") + "-----";
  }

  function jwkBase64(bytes) {
    return B.bytesToBase64Url(bytes);
  }

  function publicRawFromJwk(jwk) {
    var x = B.base64UrlToBytes(jwk.x);
    var y = B.base64UrlToBytes(jwk.y);
    return B.concat(new Uint8Array([0x04]), x, y);
  }

  function jwkFromPublic(rawOrJwk, curveName) {
    var c = curve(curveName);
    if (rawOrJwk && rawOrJwk.kty) return rawOrJwk;
    var raw = rawOrJwk instanceof Uint8Array ? rawOrJwk : B.hexToBytes(rawOrJwk);
    if (raw.length === c.size * 2 + 1 && raw[0] === 0x04) raw = raw.slice(1);
    if (raw.length !== c.size * 2) throw new Error(c.name + " 公钥应为 " + (c.size * 2) + " B 的 X‖Y（或 " + (c.size * 2 + 1) + " B 带 04 前缀）");
    var x = raw.slice(0, c.size);
    var y = raw.slice(c.size);
    validatePublicPoint(B.bytesToBigInt(x), B.bytesToBigInt(y), c.name);
    return { kty: "EC", crv: c.name, x: jwkBase64(x), y: jwkBase64(y), ext: true };
  }

  function jwkFromPrivate(dBytes, curveName, usage) {
    var c = curve(curveName);
    var d = dBytes instanceof Uint8Array ? dBytes : B.hexToBytes(dBytes);
    if (d.length > c.size) d = d.slice(d.length - c.size);
    while (d.length < c.size) d = B.concat(new Uint8Array([0]), d);
    var Q = derivePublicKey(d, c.name);
    var jwk = {
      kty: "EC",
      crv: c.name,
      x: jwkBase64(Q.x),
      y: jwkBase64(Q.y),
      d: jwkBase64(d),
      ext: true,
      key_ops: usage === "ECDH" ? ["deriveBits"] : ["sign"]
    };
    return jwk;
  }

  async function importPrivateKey(opts) {
    var curveName = opts.curve;
    var usage = opts.usage || "ECDSA";
    var alg = usage === "ECDH" ? { name: "ECDH", namedCurve: curveName } : { name: "ECDSA", namedCurve: curveName };
    var usages = usage === "ECDH" ? ["deriveBits"] : ["sign"];
    var format = (opts.format || "auto").toLowerCase();
    var data = opts.data;

    if (format === "auto") {
      var s = String(data || "").trim();
      if (s.indexOf("BEGIN") >= 0) format = "pem";
      else if (s.charAt(0) === "{") format = "jwk";
      else format = "raw";
    }

    if (format === "pem") {
      var der = typeof data === "string" ? pemToDer(data) : data;
      return subtle().importKey("pkcs8", der, alg, true, usages);
    }
    if (format === "jwk") {
      var jwk = typeof data === "string" ? JSON.parse(data) : data;
      return subtle().importKey("jwk", jwk, alg, true, usages);
    }
    if (format === "raw") {
      var d = data instanceof Uint8Array ? data : B.hexToBytes(data);
      var jwk2 = jwkFromPrivate(d, curveName, usage);
      return subtle().importKey("jwk", jwk2, alg, true, usages);
    }
    throw new Error("私钥格式只支持 PEM(PKCS#8) / JWK / 原始 d");
  }

  async function importPublicKey(opts) {
    var curveName = opts.curve;
    var usage = opts.usage || "ECDSA";
    var alg = usage === "ECDH" ? { name: "ECDH", namedCurve: curveName } : { name: "ECDSA", namedCurve: curveName };
    var usages = usage === "ECDH" ? [] : ["verify"];
    var format = (opts.format || "auto").toLowerCase();
    var data = opts.data;

    if (format === "auto") {
      var s = String(data || "").trim();
      if (s.indexOf("BEGIN") >= 0) format = "spki";
      else if (s.charAt(0) === "{") format = "jwk";
      else format = "raw";
    }
    if (format === "spki") {
      var der = typeof data === "string" ? pemToDer(data) : data;
      return subtle().importKey("spki", der, alg, true, usages);
    }
    if (format === "jwk") {
      var jwk = typeof data === "string" ? JSON.parse(data) : data;
      return subtle().importKey("jwk", jwk, alg, true, usages);
    }
    if (format === "raw") {
      var raw = data instanceof Uint8Array ? data : B.hexToBytes(data);
      var jwk2 = jwkFromPublic(raw, curveName);
      return subtle().importKey("jwk", jwk2, alg, true, usages);
    }
    throw new Error("公钥格式只支持 X‖Y / 04‖X‖Y / SPKI PEM / JWK");
  }

  async function generateKeyPair(curveName, usage) {
    var c = curve(curveName);
    var u = (usage || "ECDSA").toUpperCase();
    var alg = u === "ECDH" ? { name: "ECDH", namedCurve: c.name } : { name: "ECDSA", namedCurve: c.name };
    var usages = u === "ECDH" ? ["deriveBits"] : ["sign", "verify"];
    var kp = await subtle().generateKey(alg, true, usages);
    var privJwk = await subtle().exportKey("jwk", kp.privateKey);
    var pubRaw = new Uint8Array(await subtle().exportKey("raw", kp.publicKey));
    var pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", kp.privateKey));
    var publicJwk = {
      kty: "EC",
      crv: c.name,
      x: privJwk.x,
      y: privJwk.y,
      ext: true,
      key_ops: u === "ECDH" ? [] : ["verify"]
    };
    return {
      privateKey: kp.privateKey,
      publicKey: kp.publicKey,
      privateJwk: privJwk,
      publicJwk: publicJwk,
      publicRaw: pubRaw,
      publicRawXY: pubRaw.slice(1),
      pkcs8: pkcs8,
      pkcs8Pem: derToPem(pkcs8, "PRIVATE KEY")
    };
  }

  async function sign(opts) {
    var key = opts.privateKey;
    var hash = opts.hash || "SHA-256";
    var sig = await subtle().sign({ name: "ECDSA", hash: hash }, key, opts.message);
    return new Uint8Array(sig);
  }

  function isDerSignature(sig) {
    if (sig.length < 8 || sig[0] !== 0x30) return false;
    var len = sig[1];
    var header = 2;
    if (len & 0x80) {
      var n = len & 0x7f;
      if (n < 1 || n > 3 || sig.length < 2 + n) return false;
      len = 0;
      for (var i = 0; i < n; i++) len = (len << 8) | sig[2 + i];
      header = 2 + n;
    }
    return header + len === sig.length;
  }

  function derToRaw(sig, curveName) {
    var c = curve(curveName);
    if (!isDerSignature(sig)) {
      if (sig.length !== c.size * 2) throw new Error("签名长度应为 " + (c.size * 2) + " B（plain R‖S）或 DER");
      return new Uint8Array(sig);
    }
    var pos = 0;
    function readTlv() {
      if (pos + 2 > sig.length) throw new Error("DER 签名被截断");
      var tag = sig[pos++];
      var len = sig[pos++];
      if (len & 0x80) {
        var n = len & 0x7f;
        if (n < 1 || n > 3) throw new Error("DER 长度形式不支持");
        len = 0;
        for (var i = 0; i < n; i++) len = (len << 8) | sig[pos++];
      }
      if (pos + len > sig.length) throw new Error("DER 长度超出签名范围");
      var value = sig.slice(pos, pos + len);
      pos += len;
      return { tag: tag, value: value };
    }
    var seq = readTlv();
    if (seq.tag !== 0x30) throw new Error("DER 签名缺少 SEQUENCE");
    var body = seq.value;
    var p = 0;
    function readInt() {
      if (p + 2 > body.length) throw new Error("DER INTEGER 被截断");
      var tag = body[p++];
      var len = body[p++];
      if (len & 0x80) {
        var n = len & 0x7f;
        if (n < 1 || n > 3) throw new Error("DER INTEGER 长度形式不支持");
        len = 0;
        for (var i = 0; i < n; i++) len = (len << 8) | body[p++];
      }
      if (p + len > body.length) throw new Error("DER INTEGER 长度超出范围");
      var v = body.slice(p, p + len);
      p += len;
      return { tag: tag, value: v };
    }
    var r = readInt();
    var s = readInt();
    if (r.tag !== 0x02 || s.tag !== 0x02) throw new Error("DER 签名缺少 INTEGER");
    if (p !== body.length) throw new Error("DER 签名有多余字节");
    function trimInt(v) {
      var i = 0;
      while (i < v.length - 1 && v[i] === 0) i++;
      v = v.slice(i);
      if (v.length > c.size) throw new Error("DER 整数超出曲线长度");
      var out = new Uint8Array(c.size);
      out.set(v, c.size - v.length);
      return out;
    }
    return B.concat(trimInt(r.value), trimInt(s.value));
  }

  function rawToDer(sig, curveName) {
    var c = curve(curveName);
    if (sig.length !== c.size * 2) throw new Error("plain 签名应为 " + (c.size * 2) + " B");
    function intBytes(v) {
      var i = 0;
      while (i < v.length - 1 && v[i] === 0) i++;
      v = v.slice(i);
      if (v[0] & 0x80) v = B.concat(new Uint8Array([0]), v);
      return B.concat(new Uint8Array([0x02, v.length]), v);
    }
    var body = B.concat(intBytes(sig.slice(0, c.size)), intBytes(sig.slice(c.size)));
    return B.concat(new Uint8Array([0x30, body.length]), body);
  }

  async function verify(opts) {
    var key = opts.publicKey;
    var hash = opts.hash || "SHA-256";
    var sig = opts.signature;
    if (isDerSignature(sig)) sig = derToRaw(sig, opts.curve);
    try {
      return await subtle().verify({ name: "ECDSA", hash: hash }, key, sig, opts.message);
    } catch (e) {
      return false;
    }
  }

  async function ecdh(opts) {
    var privateKey = opts.privateKey;
    var publicKey = opts.publicKey;
    var c = curve(opts.curve);
    var bits = c.size * 8;
    var buf = await subtle().deriveBits({ name: "ECDH", public: publicKey }, privateKey, bits);
    return new Uint8Array(buf);
  }

  function hashForCurve(curveName) {
    return String(curveName).toUpperCase() === "P-384" ? "SHA-384" : "SHA-256";
  }

  DLMS.EC = {
    CURVES: CURVES,
    curve: curve,
    derivePublicKey: derivePublicKey,
    validatePublicPoint: validatePublicPoint,
    jwkFromPrivate: jwkFromPrivate,
    jwkFromPublic: jwkFromPublic,
    importPrivateKey: importPrivateKey,
    importPublicKey: importPublicKey,
    generateKeyPair: generateKeyPair,
    sign: sign,
    verify: verify,
    ecdh: ecdh,
    derToRaw: derToRaw,
    rawToDer: rawToDer,
    isDerSignature: isDerSignature,
    pemToDer: pemToDer,
    derToPem: derToPem,
    hashForCurve: hashForCurve
  };

  if (typeof module !== "undefined" && module.exports) module.exports = DLMS.EC;
})(typeof globalThis !== "undefined" ? globalThis : this);
