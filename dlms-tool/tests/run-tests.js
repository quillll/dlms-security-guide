/* 核心算法回归测试：node tests/run-tests.js */
"use strict";

const assert = require("assert");
const path = require("path");

require("../assets/js/core/bytes.js");
require("../assets/js/core/hash.js");
require("../assets/js/core/gcm.js");
require("../assets/js/core/aes-kw.js");
require("../assets/js/core/kdf.js");
require("../assets/js/core/crc.js");
require("../assets/js/core/ec.js");
require("../assets/js/core/x509.js");
require("../assets/js/core/dlms.js");

const fs = require("fs");

const B = global.DLMS.Bytes;
const H = global.DLMS.Hash;
const G = global.DLMS.GCM;
const KW = global.DLMS.AESKW;
const KDF = global.DLMS.KDF;
const CRC = global.DLMS.CRC;
const EC = global.DLMS.EC;
const X509 = global.DLMS.X509;
const D = global.DLMS.DLMS;

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log("  ✓ " + name);
  } catch (e) {
    failed++;
    console.error("  ✗ " + name);
    console.error("    " + (e && e.stack ? e.stack.split("\n").slice(0, 3).join("\n    ") : e));
  }
}

function hex(s) { return B.hexToBytes(s); }
function eqHex(actual, expected, label) {
  const a = B.bytesToHexCompact(actual);
  assert.strictEqual(a, expected.replace(/\s/g, "").toUpperCase(), label || "hex mismatch");
}

(async function main() {
  console.log("bytes");
  await test("hex 归一化与奇数位报错", async () => {
    assert.strictEqual(B.bytesToHex(hex("0x01 02:03-04")), "01 02 03 04");
    assert.throws(() => hex("ABC"), /奇数/);
  });

  console.log("hash");
  await test("MD5(abc)", async () => {
    eqHex(H.md5(B.utf8ToBytes("abc")), "900150983CD24FB0D6963F7D28E17F72");
  });
  await test("SHA-256(abc)", async () => {
    eqHex(await H.hash("SHA-256", B.utf8ToBytes("abc")), "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
  });

  const EK = hex("000102030405060708090A0B0C0D0E0F");
  const AK = hex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF");
  const ST = hex("4D4D4D0000BC614E");
  const IC = hex("01234567");
  const P = hex("C0010000080000010000FF0200");
  const IV = B.concat(ST, IC);

  console.log("Table 48");
  await test("认证+加密 C / tag", async () => {
    const r = await G.gcmEncrypt({ key: EK, iv: IV, aad: B.concat(hex("30"), AK), plaintext: P });
    eqHex(r.ciphertext, "411312FF935A47566827C467BC", "C");
    eqHex(r.tag, "7D825C3BE4A77C3FCC056B6B", "T");
  });
  await test("仅认证 tag（P 为空，APDU 进 AAD）", async () => {
    const r = await G.gcmEncrypt({
      key: EK, iv: IV,
      aad: B.concat(hex("10"), AK, P),
      plaintext: new Uint8Array(0)
    });
    eqHex(r.tag, "06725D910F9221D263877516", "T");
  });
  await test("仅加密 C（tag 不携带）", async () => {
    const r = await G.gcmEncrypt({ key: EK, iv: IV, aad: new Uint8Array(0), plaintext: P });
    eqHex(r.ciphertext, "411312FF935A47566827C467BC", "C");
    eqHex(r.tag, "0387BA79BDB9DF0E1349AE2A", "T(first 12)");
  });
  await test("解密 + 验 tag", async () => {
    const r = await G.gcmDecrypt({
      key: EK, iv: IV,
      aad: B.concat(hex("30"), AK),
      ciphertext: hex("411312FF935A47566827C467BC"),
      tag: hex("7D825C3BE4A77C3FCC056B6B")
    });
    eqHex(r.plaintext, "C0010000080000010000FF0200");
  });
  await test("篡改 tag 触发 AUTH_FAILED", async () => {
    await assert.rejects(
      G.gcmDecrypt({
        key: EK, iv: IV,
        aad: B.concat(hex("30"), AK),
        ciphertext: hex("411312FF935A47566827C467BC"),
        tag: hex("000000000000000000000000")
      }),
      (e) => e.code === "AUTH_FAILED"
    );
  });

  console.log("Table 51 · HLS GMAC");
  await test("f(StoC)", async () => {
    const r = await G.gmac({
      key: EK,
      iv: B.concat(hex("4D4D4D0000000001"), hex("00000001")),
      aad: B.concat(hex("10"), AK, hex("503677524A323146"))
    });
    eqHex(r.tag, "1A52FE7DD3E72748973C1E28");
  });
  await test("f(CtoS)", async () => {
    const r = await G.gmac({
      key: EK,
      iv: B.concat(hex("4D4D4D0000BC614E"), hex("01234567")),
      aad: B.concat(hex("10"), AK, hex("4B35366956616759"))
    });
    eqHex(r.tag, "FE1466AFB3DBCD4F9389E2B7");
  });

  console.log("AES Key Wrap");
  await test("RFC 3394 向量", async () => {
    const kek = hex("11111111111111111111111111111111");
    const key = hex("000102030405060708090A0B0C0D0E0F");
    const wrapped = await KW.wrap(kek, key);
    eqHex(wrapped, "2E407E7FE4E742B77DC1B743516DE8455C77DC7C7391D924");
    const back = await KW.unwrap(kek, wrapped);
    eqHex(back, "000102030405060708090A0B0C0D0E0F");
  });

  console.log("KDF · Annex C.1");
  await test("KDF(Z, AlgID, Sys-TC, Sys-TS)", async () => {
    const r = await KDF.concatKdf({
      z: hex("C1CF8FE7891AEF3617D7190795E61FE6C24EFC3CCA2E08469BAD1A225CE6EA08"),
      hash: "SHA-256",
      keydatalenBits: 256,
      algId: hex("60857405080300"),
      partyU: hex("4D4D4D0000BC614E"),
      partyV: hex("4D4D4D0000000001")
    });
    eqHex(r.key, "C5F4512846EDE51CFB8CCF59F08A694E002EDF66B4CB1739AC26A74E49712F46");
  });

  console.log("CRC");
  await test("CRC-16/X.25 (HDLC FCS)", async () => {
    assert.strictEqual(CRC.crc16(CRC.CRC16.X25, B.utf8ToBytes("123456789")), 0x906E);
  });
  await test("CRC-16/CCITT-FALSE", async () => {
    assert.strictEqual(CRC.crc16(CRC.CRC16["CCITT-FALSE"], B.utf8ToBytes("123456789")), 0x29B1);
  });
  await test("CRC-16/ARC", async () => {
    assert.strictEqual(CRC.crc16(CRC.CRC16.ARC, B.utf8ToBytes("123456789")), 0xBB3D);
  });
  await test("CRC-16/MODBUS", async () => {
    assert.strictEqual(CRC.crc16(CRC.CRC16.MODBUS, B.utf8ToBytes("123456789")), 0x4B37);
  });
  await test("CRC-32/ISO-HDLC", async () => {
    assert.strictEqual(CRC.crc32(CRC.CRC32["ISO-HDLC"], B.utf8ToBytes("123456789")), 0xCBF43926);
  });

  console.log("EC");
  await test("原始私钥 d 推导 P-256 公钥", async () => {
    const kp = await global.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await global.crypto.subtle.exportKey("jwk", kp.privateKey);
    const d = B.base64UrlToBytes(jwk.d);
    const q = EC.derivePublicKey(d, "P-256");
    eqHex(q.x, B.bytesToHexCompact(B.base64UrlToBytes(jwk.x)));
    eqHex(q.y, B.bytesToHexCompact(B.base64UrlToBytes(jwk.y)));
  });
  await test("原始私钥 d 推导 P-384 公钥", async () => {
    const kp = await global.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
    const jwk = await global.crypto.subtle.exportKey("jwk", kp.privateKey);
    const d = B.base64UrlToBytes(jwk.d);
    const q = EC.derivePublicKey(d, "P-384");
    eqHex(q.x, B.bytesToHexCompact(B.base64UrlToBytes(jwk.x)));
    eqHex(q.y, B.bytesToHexCompact(B.base64UrlToBytes(jwk.y)));
  });
  await test("ECDSA 签名 / raw↔DER / 验签", async () => {
    const kp = await EC.generateKeyPair("P-256", "ECDSA");
    const msg = B.utf8ToBytes("DLMS interoperability");
    const raw = await EC.sign({ privateKey: kp.privateKey, hash: "SHA-256", message: msg });
    assert.strictEqual(raw.length, 64);
    const der = EC.rawToDer(raw, "P-256");
    assert.ok(EC.isDerSignature(der));
    eqHex(EC.derToRaw(der, "P-256"), B.bytesToHexCompact(raw));
    assert.ok(await EC.verify({ publicKey: kp.publicKey, hash: "SHA-256", message: msg, signature: raw, curve: "P-256" }));
    assert.ok(await EC.verify({ publicKey: kp.publicKey, hash: "SHA-256", message: msg, signature: der, curve: "P-256" }));
    assert.ok(!(await EC.verify({ publicKey: kp.publicKey, hash: "SHA-256", message: B.utf8ToBytes("tampered"), signature: raw, curve: "P-256" })));
  });
  await test("ECDH 双方向共享秘密一致", async () => {
    const a = await EC.generateKeyPair("P-256", "ECDH");
    const b = await EC.generateKeyPair("P-256", "ECDH");
    const z1 = await EC.ecdh({ privateKey: a.privateKey, publicKey: b.publicKey, curve: "P-256" });
    const z2 = await EC.ecdh({ privateKey: b.privateKey, publicKey: a.publicKey, curve: "P-256" });
    eqHex(z1, B.bytesToHexCompact(z2));
  });
  await test("PKCS#8 PEM / SPKI PEM 导入", async () => {
    const kp = await EC.generateKeyPair("P-256", "ECDSA");
    const pk = await EC.importPrivateKey({ format: "pem", data: kp.pkcs8Pem, curve: "P-256", usage: "ECDSA" });
    const msg = B.utf8ToBytes("pem import");
    const sig = await EC.sign({ privateKey: pk, hash: "SHA-256", message: msg });
    const spki = new Uint8Array(await global.crypto.subtle.exportKey("spki", kp.publicKey));
    const pub = await EC.importPublicKey({ format: "spki", data: EC.derToPem(spki, "PUBLIC KEY"), curve: "P-256", usage: "ECDSA" });
    assert.ok(await EC.verify({ publicKey: pub, hash: "SHA-256", message: msg, signature: sig, curve: "P-256" }));
  });
  await test("Table 52 · 客户端 f(StoC) 验签", async () => {
    const pub = await EC.importPublicKey({
      format: "raw",
      curve: "P-256",
      usage: "ECDSA",
      data: hex("917DBFECA43307375247989F07CC23F53D4B963AF8026C749DB33852011056DFDBE8327BD69CC149F018A8E446DDA6C55BCD78E596A56D403236233F93CC89B3")
    });
    const msg = B.concat(
      hex("4D4D4D0000BC614E"),
      hex("4D4D4D0000000001"),
      hex("18E95FFE3AD0DCABDC5D0D141DC987E270CB0A395948D4231B09DE6579883657"),
      hex("2CA1FC2DE9CD03B5E8E234CEA16F2853F6DC5F54526F4F4995772A50FB7E63B3")
    );
    const sig = hex("C5C6D6620BDB1A39FCE50F4D64F0DB712D6FB57A64030B0C297E1250DC859660D3B1FA334AD80411807369F5DD3BC17B59894C9E9C11C59376580D15A2646D16");
    assert.ok(await EC.verify({ publicKey: pub, hash: "SHA-256", message: msg, signature: sig, curve: "P-256" }));
  });
  await test("Table 52 · 服务端 f(CtoS) 验签", async () => {
    const pub = await EC.importPublicKey({
      format: "raw",
      curve: "P-256",
      usage: "ECDSA",
      data: hex("E4D07CEB0A5A6DA9D2228B054A1F5E295E1747A963974AF75091A0B0BC2FB92DA7D2ABD9FDD41579F36A1C8171A0CB638221DF1949FD95C8FAE148896920450D")
    });
    const msg = B.concat(
      hex("4D4D4D0000000001"),
      hex("4D4D4D0000BC614E"),
      hex("2CA1FC2DE9CD03B5E8E234CEA16F2853F6DC5F54526F4F4995772A50FB7E63B3"),
      hex("18E95FFE3AD0DCABDC5D0D141DC987E270CB0A395948D4231B09DE6579883657")
    );
    const sig = hex("946C2E3E4F18291571F4A45ACB7086100574694A3BAF67D2D147FE8F92481A5AB2186C5CBC3F80E94482D9388B85C6A73E5FD687F09773C1F615AA2A905ED057");
    assert.ok(await EC.verify({ publicKey: pub, hash: "SHA-256", message: msg, signature: sig, curve: "P-256" }));
  });

  console.log("X.509");
  const rootPem = fs.readFileSync(path.join(__dirname, "fixtures/root.pem"), "utf8");
  const interPem = fs.readFileSync(path.join(__dirname, "fixtures/inter.pem"), "utf8");
  const leafPem = fs.readFileSync(path.join(__dirname, "fixtures/leaf.pem"), "utf8");
  const rootCert = X509.parseCertificate(X509.parsePem(rootPem)[0].der);
  const interCert = X509.parseCertificate(X509.parsePem(interPem)[0].der);
  const leafCert = X509.parseCertificate(X509.parsePem(leafPem)[0].der);

  await test("解析 Root CA 基本字段", async () => {
    assert.ok(rootCert.subject.text.indexOf("CN=Example DLMS Root CA") >= 0);
    assert.strictEqual(rootCert.version, 3);
    assert.strictEqual(rootCert.spki.curveName, "P-256");
    assert.strictEqual(rootCert.extensions["2.5.29.19"].value.ca, true);
    assert.ok(rootCert.extensions["2.5.29.15"].value.usages.indexOf("keyCertSign") >= 0);
  });
  await test("解析 Leaf 扩展 / SAN / keyUsage", async () => {
    assert.ok(leafCert.subject.text.indexOf("CN=DLMS-SERVER-0001") >= 0);
    assert.strictEqual(leafCert.extensions["2.5.29.19"].value.ca, false);
    assert.ok(leafCert.extensions["2.5.29.15"].value.usages.indexOf("digitalSignature") >= 0);
    assert.ok(leafCert.extensions["2.5.29.15"].value.usages.indexOf("keyAgreement") >= 0);
    const san = leafCert.extensions["2.5.29.17"].value.names;
    assert.ok(san.some((n) => n.type === "dNSName" && n.value === "meter.example"));
    assert.ok(san.some((n) => n.type === "iPAddress" && n.value === "192.0.2.10"));
  });
  await test("证书签名验证（leaf ← inter ← root）", async () => {
    const a = await X509.verifyCertificate(leafCert, interCert);
    const b = await X509.verifyCertificate(interCert, rootCert);
    const c = await X509.verifyCertificate(rootCert, rootCert);
    assert.ok(a.ok, a.reason);
    assert.ok(b.ok, b.reason);
    assert.ok(c.ok, c.reason);
  });
  await test("证书链验证通过", async () => {
    const r = await X509.verifyChain([leafCert, interCert, rootCert]);
    assert.ok(r.ok, JSON.stringify(r.links.map((l) => l.signature)));
    assert.strictEqual(r.links.length, 2);
  });
  await test("篡改签名后验证失败", async () => {
    const bad = Object.assign({}, leafCert);
    bad.signature = new Uint8Array(leafCert.signature);
    bad.signature[0] ^= 0xFF;
    const r = await X509.verifyCertificate(bad, interCert);
    assert.strictEqual(r.ok, false);
  });
  await test("公钥提取与指纹", async () => {
    const pub = X509.extractPublicKey(leafCert);
    assert.strictEqual(pub.rawXY.replace(/\s/g, "").length, 128);
    assert.ok(pub.spkiPem.indexOf("BEGIN PUBLIC KEY") >= 0);
    assert.strictEqual((await X509.fingerprint(leafCert.der)).length, 32);
  });
  await test("P-384 证书解析与自签名验证", async () => {
    const pem = fs.readFileSync(path.join(__dirname, "fixtures/p384.pem"), "utf8");
    const c = X509.parseCertificate(X509.parsePem(pem)[0].der);
    assert.strictEqual(c.spki.curveName, "P-384");
    assert.strictEqual(c.signatureAlgorithm.hash, "SHA-384");
    const r = await X509.verifyCertificate(c, c);
    assert.ok(r.ok, r.reason);
  });
  await test("RSA 证书解析与自签名验证", async () => {
    const pem = fs.readFileSync(path.join(__dirname, "fixtures/rsa.pem"), "utf8");
    const c = X509.parseCertificate(X509.parsePem(pem)[0].der);
    assert.strictEqual(c.spki.algorithm.keyType, "RSA");
    assert.strictEqual(c.signatureAlgorithm.hash, "SHA-256");
    const r = await X509.verifyCertificate(c, c);
    assert.ok(r.ok, r.reason);
  });

  console.log("DLMS 安全层");
  const baseOpts = { plaintext: P, st: ST, ic: IC, ek: EK, ak: AK, suite: 0 };
  await test("构建 C8 认证+加密报文", async () => {
    const r = await D.protect(Object.assign({}, baseOpts, { auth: true, enc: true, family: "service-glo" }));
    eqHex(r.apdu, "C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B");
    assert.strictEqual(r.parsed.family, "service-glo");
    assert.strictEqual(r.parsed.sc, 0x30);
    assert.strictEqual(r.parsed.lengthOk, true);
  });
  await test("构建 C8 仅认证报文", async () => {
    const r = await D.protect(Object.assign({}, baseOpts, { auth: true, enc: false, family: "service-glo" }));
    eqHex(r.apdu, "C81E1001234567C0010000080000010000FF020006725D910F9221D263877516");
  });
  await test("构建 C8 仅加密报文", async () => {
    const r = await D.protect(Object.assign({}, baseOpts, { auth: false, enc: true, family: "service-glo" }));
    eqHex(r.apdu, "C8122001234567411312FF935A47566827C467BC");
  });
  await test("解析并解密 C8", async () => {
    const r = await D.decrypt({
      apdu: "C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B",
      st: ST, ek: EK, ak: AK, suite: 0
    });
    eqHex(r.plaintext, "C0010000080000010000FF0200");
    assert.strictEqual(r.verified, true);
  });
  await test("general-glo 构建 / 解析 / 解密", async () => {
    const r = await D.protect(Object.assign({}, baseOpts, { auth: true, enc: true, family: "general-glo" }));
    assert.strictEqual(r.apdu[0], 0xDB);
    const p = D.parse(r.apdu);
    assert.strictEqual(p.family, "general-glo");
    eqHex(p.systemTitle, "4D4D4D0000BC614E");
    const d = await D.decrypt({ apdu: r.apdu, ek: EK, ak: AK, suite: 0 });
    eqHex(d.plaintext, "C0010000080000010000FF0200");
  });
  await test("HLS-5 输出 17 B", async () => {
    const r = await D.hls5({
      challenge: hex("503677524A323146"),
      ek: EK, ak: AK, st: hex("4D4D4D0000000001"), ic: hex("00000001"), suite: 0
    });
    eqHex(r.output, "10000000011A52FE7DD3E72748973C1E28");
  });
  await test("HLS-5 Suite 1 / Suite 2 的 SC", async () => {
    const r1 = await D.hls5({ challenge: hex("503677524A323146"), ek: EK, ak: AK, st: hex("4D4D4D0000000001"), ic: hex("00000001"), suite: 1 });
    assert.strictEqual(r1.output[0], 0x11);
    const ek2 = new Uint8Array(32).fill(0x11);
    const ak2 = new Uint8Array(32).fill(0x22);
    const r2 = await D.hls5({ challenge: hex("503677524A323146"), ek: ek2, ak: ak2, st: hex("4D4D4D0000000001"), ic: hex("00000001"), suite: 2 });
    assert.strictEqual(r2.output[0], 0x12);
  });
  await test("Suite 2 保护/解密往返", async () => {
    const ek2 = new Uint8Array(32).fill(0x11);
    const ak2 = new Uint8Array(32).fill(0x22);
    const r = await D.protect({ plaintext: P, st: ST, ic: IC, ek: ek2, ak: ak2, suite: 2, auth: true, enc: true, family: "service-glo" });
    const d = await D.decrypt({ apdu: r.apdu, st: ST, ek: ek2, ak: ak2, suite: 2 });
    eqHex(d.plaintext, "C0010000080000010000FF0200");
  });
  await test("HDLC FCS 解析", async () => {
    const apdu = hex("C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B");
    const header = hex("A0 1E 00 02 03 23 21 E6 E6 00");
    const withoutFcs = B.concat(header, apdu);
    const fcs = CRC.hdlcFcs(withoutFcs);
    const body = B.concat(withoutFcs, fcs.bytesLE);
    const escaped = [];
    for (const b of body) {
      if (b === 0x7E) { escaped.push(0x7D, 0x5E); }
      else if (b === 0x7D) { escaped.push(0x7D, 0x5D); }
      else escaped.push(b);
    }
    const frame = B.concat(new Uint8Array([0x7E]), new Uint8Array(escaped), new Uint8Array([0x7E]));
    const r = D.parseHdlcFrame(frame);
    assert.strictEqual(r.type, "HDLC");
    assert.strictEqual(r.fcsOk, true);
    eqHex(r.apdu, "C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B");
  });
  await test("wrapper 帧解析", async () => {
    const apdu = hex("C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B");
    const frame = B.concat(hex("00 01 00 01 00 01"), new Uint8Array([0, apdu.length]), apdu);
    const r = D.parseWrapperFrame(frame);
    assert.strictEqual(r.type, "WRAPPER");
    assert.strictEqual(r.lengthOk, true);
    eqHex(r.apdu, B.bytesToHexCompact(apdu));
  });
  await test("general-ciphering 结构解析", async () => {
    const base = await D.protect(Object.assign({}, baseOpts, { auth: true, enc: true, family: "service-glo" }));
    const tx = hex("0102030405060708");
    const org = hex("4D4D4D0000BC614E");
    const rec = hex("4D4D4D0000000001");
    const keyInfo = B.concat(hex("01 02 01 01 04"), hex("AABBCCDD"));
    const apdu = B.concat(
      new Uint8Array([0xDD]),
      D.writeOctetString(tx), D.writeOctetString(org), D.writeOctetString(rec),
      new Uint8Array([0x00, 0x00]), keyInfo, D.writeOctetString(base.payload)
    );
    const p = D.parse(apdu);
    assert.strictEqual(p.family, "general-ciphering");
    assert.strictEqual(p.keyInfo.choiceName, "agreed");
    assert.strictEqual(p.lengthOk, true);
    eqHex(p.originatorSystemTitle, "4D4D4D0000BC614E");
  });
  await test("general-signing 结构解析", async () => {
    const tx = hex("0102030405060708");
    const org = hex("4D4D4D0000BC614E");
    const rec = hex("4D4D4D0000000001");
    const sig = new Uint8Array(64).fill(0xAA);
    const apdu = B.concat(
      new Uint8Array([0xDF]),
      D.writeOctetString(tx), D.writeOctetString(org), D.writeOctetString(rec),
      new Uint8Array([0x00, 0x00]), D.writeOctetString(P), D.writeOctetString(sig)
    );
    const p = D.parse(apdu);
    assert.strictEqual(p.family, "general-signing");
    assert.strictEqual(p.lengthOk, true);
    eqHex(p.content, "C0010000080000010000FF0200");
    assert.strictEqual(p.signature.length, 64);
  });

  console.log("");
  console.log(passed + " passed, " + failed + " failed");
  process.exit(failed ? 1 : 0);
})();
