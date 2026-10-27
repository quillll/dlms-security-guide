/* UI 冒烟测试：通过 CDP 驱动无头 Edge，验证页面按钮与结果。
   先启动：
     python -m http.server 8765 --bind 127.0.0.1
     msedge --headless=new --remote-debugging-port=9223 ... http://127.0.0.1:8765/index.html
   再运行：node tests/ui-smoke.js
*/
"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const PORT = 9223;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function norm(s) { return String(s || "").replace(/\s+/g, "").toUpperCase(); }

(async function main() {
  let targets;
  for (let i = 0; i < 20; i++) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
      if (targets.some(t => t.type === "page" && t.url.indexOf("8765") >= 0)) break;
    } catch (e) {}
    await sleep(250);
  }
  const page = (targets || []).find(t => t.type === "page" && t.url.indexOf("8765") >= 0);
  if (!page) throw new Error("找不到页面；请先启动 Edge 调试实例");

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let nextId = 1;
  const pending = new Map();
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message));
      else resolve(msg.result);
    }
  };
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });

  function send(method, params) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params: params || {} }));
    });
  }

  async function evaluate(expression) {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + " " + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || ""));
    return r.result.value;
  }

  let pass = 0, fail = 0;
  async function check(name, fn) {
    try { await fn(); pass++; console.log("  ✓ " + name); }
    catch (e) { fail++; console.error("  ✗ " + name + "\n    " + e.message); }
  }

  await send("Runtime.enable");
  await send("Page.enable");
  await send("Page.reload", { ignoreCache: true });
  await sleep(1200);
  const ready = await evaluate("document.body.classList.contains('js-ready')");
  if (!ready) throw new Error("页面未完成初始化");
  const jsError = await evaluate("document.documentElement.getAttribute('data-js-error')");
  const jsRej = await evaluate("document.documentElement.getAttribute('data-js-rejection')");
  if (jsError) throw new Error("JS error: " + jsError);
  if (jsRej) throw new Error("JS rejection: " + jsRej);

  await check("AES · 载入 Table 48 并生成 C8", async () => {
    await evaluate("document.getElementById('aes-load').click()");
    await sleep(900);
    const t = await evaluate("document.getElementById('aes-result').innerText");
    assert.ok(t.indexOf("已生成 12 B 认证标签") >= 0, t.slice(0, 200));
    assert.ok(norm(t).indexOf("7D825C3BE4A77C3FCC056B6B") >= 0, t.slice(0, 400));
  });

  await check("GMAC · Table 51 f(StoC)", async () => {
    await evaluate("document.getElementById('gmac-load').click()");
    await sleep(700);
    const t = await evaluate("document.getElementById('gmac-result').innerText");
    assert.ok(norm(t).indexOf("1A52FE7DD3E72748973C1E28") >= 0, t.slice(0, 400));
  });

  await check("HLS · 载入 Table 51", async () => {
    await evaluate("document.getElementById('hls-load51').click()");
    await sleep(700);
    const t = await evaluate("document.getElementById('hls-result').innerText");
    assert.ok(t.indexOf("10000000011A52FE7DD3E72748973C1E28") >= 0, t.slice(0, 400));
    const out = await evaluate("document.querySelectorAll('#hls-result .io-cell code')[1].textContent");
    assert.strictEqual(norm(out), "10000000011A52FE7DD3E72748973C1E28");
  });

  await check("HLS · 载入 Table 52 客户端签名", async () => {
    await evaluate("document.getElementById('hls-load52').click()");
    await sleep(900);
    const t = await evaluate("document.getElementById('hls-result').innerText");
    assert.ok(t.indexOf("ECDSA 每次签名带随机数 k") >= 0, t.slice(0, 500));
    const out = norm(await evaluate("document.querySelectorAll('#hls-result .io-cell code')[1].textContent"));
    assert.strictEqual(out.length, 128, out);
    const ok = await evaluate(`(async()=>{
      var B=DLMS.Bytes,EC=DLMS.EC;
      var pub=await EC.importPublicKey({format:'raw',curve:'P-256',usage:'ECDSA',data:B.hexToBytes('917DBFECA43307375247989F07CC23F53D4B963AF8026C749DB33852011056DFDBE8327BD69CC149F018A8E446DDA6C55BCD78E596A56D403236233F93CC89B3')});
      var msg=B.concat(B.hexToBytes('4D4D4D0000BC614E'),B.hexToBytes('4D4D4D0000000001'),B.hexToBytes('18E95FFE3AD0DCABDC5D0D141DC987E270CB0A395948D4231B09DE6579883657'),B.hexToBytes('2CA1FC2DE9CD03B5E8E234CEA16F2853F6DC5F54526F4F4995772A50FB7E63B3'));
      return await EC.verify({publicKey:pub,hash:'SHA-256',message:msg,signature:B.hexToBytes('${out}'),curve:'P-256'});
    })()`);
    assert.strictEqual(ok, true, "客户端签名应能用 Pub-KC 验签");
  });

  await check("KDF · Annex C.1", async () => {
    await evaluate("document.getElementById('kdf-load').click()");
    await sleep(600);
    const t = await evaluate("document.getElementById('kdf-result').innerText");
    assert.ok(t.indexOf("C5F45128") >= 0, t.slice(0, 300));
  });

  await check("CRC · 0x906E", async () => {
    await evaluate("document.getElementById('crc-run').click()");
    await sleep(250);
    const t = await evaluate("document.getElementById('crc-result').value");
    assert.ok(t.indexOf("906E") >= 0, t);
  });

  await check("Hash · SHA-256(abc)", async () => {
    await evaluate("document.getElementById('hash-run').click()");
    await sleep(350);
    const t = await evaluate("document.getElementById('hash-result').value");
    assert.ok(norm(t).indexOf("BA7816BF") >= 0, t);
  });

  await check("证书 · 示例链解析与链式校验", async () => {
    await evaluate("document.getElementById('cert-load-sample').click()");
    await sleep(1600);
    const t = await evaluate("document.getElementById('cert-detail').innerText");
    assert.ok(t.indexOf("DLMS-SERVER-0001") >= 0, t.slice(0, 300));
    assert.ok(t.indexOf("链式校验通过") >= 0, t.slice(0, 800));
  });

  await check("报文解析 · Table 48 结构", async () => {
    await evaluate("document.getElementById('parse-input').value='C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B'");
    await evaluate("document.getElementById('parse-run').click()");
    await sleep(500);
    const t = await evaluate("document.getElementById('parse-result').innerText");
    assert.ok(t.indexOf("认证 tag") >= 0, t.slice(0, 400));
    assert.ok(t.indexOf("service-glo") >= 0, t.slice(0, 200));
  });

  await check("AES · 解密 Table 48", async () => {
    await evaluate("document.getElementById('aes-load').click()");
    await sleep(800);
    await evaluate("[...document.querySelectorAll('#aes-mode button')].find(b=>b.dataset.mode==='dec').click()");
    await sleep(200);
    await evaluate("document.getElementById('aes-run').click()");
    await sleep(800);
    const t = await evaluate("document.getElementById('aes-result').innerText");
    assert.ok(t.indexOf("认证标签校验通过") >= 0, t.slice(0, 300));
    assert.ok(norm(t).indexOf("C0010000080000010000FF0200") >= 0, t.slice(0, 500));
  });

  await check("AES · Suite 2 密钥长度校验", async () => {
    await evaluate("document.getElementById('aes-suite').value='2'; document.getElementById('aes-suite').dispatchEvent(new Event('change'))");
    await sleep(150);
    await evaluate("document.querySelector('#aes-mode button[data-mode=\"enc\"]').click()");
    await evaluate("document.getElementById('aes-run').click()");
    await sleep(500);
    const t = await evaluate("document.getElementById('aes-result').innerText");
    assert.ok(t.indexOf("需要 32 B") >= 0, t.slice(0, 300));
    await evaluate("document.getElementById('aes-suite').value='0'; document.getElementById('aes-suite').dispatchEvent(new Event('change'))");
    await sleep(150);
  });

  await check("GMAC · 报文 GMAC 模式", async () => {
    await evaluate("document.querySelector('#gmac-mode button[data-gmac=\"payload\"]').click()");
    await evaluate("document.getElementById('gmac-run').click()");
    await sleep(600);
    const t = await evaluate("document.getElementById('gmac-result').innerText");
    assert.ok(t.indexOf("仅认证，不加密") >= 0, t.slice(0, 300));
    assert.ok(norm(t).indexOf("1A52FE7DD3E72748973C1E28") >= 0, t.slice(0, 400));
  });

  await check("HLS · mechanism 3/4/6 输出长度", async () => {
    await evaluate("document.getElementById('hls-mech').value='3'; document.getElementById('hls-mech').dispatchEvent(new Event('change'))");
    await evaluate("document.getElementById('hls-run').click()");
    await sleep(400);
    let t = await evaluate("document.getElementById('hls-result').innerText");
    assert.ok(t.indexOf("16 B") >= 0, t.slice(0, 300));
    await evaluate("document.getElementById('hls-mech').value='4'; document.getElementById('hls-mech').dispatchEvent(new Event('change'))");
    await evaluate("document.getElementById('hls-run').click()");
    await sleep(400);
    t = await evaluate("document.getElementById('hls-result').innerText");
    assert.ok(t.indexOf("20 B") >= 0, t.slice(0, 300));
    await evaluate("document.getElementById('hls-mech').value='6'; document.getElementById('hls-mech').dispatchEvent(new Event('change'))");
    await evaluate("document.getElementById('hls-run').click()");
    await sleep(400);
    t = await evaluate("document.getElementById('hls-result').innerText");
    assert.ok(t.indexOf("32 B") >= 0, t.slice(0, 300));
    await evaluate("document.getElementById('hls-mech').value='5'; document.getElementById('hls-mech').dispatchEvent(new Event('change'))");
  });

  await check("密钥 · AES-KW 解包", async () => {
    await evaluate("document.querySelector('[data-keys-tab=\"kw\"]').click()");
    await evaluate("document.querySelector('#kw-mode button[data-kw=\"unwrap\"]').click()");
    await evaluate("document.getElementById('kw-key').value='2E407E7FE4E742B77DC1B743516DE8455C77DC7C7391D924'");
    await evaluate("document.getElementById('kw-run').click()");
    await sleep(600);
    const t = await evaluate("document.getElementById('kw-result').innerText");
    assert.ok(norm(t).indexOf("000102030405060708090A0B0C0D0E0F") >= 0, t.slice(0, 400));
  });

  await check("密钥 · ECDH + KDF", async () => {
    await evaluate("document.querySelector('[data-keys-tab=\"ecdh\"]').click()");
    await evaluate("document.getElementById('ecdh-run').click()");
    await sleep(1400);
    const t = await evaluate("document.getElementById('ecdh-result').innerText");
    assert.ok(t.indexOf("ECDH + KDF 完成") >= 0, t.slice(0, 400));
  });

  await check("签名 · 签名与验签", async () => {
    await evaluate("document.querySelector('.nav-item[data-view=\"sign\"]').click()");
    await evaluate("document.getElementById('sign-run').click()");
    await sleep(800);
    let t = await evaluate("document.getElementById('sign-result').innerText");
    assert.ok(t.indexOf("签名完成") >= 0, t.slice(0, 300));
    await evaluate("document.querySelector('#sign-mode button[data-sign=\"verify\"]').click()");
    await evaluate("document.getElementById('sign-run').click()");
    await sleep(700);
    t = await evaluate("document.getElementById('sign-result').innerText");
    assert.ok(t.indexOf("验签通过") >= 0, t.slice(0, 300));
  });

  await check("报文解析 · HDLC FCS", async () => {
    await evaluate(`(function(){
      var B=DLMS.Bytes,C=DLMS.CRC;
      var apdu=B.hexToBytes('C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B');
      var header=B.hexToBytes('A0 1E 00 02 03 23 21 E6 E6 00');
      var wf=B.concat(header,apdu), fcs=C.hdlcFcs(wf), body=B.concat(wf,fcs.bytesLE), esc=[];
      for (var i=0;i<body.length;i++){ var b=body[i]; if(b===0x7E){esc.push(0x7D,0x5E);} else if(b===0x7D){esc.push(0x7D,0x5D);} else esc.push(b); }
      var frame=B.concat(new Uint8Array([0x7E]),new Uint8Array(esc),new Uint8Array([0x7E]));
      document.getElementById('parse-input').value=B.bytesToHex(frame);
      document.getElementById('parse-run').click();
    })()`);
    await sleep(600);
    const t = await evaluate("document.getElementById('parse-result').innerText");
    assert.ok(t.indexOf("HDLC") >= 0, t.slice(0, 300));
    assert.ok(t.indexOf("FCS") >= 0, t.slice(0, 400));
  });

  await check("HLS · Table 52 服务端签名", async () => {
    await evaluate("document.querySelector('.nav-item[data-view=\"hls\"]').click()");
    await evaluate("document.querySelector('#hls-dir button[data-dir=\"server\"]').click()");
    await evaluate("document.getElementById('hls-load52').click()");
    await sleep(900);
    const t = await evaluate("document.getElementById('hls-result').innerText");
    assert.ok(t.indexOf("ECDSA 每次签名带随机数 k") >= 0, t.slice(0, 500));
    const out = norm(await evaluate("document.querySelectorAll('#hls-result .io-cell code')[1].textContent"));
    assert.strictEqual(out.length, 128, out);
    const ok = await evaluate(`(async()=>{
      var B=DLMS.Bytes,EC=DLMS.EC;
      var pub=await EC.importPublicKey({format:'raw',curve:'P-256',usage:'ECDSA',data:B.hexToBytes('E4D07CEB0A5A6DA9D2228B054A1F5E295E1747A963974AF75091A0B0BC2FB92DA7D2ABD9FDD41579F36A1C8171A0CB638221DF1949FD95C8FAE148896920450D')});
      var msg=B.concat(B.hexToBytes('4D4D4D0000000001'),B.hexToBytes('4D4D4D0000BC614E'),B.hexToBytes('2CA1FC2DE9CD03B5E8E234CEA16F2853F6DC5F54526F4F4995772A50FB7E63B3'),B.hexToBytes('18E95FFE3AD0DCABDC5D0D141DC987E270CB0A395948D4231B09DE6579883657'));
      return await EC.verify({publicKey:pub,hash:'SHA-256',message:msg,signature:B.hexToBytes('${out}'),curve:'P-256'});
    })()`);
    assert.strictEqual(ok, true, "服务端签名应能用 Pub-KS 验签");
  });

  await check("AES · Suite 2 (AES-256) 正常生成", async () => {
    await evaluate("document.querySelector('.nav-item[data-view=\"aes\"]').click()");
    await evaluate("document.getElementById('aes-suite').value='2'; document.getElementById('aes-suite').dispatchEvent(new Event('change'))");
    await evaluate("document.querySelector('#aes-mode button[data-mode=\"enc\"]').click()");
    await evaluate("document.querySelector('#aes-protect button[data-protect=\"ae\"]').click()");
    await evaluate("document.getElementById('aes-ek').value='11'.repeat(32); document.getElementById('aes-ak').value='22'.repeat(32); document.getElementById('aes-input').value='C0010000080000010000FF0200'");
    await evaluate("document.getElementById('aes-run').click()");
    await sleep(700);
    const t = await evaluate("document.getElementById('aes-result').innerText");
    assert.ok(t.indexOf("已生成 12 B 认证标签") >= 0, t.slice(0, 300));
    assert.ok(t.indexOf("需要 32 B") < 0, t.slice(0, 300));
    await evaluate("document.getElementById('aes-suite').value='0'; document.getElementById('aes-suite').dispatchEvent(new Event('change'))");
  });

  await check("证书 · 解析 RSA 证书并隐藏 EC 专用按钮", async () => {
    const pem = fs.readFileSync(path.join(__dirname, "fixtures/rsa.pem"), "utf8");
    await evaluate("document.querySelector('.nav-item[data-view=\"cert\"]').click()");
    await evaluate("document.getElementById('cert-input').value=" + JSON.stringify(pem) + "; document.getElementById('cert-parse').click()");
    await sleep(1400);
    const t = await evaluate("document.getElementById('cert-detail').innerText");
    assert.ok(t.indexOf("RSA 证书只做证书签名验证") >= 0, t.slice(0, 600));
    assert.ok(t.indexOf("复制 X‖Y") < 0, "不应显示 EC 专用按钮");
  });

  await check("整套证书 · 默认值 / 生成 / 清空 / 口令包恢复", async () => {
    await evaluate("document.querySelector('.nav-item[data-view=\"pki\"]').click()");
    assert.strictEqual(await evaluate("document.getElementById('pki-notbefore').value"), "2000-01-01");
    assert.strictEqual(await evaluate("document.getElementById('pki-notafter').value"), "2099-01-01");
    assert.strictEqual(await evaluate("document.getElementById('pki-o').value"), "");
    assert.strictEqual(await evaluate("document.getElementById('pki-c').value"), "");
    await evaluate("document.querySelector('#pki-auto button[data-auto=\"off\"]').click()");
    await evaluate("document.getElementById('pki-serial-s1-ca').value='0x0102'; document.getElementById('pki-serial-s1-client-sign').value='7'; document.getElementById('pki-serial-s1-client-key-agreement').value='ABCDEF'");
    await evaluate("document.getElementById('pki-run').click()");
    await sleep(3200);
    let t = await evaluate("document.getElementById('pki-state').innerText");
    assert.ok(t.indexOf("6 张证书") >= 0, t);
    assert.strictEqual(await evaluate("document.querySelectorAll('#pki-list tbody tr').length"), 6);
    assert.strictEqual(await evaluate("document.querySelectorAll('#pki-list [data-pki-act=\"privhex\"]').length"), 6);
    assert.strictEqual(await evaluate("document.querySelectorAll('#pki-list [data-pki-act=\"pubhex\"]').length"), 6);
    await evaluate("window.__pkiClip=null; Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:function(t){window.__pkiClip=t;return Promise.resolve();}}})");
    await evaluate("document.querySelector('#pki-list [data-pki-act=\"privhex\"]').click()");
    await sleep(150);
    const privHex = await evaluate("window.__pkiClip");
    assert.strictEqual(privHex.length, 64, "P-256 私钥应为 32 B / 64 HEX");
    assert.ok(/^[0-9A-F]+$/.test(privHex), privHex);
    await evaluate("document.querySelector('#pki-list [data-pki-act=\"pubhex\"]').click()");
    await sleep(150);
    const pubHex = await evaluate("window.__pkiClip");
    assert.strictEqual(pubHex.length, 128, "P-256 公钥应为 64 B / 128 HEX");
    assert.ok(/^[0-9A-F]+$/.test(pubHex), pubHex);
    const rows = await evaluate("[...document.querySelectorAll('#pki-list tbody tr')].map(tr=>tr.innerText).join('\\n')");
    assert.ok(rows.indexOf("0102") >= 0, rows.slice(0, 500));
    assert.strictEqual(await evaluate("document.getElementById('pki-export-zip').disabled"), false);

    const encText = await evaluate(`(async()=>{
      var b = await DLMS.PKIBundle.generate({systemTitle:'4D4D4D0000BC614E', suites:[1,2]});
      return await DLMS.PKIBundle.serialize(b, {passphrase:'ui-test'});
    })()`);
    await evaluate("document.getElementById('pki-clear').click()");
    await sleep(150);
    assert.strictEqual(await evaluate("document.querySelectorAll('#pki-list tbody tr').length"), 0);
    await evaluate("document.getElementById('pki-pass').value='ui-test'");
    await evaluate("document.getElementById('pki-import-text').value=" + JSON.stringify(encText) + "; document.getElementById('pki-import-run').click()");
    await sleep(4200);
    t = await evaluate("document.getElementById('pki-import-report').innerText");
    assert.ok(t.indexOf("密钥包校验通过") >= 0, t.slice(0, 500));
    assert.strictEqual(await evaluate("document.querySelectorAll('#pki-list tbody tr').length"), 6);
  });

  await check("测试向量 · 全部运行", async () => {
    await evaluate("document.getElementById('vectors-run-all').click()");
    await sleep(5000);
    const t = await evaluate("document.getElementById('vectors-summary').innerText");
    assert.ok(t.indexOf("13 / 13 通过") >= 0, t);
  });

  console.log("\nUI smoke: " + pass + " passed, " + fail + " failed");
  ws.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
