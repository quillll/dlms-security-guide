/* 生成界面截图：node tests/screenshots.js */
"use strict";
const fs = require("fs");
const path = require("path");
const PORT = 9223;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

(async function () {
  const targets = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
  const page = targets.find(t => t.type === "page" && t.url.indexOf("8765") >= 0);
  if (!page) throw new Error("找不到页面");
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 1; const pending = new Map();
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result); } };
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  const send = (method, params) => new Promise((resolve, reject) => { const i = id++; pending.set(i, { resolve, reject }); ws.send(JSON.stringify({ id: i, method, params: params || {} })); });
  const evaluate = async expression => { const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.text); return r.result.value; };
  const shot = async name => {
    const r = await send("Page.captureScreenshot", { format: "png", fromSurface: true });
    const out = path.join(__dirname, "..", name);
    fs.writeFileSync(out, Buffer.from(r.data, "base64"));
    console.log("saved", out);
  };

  await send("Runtime.enable"); await send("Page.enable");
  await send("Page.reload", { ignoreCache: true });
  await sleep(1200);
  await send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1100, deviceScaleFactor: 1, mobile: false });
  await evaluate("document.querySelector('.nav-item[data-view=\"aes\"]').click(); document.getElementById('aes-load').click()");
  await sleep(900);
  await shot("_shot-aes.png");

  await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  await sleep(300);
  await shot("_shot-mobile.png");
  await send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1100, deviceScaleFactor: 1, mobile: false });
  await sleep(300);

  await evaluate("document.querySelector('.nav-item[data-view=\"registry\"]').click()");
  await sleep(400);
  await shot("_shot-registry.png");

  await evaluate("document.querySelector('.nav-item[data-view=\"cert\"]').click(); document.getElementById('cert-load-sample').click()");
  await sleep(1800);
  await shot("_shot-cert.png");

  await evaluate("document.querySelector('.nav-item[data-view=\"vectors\"]').click(); document.getElementById('vectors-run-all').click()");
  await sleep(5000);
  await shot("_shot-vectors.png");

  await evaluate("document.querySelector('.nav-item[data-view=\"hls\"]').click(); document.getElementById('hls-load51').click()");
  await sleep(900);
  await shot("_shot-hls.png");

  await evaluate("document.querySelector('.nav-item[data-view=\"keys\"]').click(); document.querySelector('[data-keys-tab=\"ecdh\"]').click(); document.getElementById('ecdh-run').click()");
  await sleep(1600);
  await shot("_shot-keys.png");

  await evaluate("document.querySelector('.nav-item[data-view=\"hash\"]').click(); document.getElementById('hash-run').click(); document.getElementById('crc-run').click()");
  await sleep(700);
  await shot("_shot-hash.png");

  await evaluate("document.querySelector('.nav-item[data-view=\"sign\"]').click(); document.getElementById('sign-run').click()");
  await sleep(800);
  await shot("_shot-sign.png");

  await evaluate(`document.querySelector('.nav-item[data-view="parse"]').click();
    document.getElementById('parse-input').value='C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B';
    document.getElementById('parse-run').click()`);
  await sleep(700);
  await shot("_shot-parse.png");

  ws.close();
})().catch(e => { console.error(e); process.exit(1); });
