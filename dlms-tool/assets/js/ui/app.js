/* ============================================================
   DLMS 安全算法工作台 · 页面逻辑
   ============================================================ */
(function () {
  "use strict";

  var DLMS = globalThis.DLMS;
  var B = DLMS.Bytes, H = DLMS.Hash, G = DLMS.GCM, KW = DLMS.AESKW;
  var KDF = DLMS.KDF, CRC = DLMS.CRC, EC = DLMS.EC, X509 = DLMS.X509;
  var CG = DLMS.CertGen;
  var D = DLMS.DLMS, V = DLMS.Vectors, UI = DLMS.UI;
  var $ = UI.$, $$ = UI.$$;
  var toast = UI.toast;

  var VIEW_META = {
    aes: { title: "报文保护" },
    gmac: { title: "GMAC 认证" },
    hls: { title: "HLS 双向认证" },
    keys: { title: "密钥工具" },
    hash: { title: "哈希与校验" },
    sign: { title: "数字签名" },
    cert: { title: "X.509 证书" },
    certgen: { title: "证书签发" },
    parse: { title: "报文解析" },
    registry: { title: "算法总览" },
    vectors: { title: "测试向量" }
  };

  var currentView = "aes";

  function go(view) {
    if (!document.getElementById("view-" + view)) view = "aes";
    currentView = view;
    $$(".view").forEach(function (v) { v.classList.remove("active"); });
    var el = document.getElementById("view-" + view);
    if (el) el.classList.add("active");
    $$(".nav-item").forEach(function (b) {
      var on = b.getAttribute("data-view") === view;
      b.classList.toggle("active", on);
      if (on) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
    });
    var meta = VIEW_META[view];
    $("#crumbTitle").textContent = meta ? meta.title : "";
    document.body.classList.remove("nav-open");
    try { history.replaceState(null, "", "#" + view); } catch (e) {}
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function initNav() {
    $$("[data-view]").forEach(function (el) {
      el.addEventListener("click", function () { go(el.getAttribute("data-view")); });
    });
    $("#menuBtn").addEventListener("click", function () { document.body.classList.toggle("nav-open"); });
    $("#scrim").addEventListener("click", function () { document.body.classList.remove("nav-open"); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") document.body.classList.remove("nav-open");
    });
    var initial = (location.hash || "").replace(/^#\/?/, "");
    if (initial && VIEW_META[initial]) go(initial);
  }

  function setHexField(id, hexValue) {
    var input = document.getElementById(id);
    if (!input) return;
    input.dataset.hex = String(hexValue || "").replace(/\s/g, "");
    try {
      UI.formatBytesInput(input, B.hexToBytes(input.dataset.hex), input.dataset.fmt || "hex");
    } catch (e) {
      input.value = hexValue || "";
    }
    input.classList.remove("invalid");
  }

  function handleError(container, e) {
    var msg = e && e.message ? e.message : String(e);
    if (e && e.field) UI.setFieldError(e.field, msg);
    UI.toast(msg);
    UI.renderResultCard(container, {
      status: { kind: "bad", icon: "!", title: "计算失败", sub: msg },
      headerActions: ""
    });
    if (e && e.field) {
      var input = document.getElementById(e.field);
      if (input) input.focus();
    }
  }

  function busy(btn, on) {
    if (!btn) return;
    btn.disabled = !!on;
    btn.dataset.label = btn.dataset.label || btn.textContent;
    btn.textContent = on ? "计算中…" : btn.dataset.label;
  }

  /* ============================================================
     报文保护
     ============================================================ */
  var aesMode = "enc";
  var aesProtect = "ae";

  function aesKeyLen() {
    return parseInt($("#aes-suite").value, 10) === 2 ? 32 : 16;
  }

  function updateAESSuite() {
    var suite = parseInt($("#aes-suite").value, 10);
    var len = suite === 2 ? 32 : 16;
    $("#aes-ek-req").textContent = len + " B";
    $("#aes-ak-req").textContent = len + " B";
    $("#aes-suite-note").textContent = suite === 0
      ? "EK/AK 16 B · tag 12 B · 无 ECC"
      : suite === 1
        ? "AES-128 · P-256 · SHA-256 · EK/AK 16 B"
        : "AES-256 · P-384 · SHA-384 · EK/AK 32 B";
    ["aes-ek", "aes-ak"].forEach(function (id, idx) {
      var input = document.getElementById(id);
      var foot = document.getElementById(idx === 0 ? "aes-ek-foot" : "aes-ak-foot");
      var hint = document.getElementById(idx === 0 ? "aes-ek-hint" : "aes-ak-hint");
      if (!input || !foot) return;
      var n = 0;
      try { n = UI.bytesFromInput(input).length; } catch (e) {}
      if (n === len) {
        foot.textContent = "✓ " + len + " 字节 / " + (len * 8) + " bit";
        foot.className = "ok-text";
        hint.textContent = idx === 0 ? "AES 分组密钥" : "进 AAD：SC ‖ AK";
      } else if (n === 0) {
        foot.textContent = "待输入 " + len + " 字节";
        foot.className = "warn-text";
      } else {
        foot.textContent = "✗ Suite " + suite + " 需要 " + len + " B，当前 " + n + " B";
        foot.className = "bad-text";
      }
    });
  }

  function updateAESChip() {
    var input = $("#aes-input");
    var chip = $("#aes-input-chip");
    try {
      var bytes = UI.bytesFromInput(input);
      if (!bytes.length) { chip.style.display = "none"; return; }
      chip.style.display = "inline-flex";
      chip.textContent = D.tagName(bytes[0]);
    } catch (e) { chip.style.display = "none"; }
  }

  function setAESMode(mode) {
    if (aesMode === mode) return;
    aesMode = mode;
    UI.setSegment($("#aes-mode"), "data-mode", mode);
    var input = $("#aes-input");
    var hint = $("#aes-input-hint");
    var compact = (input.value || "").replace(/\s/g, "").toUpperCase();
    if (mode === "dec") {
      hint.textContent = "解密：完整安全报文（C8/DB/DC/DD/DF 或 SH‖C‖T）";
      if (compact === V.table48.plaintext) setHexField("aes-input", V.table48.authEnc);
    } else {
      hint.textContent = "加密：明文 APDU；解密：完整安全报文";
      if (compact === V.table48.authEnc) setHexField("aes-input", V.table48.plaintext);
    }
    updateAESChip();
  }

  function initAES() {
    $$("#aes-mode button").forEach(function (b) {
      b.addEventListener("click", function () { setAESMode(b.getAttribute("data-mode")); });
    });
    $$("#aes-protect button").forEach(function (b) {
      b.addEventListener("click", function () {
        aesProtect = b.getAttribute("data-protect");
        UI.setSegment($("#aes-protect"), "data-protect", aesProtect);
      });
    });
    $("#aes-suite").addEventListener("change", updateAESSuite);
    $("#aes-input").addEventListener("input", updateAESChip);
    $("#aes-run").addEventListener("click", aesRun);
    $("#aes-load").addEventListener("click", function () {
      setHexField("aes-st", V.table48.st);
      setHexField("aes-ic", V.table48.ic);
      setHexField("aes-ek", V.table48.ek);
      setHexField("aes-ak", V.table48.ak);
      setHexField("aes-input", V.table48.plaintext);
      $("#aes-suite").value = "0";
      $("#aes-family").value = "service-glo";
      aesMode = "enc";
      UI.setSegment($("#aes-mode"), "data-mode", "enc");
      aesProtect = "ae";
      UI.setSegment($("#aes-protect"), "data-protect", "ae");
      updateAESSuite();
      updateAESChip();
      aesRun();
    });
    $("#aes-reset").addEventListener("click", function () {
      ["aes-st", "aes-ic", "aes-ek", "aes-ak", "aes-input"].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) { el.value = ""; el.dataset.hex = ""; }
      });
      UI.emptyResult($("#aes-result"), "等待参数", "填入参数，或载入 Table 48 向量。", "i-shield");
      $("#aes-trace").innerHTML = '<h3>计算轨迹 <span class="badge">加密后显示</span></h3><div class="hint">K → IV → AAD → P → T，逐步展示中间值。</div>';
      toast("已重置");
    });
    updateAESSuite();
    updateAESChip();
  }

  async function aesRun() {
    var btn = $("#aes-run");
    busy(btn, true);
    UI.clearAllErrors();
    var mode = UI.activeButton($("#aes-mode")).getAttribute("data-mode");
    var protect = UI.activeButton($("#aes-protect")).getAttribute("data-protect");
    var suite = parseInt($("#aes-suite").value, 10);
    var family = $("#aes-family").value;
    var auth = protect !== "enc";
    var enc = protect !== "auth";
    try {
      var st = UI.readBytes("aes-st", 8, "System Title");
      var ic = UI.readBytes("aes-ic", 4, "IC");
      var ek = UI.readBytes("aes-ek", suite === 2 ? 32 : 16, "EK");
      var ak = auth ? UI.readBytes("aes-ak", suite === 2 ? 32 : 16, "AK") : null;
      var input = UI.readBytes("aes-input", null, "输入报文");
      if (mode === "enc") {
        var r = await D.protect({ plaintext: input, st: st, ic: ic, ek: ek, ak: ak, suite: suite, auth: auth, enc: enc, family: family });
        renderAESEncrypt(r, protect, family, suite, input);
      } else {
        var akDec = $("#aes-ak").value.trim() ? UI.readBytes("aes-ak", suite === 2 ? 32 : 16, "AK") : null;
        var d = await D.decrypt({ apdu: input, st: st, ek: ek, ak: akDec, suite: suite });
        renderAESDecrypt(d, family, suite, input);
      }
    } catch (e) {
      if (e && e.code === "AUTH_FAILED") {
        var msg = "认证失败：tag 不匹配。期望 " + (e.expected ? B.bytesToHex(e.expected) : "?") + "，实际 " + (e.actual ? B.bytesToHex(e.actual) : "?");
        UI.renderResultCard($("#aes-result"), { status: { kind: "bad", icon: "!", title: "认证失败", sub: msg } });
        toast("认证失败：tag 不匹配");
      } else {
        handleError($("#aes-result"), e);
      }
    } finally {
      busy(btn, false);
    }
  }

  function aesTrace(r, mode) {
    var items = [
      { label: "K · 加密密钥（EK）", value: B.bytesToHex(r.ek || []), note: (r.ek ? r.ek.length : 0) + " B" },
      { label: "IV = ST ‖ IC", value: B.bytesToHex(r.iv || []), note: "12 B · 用发送方 ST" },
      { label: "AAD", value: B.bytesToHex(r.aad || []), note: (r.aad ? r.aad.length : 0) + " B" },
      { label: mode === "enc" ? "P · 明文" : "C · 密文", value: B.bytesToHex(r.inputBytes || []), note: (r.inputBytes ? r.inputBytes.length : 0) + " B" }
    ];
    if (r.tag && r.tag.length) items.push({ label: "T · 认证标签", value: B.bytesToHex(r.tag), note: "12 B · GCM tag 前 12 B" });
    return items;
  }

  function renderAESEncrypt(r, protect, family, suite, plaintext) {
    var auth = protect !== "enc";
    var title = auth ? "已生成 " + r.tag.length + " B 认证标签" : "已生成安全报文（仅加密）";
    var sub = "Suite " + suite + " · " + (protect === "ae" ? "认证+加密" : protect === "auth" ? "仅认证（GMAC）" : "仅加密") + " · " + $("#aes-family").selectedOptions[0].textContent;
    var outLabel = auth ? (protect === "auth" ? "输出 · 内容（明文）+ tag" : "输出 · 密文 + tag") : "输出 · 密文";
    var outBytes = protect === "auth" ? plaintext : r.ciphertext;
    UI.renderResultCard($("#aes-result"), {
      status: { kind: protect === "enc" ? "warn" : "ok", icon: protect === "enc" ? "!" : "✓", title: title, sub: sub },
      headerActions: '<button class="icon-btn" data-copy="' + B.bytesToHexCompact(r.apdu) + '" aria-label="复制报文"><svg class="ico"><use href="#i-copy"/></svg></button>',
      io: {
        inLabel: "输入 · 明文 APDU", inCode: B.bytesToHex(plaintext), inSize: plaintext.length + " B",
        outLabel: outLabel, outCode: B.bytesToHex(outBytes), outSize: outBytes.length + " B" + (auth ? " + tag 12 B" : "")
      },
      bytes: r.apdu,
      fields: r.parsed.fields,
      extraHtml: '<div class="note" style="margin:0 16px 12px">' + (auth ? "tag 取 GCM 16 B 输出的前 12 B；Len 从 SC 起算，含 C 与 tag。" : "仅加密没有 tag，也没有完整性保护；不要把它当成“认证+加密”。") + "</div>",
      actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(r.apdu) + '">复制完整报文</button>' +
        '<button class="btn small ghost" data-download="' + B.bytesToHexCompact(r.apdu) + '" data-download-name="dlms-secured-apdu.txt">下载 .txt</button>' +
        '<button class="btn small ghost" data-aes-use="dec">作为解密输入</button>'
    });
    var use = $("#aes-result").querySelector("[data-aes-use]");
    if (use) use.addEventListener("click", function () {
      aesMode = "enc"; setAESMode("dec");
      setHexField("aes-input", B.bytesToHexCompact(r.apdu));
      go("aes");
      toast("已填入解密框；密钥仍沿用当前值");
    });
    $("#aes-trace").innerHTML = '<h3>计算轨迹 <span class="badge">可逐步复制</span></h3>' +
      UI.traceList([
        { label: "K · 加密密钥（EK）", value: B.bytesToHex(r.ek || []), note: (r.ek ? r.ek.length : 0) + " B" },
        { label: "IV = ST ‖ IC", value: B.bytesToHex(r.iv), note: "12 B" },
        { label: "AAD", value: B.bytesToHex(r.aad), note: r.aad.length + " B" },
        { label: "P · 明文", value: B.bytesToHex(plaintext), note: plaintext.length + " B" },
        auth ? { label: "T · 认证标签", value: B.bytesToHex(r.tag), note: "12 B" } : { label: "T", value: "—", note: "仅加密不带 tag" }
      ]);
  }

  function renderAESDecrypt(r, family, suite, input) {
    var plain = r.plaintext;
    var sub = "Suite " + suite + " · " + (r.verified === true ? "tag 校验通过" : "仅加密") + " · " + $("#aes-family").selectedOptions[0].textContent;
    UI.renderResultCard($("#aes-result"), {
      status: r.verified === true
        ? { kind: "ok", icon: "✓", title: "认证标签校验通过", sub: sub }
        : { kind: "warn", icon: "!", title: "仅加密：没有完整性保护", sub: "已解出明文，但无法证明报文未被改动" },
      headerActions: '<button class="icon-btn" data-copy="' + B.bytesToHexCompact(plain) + '" aria-label="复制明文"><svg class="ico"><use href="#i-copy"/></svg></button>',
      io: {
        inLabel: "输入 · 完整报文", inCode: UI.shortHex(input, 72), inSize: input.length + " B",
        outLabel: "输出 · 明文 APDU", outCode: B.bytesToHex(plain), outSize: plain.length + " B"
      },
      bytes: plain,
      fields: [{ name: "明文 APDU", offset: 0, length: plain.length, value: B.bytesToHex(plain), note: D.tagName(plain[0] || 0), color: "plain" }],
      extraHtml: '<div class="section-title" style="padding:0 16px">输入报文结构</div>' + UI.renderFieldTable(r.parsed.fields),
      actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(plain) + '">复制明文</button>' +
        '<button class="btn small ghost" data-download="' + B.bytesToHexCompact(plain) + '" data-download-name="dlms-plain.txt">下载 .txt</button>' +
        '<button class="btn small ghost" data-aes-use="enc">作为加密明文</button>'
    });
    var use = $("#aes-result").querySelector("[data-aes-use]");
    if (use) use.addEventListener("click", function () {
      setAESMode("enc");
      setHexField("aes-input", B.bytesToHexCompact(plain));
      go("aes");
      toast("已填入加密框");
    });
    $("#aes-trace").innerHTML = '<h3>计算轨迹 <span class="badge">可逐步复制</span></h3>' +
      UI.traceList([
        { label: "K · 加密密钥（EK）", value: "见输入", note: "" },
        { label: "IV = 发送方 ST ‖ IC", value: B.bytesToHex(r.iv), note: "12 B" },
        { label: "AAD", value: B.bytesToHex(r.aad), note: r.aad.length + " B" },
        { label: "C · 输入密文", value: UI.shortHex(r.parsed.ciphertext, 64), note: r.parsed.ciphertext.length + " B" },
        { label: "tag 校验", value: r.verified === true ? "通过" : "未校验（仅加密）", note: r.warning || "" }
      ]);
  }

  /* ============================================================
     GMAC
     ============================================================ */
  function initGMAC() {
    $$("#gmac-mode button").forEach(function (b) {
      b.addEventListener("click", function () {
        UI.setSegment($("#gmac-mode"), "data-gmac", b.getAttribute("data-gmac"));
        var hls = b.getAttribute("data-gmac") === "hls5";
        $("#gmac-content-label").textContent = hls ? "质询值 (challenge)" : "内容 / APDU";
        $("#gmac-content-req").textContent = hls ? "8 B" : "n B";
      });
    });
    $("#gmac-run").addEventListener("click", gmacRun);
    $("#gmac-load").addEventListener("click", function () {
      UI.setSegment($("#gmac-mode"), "data-gmac", "hls5");
      $("#gmac-content-label").textContent = "质询值 (challenge)";
      $("#gmac-suite").value = "0";
      setHexField("gmac-ek", V.table51.ek);
      setHexField("gmac-ak", V.table51.ak);
      setHexField("gmac-st", V.table51.clientST);
      setHexField("gmac-ic", V.table51.clientIC);
      setHexField("gmac-content", V.table51.stoC);
      updateGMACSuite();
      gmacRun();
    });
    function updateGMACSuite() {
      var len = parseInt($("#gmac-suite").value, 10) === 2 ? 32 : 16;
      ["gmac-ek", "gmac-ak"].forEach(function (id) {
        var input = document.getElementById(id);
        var req = document.getElementById(id + "-req");
        var foot = document.getElementById(id + "-foot");
        if (req) req.textContent = len + " B";
        if (!input || !foot) return;
        var n = 0;
        try { n = UI.bytesFromInput(input).length; } catch (e) {}
        if (n === len) { foot.textContent = "✓ " + len + " 字节"; foot.className = "ok-text"; }
        else if (n === 0) { foot.textContent = "待输入 " + len + " 字节"; foot.className = "warn-text"; }
        else { foot.textContent = "✗ 需要 " + len + " B，当前 " + n + " B"; foot.className = "bad-text"; }
      });
    }
    $("#gmac-suite").addEventListener("change", updateGMACSuite);
    updateGMACSuite();
  }

  async function gmacRun() {
    var btn = $("#gmac-run");
    busy(btn, true);
    UI.clearAllErrors();
    try {
      var mode = UI.activeButton($("#gmac-mode")).getAttribute("data-gmac");
      var suite = parseInt($("#gmac-suite").value, 10);
      var len = suite === 2 ? 32 : 16;
      var ek = UI.readBytes("gmac-ek", len, "EK");
      var ak = UI.readBytes("gmac-ak", len, "AK");
      var st = UI.readBytes("gmac-st", 8, "System Title");
      var ic = UI.readBytes("gmac-ic", 4, "IC");
      var content = UI.readBytes("gmac-content", null, "内容");
      if (content.length < 1) throw new Error("内容不能为空");
      var r;
      if (mode === "hls5") {
        r = await D.hls5({ challenge: content, ek: ek, ak: ak, st: st, ic: ic, suite: suite });
        renderGMACResult(r.output, r, "HLS-5 f(x)", "ok", "已生成 17 B：SC‖IC‖T", suite, content);
      } else {
        r = await D.gmacPayload({ ek: ek, ak: ak, st: st, ic: ic, content: content, suite: suite });
        renderGMACResult(r.packet, r, "报文 GMAC", "warn", "仅认证，不加密；内容仍可读", suite, content);
      }
    } catch (e) {
      handleError($("#gmac-result"), e);
    } finally {
      busy(btn, false);
    }
  }

  function renderGMACResult(bytes, r, name, kind, sub, suite, content) {
    UI.renderResultCard($("#gmac-result"), {
      status: { kind: kind, icon: kind === "warn" ? "!" : "✓", title: name + " 完成", sub: sub + " · Suite " + suite },
      headerActions: '<button class="icon-btn" data-copy="' + B.bytesToHexCompact(bytes) + '" aria-label="复制"><svg class="ico"><use href="#i-copy"/></svg></button>',
      io: {
        inLabel: "输入 · 内容", inCode: B.bytesToHex(content), inSize: content.length + " B",
        outLabel: "输出 · tag", outCode: B.bytesToHex(r.tag), outSize: "12 B"
      },
      bytes: bytes,
      fields: [
        { name: "SC", offset: 0, length: 1, value: B.bytesToHex(new Uint8Array([r.sc])), note: D.scText(r.sc), color: "sc" },
        { name: "IC", offset: 1, length: 4, value: B.bytesToHex(content.length ? bytes.slice(1, 5) : new Uint8Array(0)), note: "调用计数器", color: "ic" },
        { name: "tag", offset: 5, length: 12, value: B.bytesToHex(r.tag), note: "GCM 16 B tag 的前 12 B", color: "auth" }
      ],
      extraHtml: '<div class="note" style="margin:0 16px 12px">GMAC 的 P 为空，内容整体进 AAD。HLS-5 输出固定 17 B；报文 GMAC 的完整报文还要加上外层 APDU tag / Len。</div>',
      actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(bytes) + '">复制</button>'
    });
  }

  /* ============================================================
     HLS
     ============================================================ */
  function hlsMech() { return parseInt($("#hls-mech").value, 10); }
  function hlsDir() { return UI.activeButton($("#hls-dir")).getAttribute("data-dir"); }

  function updateHLSLabels() {
    var mech = hlsMech();
    var dir = hlsDir();
    var client = dir === "client";
    $("#hls-own-ch-label").textContent = client ? "己方质询值（收到的 StoC）" : "己方质询值（收到的 CtoS）";
    $("#hls-st-label").textContent = client ? "己方 System Title（客户端）" : "己方 System Title（服务端）";
    $("#hls-own-ch-req").textContent = mech === 7 ? "32 B" : "8–64 B";
    var hint = document.getElementById("hls-own-ch-hint");
    if (hint) hint.textContent = mech === 7 ? "HLS-7 建议 32–64 B" : "HLS 允许 8–64 B";
    var suiteHint = document.getElementById("hls-suite-hint");
    if (suiteHint) suiteHint.textContent = parseInt($("#hls-suite").value, 10) === 2 ? "GMAC 密钥 32 B（Suite 2）" : "GMAC 密钥 16 B（Suite 0/1）";
    var len5 = parseInt($("#hls-suite").value, 10) === 2 ? 32 : 16;
    ["hls-ek", "hls-ak"].forEach(function (id) {
      var input = document.getElementById(id);
      var req = document.getElementById(id + "-req");
      var foot = document.getElementById(id + "-foot");
      if (req) req.textContent = len5 + " B";
      if (!input || !foot) return;
      var n = 0;
      try { n = UI.bytesFromInput(input).length; } catch (e) {}
      if (n === len5) { foot.textContent = "✓ " + len5 + " 字节"; foot.className = "ok-text"; }
      else if (n === 0) { foot.textContent = "待输入 " + len5 + " 字节"; foot.className = "warn-text"; }
      else { foot.textContent = "✗ 需要 " + len5 + " B，当前 " + n + " B"; foot.className = "bad-text"; }
    });
    $$("[data-hls-for]").forEach(function (el) {
      var list = el.getAttribute("data-hls-for").split(/\s+/);
      el.hidden = list.indexOf(String(mech)) < 0;
    });
  }

  function initHLS() {
    $("#hls-mech").addEventListener("change", updateHLSLabels);
    $("#hls-suite").addEventListener("change", updateHLSLabels);
    $$("#hls-dir button").forEach(function (b) {
      b.addEventListener("click", function () {
        UI.setSegment($("#hls-dir"), "data-dir", b.getAttribute("data-dir"));
        updateHLSLabels();
      });
    });
    $("#hls-run").addEventListener("click", hlsRun);
    $("#hls-load51").addEventListener("click", function () {
      $("#hls-mech").value = "5";
      $("#hls-suite").value = "0";
      UI.setSegment($("#hls-dir"), "data-dir", "client");
      setHexField("hls-own-ch", V.table51.stoC);
      setHexField("hls-ek", V.table51.ek);
      setHexField("hls-ak", V.table51.ak);
      setHexField("hls-st", V.table51.clientST);
      setHexField("hls-ic", V.table51.clientIC);
      updateHLSLabels();
      hlsRun();
    });
    $("#hls-load52").addEventListener("click", function () {
      $("#hls-mech").value = "7";
      updateHLSLabels();
      var dir = hlsDir();
      if (dir === "client") {
        setHexField("hls-own-ch", V.table52.stoC);
        setHexField("hls-peer-ch", V.table52.ctoS);
        setHexField("hls-st", V.table52.sysTC);
        setHexField("hls-peer-st", V.table52.sysTS);
        $("#hls-priv").value = V.table52.privClient;
      } else {
        setHexField("hls-own-ch", V.table52.ctoS);
        setHexField("hls-peer-ch", V.table52.stoC);
        setHexField("hls-st", V.table52.sysTS);
        setHexField("hls-peer-st", V.table52.sysTC);
        $("#hls-priv").value = V.table52.privServer;
      }
      $("#hls-priv").dataset.keyFormat = "raw";
      $("#hls-curve").value = "P-256";
      hlsRun();
    });
    updateHLSLabels();
  }

  async function hlsRun() {
    var btn = $("#hls-run");
    busy(btn, true);
    UI.clearAllErrors();
    var mech = hlsMech();
    var dir = hlsDir();
    var client = dir === "client";
    function checkChallenge(bytes, field, label) {
      var min = mech === 7 ? 32 : 8;
      if (bytes.length < min || bytes.length > 64) {
        throw { field: field, message: label + " 需要 " + min + "–64 B，当前 " + bytes.length + " B" };
      }
    }
    try {
      var ownCh = UI.readBytes("hls-own-ch", null, "己方质询值");
      checkChallenge(ownCh, "hls-own-ch", "己方质询值");
      var ownST = (mech === 5 || mech === 6 || mech === 7) ? UI.readBytes("hls-st", 8, "己方 ST") : null;
      var ic = mech === 5 ? UI.readBytes("hls-ic", 4, "IC") : null;
      var out, fields, formula, sub;
      if (mech === 3 || mech === 4) {
        var secret = UI.readBytes("hls-secret", null, "Secret");
        out = mech === 3 ? await D.hls3({ challenge: ownCh, secret: secret }) : await D.hls4({ challenge: ownCh, secret: secret });
        fields = [{ name: "f(·)", offset: 0, length: out.length, value: B.bytesToHex(out), note: mech === 3 ? "MD5" : "SHA-1", color: "auth" }];
        formula = (mech === 3 ? "MD5" : "SHA-1") + "(质询值 ‖ secret)";
        sub = "输出 " + out.length + " B 原始哈希，无 SC/IC";
      } else if (mech === 5) {
        var suite5 = parseInt($("#hls-suite").value, 10);
        var keyLen5 = suite5 === 2 ? 32 : 16;
        var ek5 = UI.readBytes("hls-ek", keyLen5, "EK");
        var ak5 = UI.readBytes("hls-ak", keyLen5, "AK");
        var r5 = await D.hls5({
          challenge: ownCh,
          ek: ek5,
          ak: ak5,
          st: ownST, ic: ic, suite: suite5
        });
        out = r5.output;
        fields = [
          { name: "SC", offset: 0, length: 1, value: B.bytesToHex(new Uint8Array([r5.sc])), note: D.scText(r5.sc), color: "sc" },
          { name: "IC", offset: 1, length: 4, value: B.bytesToHex(ic), note: "计算方 IC", color: "ic" },
          { name: "T", offset: 5, length: 12, value: B.bytesToHex(r5.tag), note: "GMAC tag", color: "auth" }
        ];
        formula = "SC ‖ IC ‖ GMAC_EK(SC ‖ AK ‖ 质询值)";
        sub = "输出 17 B；IV = 计算方 ST‖IC";
      } else if (mech === 6) {
        var secret6 = UI.readBytes("hls-secret", null, "Secret");
        var peerST = UI.readBytes("hls-peer-st", 8, "对方 ST");
        var peerCh = UI.readBytes("hls-peer-ch", null, "对方质询值");
        checkChallenge(peerCh, "hls-peer-ch", "对方质询值");
        out = await D.hls6({ secret: secret6, ownST: ownST, peerST: peerST, ownChallenge: ownCh, peerChallenge: peerCh });
        fields = [{ name: "f(·)", offset: 0, length: out.length, value: B.bytesToHex(out), note: "SHA-256", color: "auth" }];
        formula = "SHA-256(secret ‖ 己方ST ‖ 对方ST ‖ 己方质询值 ‖ 对方质询值)";
        sub = "输出 32 B；secret 永远在最前";
      } else if (mech === 7) {
        var peerST7 = UI.readBytes("hls-peer-st", 8, "对方 ST");
        var peerCh7 = UI.readBytes("hls-peer-ch", null, "对方质询值");
        checkChallenge(peerCh7, "hls-peer-ch", "对方质询值");
        var curve = $("#hls-curve").value;
        var priv = $("#hls-priv");
        var keyFmt = priv.dataset.keyFormat || "raw";
        var keyData = keyFmt === "raw" ? B.hexToBytes(priv.value) : priv.value.trim();
        if (keyFmt === "raw" && keyData.length !== (curve === "P-384" ? 48 : 32)) {
          throw { field: "hls-priv", message: "原始私钥 d 需要 " + (curve === "P-384" ? 48 : 32) + " B，当前 " + keyData.length + " B" };
        }
        var pk = await EC.importPrivateKey({ format: keyFmt === "raw" ? "raw" : keyFmt, data: keyData, curve: curve, usage: "ECDSA" });
        var r7 = await D.hls7({ privateKey: pk, ownST: ownST, peerST: peerST7, ownChallenge: ownCh, peerChallenge: peerCh7, hash: curve === "P-384" ? "SHA-384" : "SHA-256" });
        out = r7.signature;
        fields = [{ name: "签名 R‖S", offset: 0, length: out.length, value: B.bytesToHex(out), note: "plain 格式", color: "auth" }];
        formula = "ECDSA(己方ST ‖ 对方ST ‖ 己方质询值 ‖ 对方质询值)";
        sub = "输出 " + out.length + " B；P-256/SHA-256 或 P-384/SHA-384";
      }
      var expected = mech === 5
        ? (client ? V.table51.fStoC : V.table51.fCtoS)
        : null;
      var match = expected && B.bytesToHexCompact(out).toUpperCase() === expected.toUpperCase();
      var ecdsaNote = mech === 7
        ? '<div class="note" style="margin:0 16px 12px">ECDSA 每次签名带随机数 k，结果会不同；Table 52 的示例值只是其中一次有效签名，<b>不能逐字节比较</b>。请用对应公钥验签。</div>'
        : "";
      var extra = '<div class="note" style="margin:0 16px 12px"><b>公式：</b>' + UI.esc(formula) + "<br><b>输入：</b>" +
        UI.esc(UI.shortHex(ownCh, 64)) + "（质询值）" + (ownST ? " · ST " + UI.esc(B.bytesToHexCompact(ownST)) : "") + "</div>" +
        '<pre style="margin:0 16px 12px;background:var(--surface-2);border:1px solid var(--line-2);border-radius:7px;padding:9px;font-family:var(--mono);font-size:9.5px;white-space:pre-wrap">' +
        "机制 " + mech + " · " + (client ? "客户端 f(StoC)" : "服务端 f(CtoS)") + "\n" + UI.esc(formula) + "</pre>" +
        (expected ? '<div class="note" style="margin:0 16px 12px;border-left-color:' + (match ? "var(--ok)" : "var(--danger)") + '">规范期望：' + UI.esc(expected) + (match ? " ✓ 一致" : " ✗ 不一致") + "</div>" : "") +
        ecdsaNote;
      UI.renderResultCard($("#hls-result"), {
        status: { kind: "ok", icon: "✓", title: "f(·) 已生成", sub: "机制 " + mech + " · " + sub },
        headerActions: '<button class="icon-btn" data-copy="' + B.bytesToHexCompact(out) + '" aria-label="复制"><svg class="ico"><use href="#i-copy"/></svg></button>',
        io: {
          inLabel: "输入 · 质询值", inCode: B.bytesToHex(ownCh), inSize: ownCh.length + " B",
          outLabel: "输出 · f(·)", outCode: B.bytesToHex(out), outSize: out.length + " B"
        },
        bytes: out, fields: fields, extraHtml: extra,
        actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(out) + '">复制输出</button>'
      });
    } catch (e) {
      handleError($("#hls-result"), e);
    } finally {
      busy(btn, false);
    }
  }

  /* ============================================================
     密钥工具
     ============================================================ */
  function showKeysPane(name) {
    $$("#keys-tabs .filter").forEach(function (b) { b.classList.toggle("active", b.getAttribute("data-keys-tab") === name); });
    $$(".keys-pane").forEach(function (p) { p.hidden = p.getAttribute("data-keys-pane") !== name; });
  }

  function initKeys() {
    $$("#keys-tabs .filter").forEach(function (b) {
      b.addEventListener("click", function () { showKeysPane(b.getAttribute("data-keys-tab")); });
    });
    $$("#kw-mode button").forEach(function (b) {
      b.addEventListener("click", function () {
        UI.setSegment($("#kw-mode"), "data-kw", b.getAttribute("data-kw"));
        $("#kw-key-label").textContent = b.getAttribute("data-kw") === "unwrap" ? "AES-KW 密文" : "待包装密钥";
      });
    });
    $("#kw-run").addEventListener("click", kwRun);
    $("#kw-load").addEventListener("click", function () {
      setHexField("kw-kek", V.aesKw.kek);
      setHexField("kw-key", V.aesKw.key);
      UI.setSegment($("#kw-mode"), "data-kw", "wrap");
      $("#kw-key-label").textContent = "待包装密钥";
      kwRun();
    });
    $("#ecdh-run").addEventListener("click", ecdhRun);
    $("#kdf-run").addEventListener("click", kdfRun);
    $("#kdf-load").addEventListener("click", function () {
      setHexField("kdf-z", V.kdf.z);
      setHexField("kdf-algid", V.kdf.algId);
      setHexField("kdf-party-u", V.kdf.partyU);
      setHexField("kdf-party-v", V.kdf.partyV);
      setHexField("kdf-nonce", "");
      $("#kdf-hash").value = "SHA-256";
      $("#kdf-keydatalen").value = "256";
      kdfRun();
    });
    $("#rnd-aes-run").addEventListener("click", function () {
      var n = parseInt($("#rnd-aes-bits").value, 10);
      var bytes = B.randomBytes(n);
      $("#rnd-aes-result").value = B.bytesToHex(bytes) + "\n\nBase64: " + B.bytesToBase64(bytes);
      toast("已生成 " + n + " B AES 密钥");
    });
    $("#rnd-ec-run").addEventListener("click", async function () {
      var curve = $("#rnd-ec-curve").value;
      try {
        var kp = await EC.generateKeyPair(curve, "ECDSA");
        $("#rnd-ec-result").value = "d (raw) = " + B.bytesToHex(B.base64UrlToBytes(kp.privateJwk.d)) +
          "\n\nX‖Y = " + B.bytesToHex(kp.publicRawXY) +
          "\n\nPKCS#8 PEM:\n" + kp.pkcs8Pem;
        toast("已生成 " + curve + " 密钥对");
      } catch (e) { toast(e.message); }
    });
    $("#pk-run").addEventListener("click", pkRun);
    $("#pk-sample").addEventListener("click", async function () {
      try {
        var curve = $("#pk-curve").value;
        var kp = await EC.generateKeyPair(curve === "auto" ? "P-256" : curve, "ECDSA");
        $("#pk-input").value = kp.pkcs8Pem;
        $("#pk-status").textContent = "已载入示例";
      } catch (e) { toast(e.message); }
    });
    $("#pk-copy-pub").addEventListener("click", function () {
      if (!UI.copyText($("#pk-out-pub").value)) return;
      toast("公钥 HEX 已复制");
    });
    $("#pk-copy-priv").addEventListener("click", function () {
      if (!UI.copyText($("#pk-out-priv").value)) return;
      toast("私钥 HEX 已复制");
    });
  }

  async function pkRun() {
    var input = $("#pk-input").value.trim();
    if (!input) {
      toast("请先粘贴私钥或公钥");
      $("#pk-input").focus();
      return;
    }
    var btn = $("#pk-run");
    busy(btn, true);
    try {
      var r = await EC.inspectKey({ data: input, curve: $("#pk-curve").value });
      $("#pk-out-pub").value = [
        "X‖Y (" + r.publicRawXY.length + " B): " + B.bytesToHexCompact(r.publicRawXY),
        "04‖X‖Y (" + r.publicRaw.length + " B): " + B.bytesToHexCompact(r.publicRaw)
      ].join("\n");
      $("#pk-out-priv").value = r.privateRaw
        ? "d (" + r.privateRaw.length + " B): " + B.bytesToHexCompact(r.privateRaw)
        : "（输入的是公钥，无法反推私钥）";
      $("#pk-status").textContent = r.kind === "private" ? "私钥 → 公钥" : "公钥解析";
      $("#pk-out-meta").textContent = r.curve + " · " + (r.kind === "private"
        ? "私钥 " + r.privateRaw.length + " B / 公钥 " + r.publicRawXY.length + " B"
        : "公钥 " + r.publicRawXY.length + " B");
      toast("已解析");
    } catch (e) {
      $("#pk-status").textContent = "失败";
      toast(e.message || String(e));
    } finally {
      busy(btn, false);
    }
  }

  async function kwRun() {
    var btn = $("#kw-run");
    busy(btn, true);
    try {
      var mode = UI.activeButton($("#kw-mode")).getAttribute("data-kw");
      var kek = UI.readBytes("kw-kek", [16, 32], "KEK");
      var key = UI.readBytes("kw-key", null, mode === "unwrap" ? "AES-KW 密文" : "待包装密钥");
      var out = mode === "wrap" ? await KW.wrap(kek, key) : await KW.unwrap(kek, key);
      UI.renderResultCard($("#kw-result"), {
        status: { kind: "ok", icon: "✓", title: mode === "wrap" ? "AES-KW 包装完成" : "AES-KW 解包完成", sub: "RFC 3394 · " + out.length + " B" },
        headerActions: '<button class="icon-btn" data-copy="' + B.bytesToHexCompact(out) + '" aria-label="复制"><svg class="ico"><use href="#i-copy"/></svg></button>',
        io: { inLabel: "输入", inCode: UI.shortHex(key, 64), inSize: key.length + " B", outLabel: "输出", outCode: B.bytesToHex(out), outSize: out.length + " B" },
        bytes: out,
        fields: [{ name: mode === "wrap" ? "wrapped" : "key", offset: 0, length: out.length, value: B.bytesToHex(out), note: mode === "wrap" ? "长度 +8 B" : "解包还原", color: "ct" }],
        actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(out) + '">复制结果</button>'
      });
    } catch (e) { handleError($("#kw-result"), e); }
    finally { busy(btn, false); }
  }

  function detectKeyFormat(text) {
    var t = String(text || "").trim();
    if (t.indexOf("BEGIN") >= 0) return "pem";
    if (t.charAt(0) === "{") return "jwk";
    return "raw";
  }

  function detectPublicFormat(text) {
    var t = String(text || "").trim();
    if (t.indexOf("BEGIN CERTIFICATE") >= 0) return "cert";
    if (t.indexOf("BEGIN") >= 0) return "spki";
    if (t.charAt(0) === "{") return "jwk";
    return "raw";
  }

  async function ecdhRun() {
    var btn = $("#ecdh-run");
    busy(btn, true);
    try {
      var curve = $("#ecdh-curve").value;
      var purpose = $("#ecdh-purpose").value;
      var keydatalen = parseInt($("#ecdh-keydatalen").value, 10);
      var privText = $("#ecdh-priv").value.trim();
      var pubText = $("#ecdh-pub").value.trim();
      if (!privText) throw { field: "ecdh-priv", message: "请填写己方私钥" };
      if (!pubText) throw { field: "ecdh-pub", message: "请填写对方公钥" };
      var pk = await EC.importPrivateKey({ format: detectKeyFormat(privText), data: privText, curve: curve, usage: "ECDH" });
      var pubFmt = detectPublicFormat(pubText);
      var pub, pubCurve = curve;
      if (pubFmt === "cert") {
        var cert = X509.parseCertificate(X509.parsePem(pubText)[0].der);
        if (cert.spki.algorithm.keyType !== "EC") throw new Error("RSA 证书不能用于 DLMS ECDSA 验签");
        pubCurve = cert.spki.curveName || curve;
        pub = await EC.importPublicKey({ format: "raw", data: cert.spki.publicKeyBytes, curve: pubCurve, usage: "ECDH" });
      } else {
        pub = await EC.importPublicKey({ format: pubFmt, data: pubText, curve: pubCurve, usage: "ECDH" });
      }
      var z = await EC.ecdh({ privateKey: pk, publicKey: pub, curve: pubCurve });
      var suite = pubCurve === "P-384" ? 2 : 1;
      var kdf = await KDF.concatKdf({
        z: z, hash: suite === 2 ? "SHA-384" : "SHA-256", keydatalenBits: keydatalen,
        algId: KDF.algorithmId(suite, purpose),
        partyU: UI.readBytes("ecdh-party-u", 8, "PartyU"),
        partyV: UI.readBytes("ecdh-party-v", 8, "PartyV")
      });
      UI.renderResultCard($("#ecdh-result"), {
        status: { kind: "ok", icon: "✓", title: "ECDH + KDF 完成", sub: curve + " · Z " + z.length + " B · 派生密钥 " + kdf.key.length + " B" },
        headerActions: '<button class="icon-btn" data-copy="' + B.bytesToHexCompact(kdf.key) + '" aria-label="复制"><svg class="ico"><use href="#i-copy"/></svg></button>',
        io: { inLabel: "共享秘密 Z", inCode: B.bytesToHex(z), inSize: z.length + " B", outLabel: "派生密钥", outCode: B.bytesToHex(kdf.key), outSize: kdf.key.length + " B" },
        bytes: kdf.key,
        fields: [{ name: "派生密钥", offset: 0, length: kdf.key.length, value: B.bytesToHex(kdf.key), note: "KDF 输出截断", color: "auth" }],
        extraHtml: '<div class="note" style="margin:0 16px 12px">AlgID = ' + UI.esc(B.bytesToHexCompact(kdf.otherInfo.slice(0, 7))) + " · OtherInfo = AlgID‖PartyU‖PartyV</div>" +
          '<div class="section-title" style="padding:0 16px">K(i) 轨迹</div>' + kdf.blocks.map(function (b) {
            return '<div style="padding:0 16px 6px;font-family:var(--mono);font-size:9px;color:var(--muted)">K(' + b.counter + ") = " + UI.esc(B.bytesToHex(b.digest)) + "</div>";
          }).join(""),
        actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(z) + '">复制 Z</button><button class="btn small ghost" data-copy="' + B.bytesToHexCompact(kdf.key) + '">复制派生密钥</button>'
      });
    } catch (e) { handleError($("#ecdh-result"), e); }
    finally { busy(btn, false); }
  }

  async function kdfRun() {
    var btn = $("#kdf-run");
    busy(btn, true);
    try {
      var z = UI.readBytes("kdf-z", null, "Z");
      var algId = UI.readBytes("kdf-algid", 7, "AlgID");
      var nonce = $("#kdf-nonce").value.trim() ? UI.readBytes("kdf-nonce", null, "NonceU") : null;
      var kdf = await KDF.concatKdf({
        z: z, hash: $("#kdf-hash").value, keydatalenBits: parseInt($("#kdf-keydatalen").value, 10),
        algId: algId,
        partyU: UI.readBytes("kdf-party-u", 8, "PartyU"),
        partyV: UI.readBytes("kdf-party-v", 8, "PartyV"),
        nonceU: nonce
      });
      UI.renderResultCard($("#kdf-result"), {
        status: { kind: "ok", icon: "✓", title: "KDF 完成", sub: kdf.hash + " · " + kdf.key.length + " B" },
        headerActions: '<button class="icon-btn" data-copy="' + B.bytesToHexCompact(kdf.key) + '" aria-label="复制"><svg class="ico"><use href="#i-copy"/></svg></button>',
        io: { inLabel: "Z", inCode: B.bytesToHex(z), inSize: z.length + " B", outLabel: "派生密钥", outCode: B.bytesToHex(kdf.key), outSize: kdf.key.length + " B" },
        bytes: kdf.key,
        fields: [{ name: "派生密钥", offset: 0, length: kdf.key.length, value: B.bytesToHex(kdf.key), note: "截断到 keydatalen", color: "auth" }],
        extraHtml: kdf.blocks.map(function (b) {
          return '<div style="padding:0 16px 6px;font-family:var(--mono);font-size:9px;color:var(--muted)">K(' + b.counter + ") = " + UI.esc(B.bytesToHex(b.digest)) + "</div>";
        }).join("") + '<div class="note" style="margin:0 16px 12px">OtherInfo = AlgID‖PartyU' + (nonce ? "‖len(NonceU)‖NonceU" : "") + '‖PartyV</div>',
        actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(kdf.key) + '">复制派生密钥</button>'
      });
    } catch (e) { handleError($("#kdf-result"), e); }
    finally { busy(btn, false); }
  }

  /* ============================================================
     哈希 / CRC
     ============================================================ */
  var hashFileBytes = null;

  function initHash() {
    var fmt = "text";
    $$("#hash-input-format button").forEach(function (b) {
      b.addEventListener("click", function () {
        UI.setSegment($("#hash-input-format"), "data-hfmt", b.getAttribute("data-hfmt"));
        fmt = b.getAttribute("data-hfmt");
      });
    });
    $("#hash-file").addEventListener("change", function () {
      var f = this.files && this.files[0];
      if (!f) { hashFileBytes = null; return; }
      if (f.size > 20 * 1024 * 1024) {
        this.value = "";
        hashFileBytes = null;
        toast("文件超过 20 MB，已拒绝（避免浏览器卡死）");
        return;
      }
      var reader = new FileReader();
      reader.onload = function () {
        hashFileBytes = new Uint8Array(reader.result);
        toast("已读取文件：" + f.name + "（" + B.formatBytes(f.size) + "）");
      };
      reader.readAsArrayBuffer(f);
    });
    $("#hash-input").addEventListener("input", function () { hashFileBytes = null; });
    $("#hash-run").addEventListener("click", async function () {
      try {
        var algo = $("#hash-algo").value;
        var input;
        if (hashFileBytes) input = hashFileBytes;
        else {
          var raw = $("#hash-input").value;
          input = fmt === "hex" ? B.hexToBytes(raw) : B.utf8ToBytes(raw);
        }
        var out;
        if ($("#hash-hmac").checked) {
          out = await H.hmac(algo, UI.readBytes("hash-key", null, "HMAC 密钥"), input);
        } else {
          out = await H.hash(algo, input);
        }
        $("#hash-result").value = B.bytesToHex(out) + "\n\nBase64: " + B.bytesToBase64(out);
        $("#hash-result-meta").textContent = (hashFileBytes ? "文件" : "输入") + " " + B.formatBytes(input.length) + " · " + algo + (($("#hash-hmac").checked) ? " · HMAC" : "");
        toast("哈希完成");
      } catch (e) { toast(e.message); }
    });

    var cfmt = "hex";
    $$("#crc-input-format button").forEach(function (b) {
      b.addEventListener("click", function () {
        UI.setSegment($("#crc-input-format"), "data-cfmt", b.getAttribute("data-cfmt"));
        cfmt = b.getAttribute("data-cfmt");
      });
    });
    $("#crc-run").addEventListener("click", function () {
      try {
        var bytes = readCrcInput(cfmt);
        var r = calcCrc($("#crc-algo").value, bytes);
        $("#crc-result").value = r.text;
        $("#crc-result-meta").textContent = r.meta;
        toast("CRC 完成");
      } catch (e) { toast(e.message); }
    });
    $("#crc-append").addEventListener("click", function () {
      try {
        var bytes = readCrcInput(cfmt);
        var r = calcCrc($("#crc-algo").value, bytes);
        var out = B.concat(bytes, r.wire);
        $("#crc-input").value = B.bytesToHex(out);
        cfmt = "hex";
        UI.setSegment($("#crc-input-format"), "data-cfmt", "hex");
        toast("已把 " + r.wire.length + " B FCS 追加到输入");
      } catch (e) { toast(e.message); }
    });
  }

  function readCrcInput(fmt) {
    var raw = $("#crc-input").value;
    return fmt === "text" ? B.utf8ToBytes(raw) : B.hexToBytes(raw);
  }

  function calcCrc(algo, bytes) {
    if (algo === "CRC32") {
      var v32 = CRC.crc32(CRC.CRC32["ISO-HDLC"], bytes);
      var wire32 = B.u32be(v32);
      return {
        text: "CRC-32/ISO-HDLC = 0x" + v32.toString(16).toUpperCase().padStart(8, "0") + "\n\n线上字节（大端）: " + B.bytesToHex(wire32),
        meta: "poly 0x04C11DB7 · init/xorout 0xFFFFFFFF · check 0xCBF43926",
        wire: wire32
      };
    }
    var p = CRC.CRC16[algo];
    var v = CRC.crc16(p, bytes);
    var wire = new Uint8Array([v & 0xFF, (v >>> 8) & 0xFF]);
    return {
      text: p.name + " = 0x" + v.toString(16).toUpperCase().padStart(4, "0") + "\n\n线上字节（低字节在前）: " + B.bytesToHex(wire),
      meta: "poly 0x" + p.poly.toString(16).toUpperCase() + " · init 0x" + p.init.toString(16).toUpperCase() + " · check 0x" + p.check.toString(16).toUpperCase(),
      wire: wire
    };
  }

  /* ============================================================
     数字签名
     ============================================================ */
  function initSign() {
    var msgMode = "ascii";
    $$("#sign-msg-format button").forEach(function (b) {
      b.addEventListener("click", function () {
        var next = b.getAttribute("data-sfmt");
        if (next === msgMode) return;
        var input = $("#sign-msg");
        if (next === "hex") {
          input.value = B.bytesToHex(B.utf8ToBytes(input.value));
          $("#sign-msg-hint").textContent = "HEX 按字节解析；支持空格、冒号、0x 前缀";
        } else {
          try {
            var bytes = B.hexToBytes(input.value);
            if (!B.isProbablyPrintable(bytes)) { toast("消息含不可打印字节，保留 HEX 模式"); return; }
            input.value = B.bytesToUtf8(bytes);
            $("#sign-msg-hint").textContent = "ASCII/UTF-8 按字节编码；切到 HEX 可签二进制质询";
          } catch (e) { toast("当前内容不是合法 HEX，保留原样"); }
        }
        msgMode = next;
        UI.setSegment($("#sign-msg-format"), "data-sfmt", next);
      });
    });
    $$("#sign-mode button").forEach(function (b) {
      b.addEventListener("click", function () {
        var mode = b.getAttribute("data-sign");
        UI.setSegment($("#sign-mode"), "data-sign", mode);
        $$("[data-sign-for]").forEach(function (el) { el.hidden = el.getAttribute("data-sign-for") !== mode; });
      });
    });
    $("#sign-curve").addEventListener("change", function () {
      $("#sign-hash").value = this.value === "P-384" ? "SHA-384" : "SHA-256";
    });
    $("#sign-run").addEventListener("click", signRun);
    $("#sign-gen").addEventListener("click", async function () {
      try {
        var kp = await EC.generateKeyPair($("#sign-curve").value, "ECDSA");
        $("#sign-priv").value = kp.pkcs8Pem;
        $("#sign-pub").value = B.bytesToHex(kp.publicRawXY);
        toast("已生成密钥对并填入私钥 / 公钥");
      } catch (e) { toast(e.message); }
    });
    $("#sign-raw2der").addEventListener("click", function () {
      try {
        var sig = B.hexToBytes($("#sign-sig").value);
        var der = EC.rawToDer(sig, $("#sign-curve").value);
        $("#sign-sig").value = B.bytesToHex(der);
        toast("raw → DER 完成");
      } catch (e) { toast(e.message); }
    });
    $("#sign-der2raw").addEventListener("click", function () {
      try {
        var sig = B.hexToBytes($("#sign-sig").value);
        var raw = EC.derToRaw(sig, $("#sign-curve").value);
        $("#sign-sig").value = B.bytesToHex(raw);
        toast("DER → raw 完成");
      } catch (e) { toast(e.message); }
    });
    $$("[data-sign-for]").forEach(function (el) { el.hidden = el.getAttribute("data-sign-for") !== "sign"; });
  }

  async function signRun() {
    var btn = $("#sign-run");
    busy(btn, true);
    try {
      var mode = UI.activeButton($("#sign-mode")).getAttribute("data-sign");
      var curve = $("#sign-curve").value;
      var hash = $("#sign-hash").value;
      var msgFmt = UI.activeButton($("#sign-msg-format")).getAttribute("data-sfmt");
      var msg = msgFmt === "hex" ? B.hexToBytes($("#sign-msg").value) : B.utf8ToBytes($("#sign-msg").value);
      if (mode === "sign") {
        var privText = $("#sign-priv").value.trim();
        if (!privText) throw { field: "sign-priv", message: "请填写私钥" };
        var pk = await EC.importPrivateKey({ format: detectKeyFormat(privText), data: privText, curve: curve, usage: "ECDSA" });
        var sig = await EC.sign({ privateKey: pk, hash: hash, message: msg });
        var der = EC.rawToDer(sig, curve);
        $("#sign-sig").value = B.bytesToHex(sig);
        UI.renderResultCard($("#sign-result"), {
          status: { kind: "ok", icon: "✓", title: "签名完成", sub: curve + " · " + hash + " · " + sig.length + " B" },
          headerActions: '<button class="icon-btn" data-copy="' + B.bytesToHexCompact(sig) + '" aria-label="复制"><svg class="ico"><use href="#i-copy"/></svg></button>',
          bytes: sig,
          fields: [{ name: "R‖S", offset: 0, length: sig.length, value: B.bytesToHex(sig), note: "DLMS plain 签名", color: "auth" }],
          extraHtml: '<div class="note" style="margin:0 16px 12px">DER: ' + UI.esc(B.bytesToHex(der)) + "</div>",
          actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(sig) + '">复制 raw</button><button class="btn small ghost" data-copy="' + B.bytesToHexCompact(der) + '">复制 DER</button>'
        });
      } else {
        var pubText = $("#sign-pub").value.trim();
        var sigText = $("#sign-sig").value.trim();
        if (!pubText) throw { field: "sign-pub", message: "请填写公钥或证书" };
        if (!sigText) throw { field: "sign-sig", message: "请粘贴签名" };
        var pubFmt = detectPublicFormat(pubText);
        var pub, useCurve = curve;
        if (pubFmt === "cert") {
          var cert = X509.parseCertificate(X509.parsePem(pubText)[0].der);
          if (cert.spki.algorithm.keyType !== "EC") throw new Error("RSA 证书不能用于 DLMS ECDSA 验签");
          useCurve = cert.spki.curveName || curve;
          pub = await EC.importPublicKey({ format: "raw", data: cert.spki.publicKeyBytes, curve: useCurve, usage: "ECDSA" });
        } else {
          pub = await EC.importPublicKey({ format: pubFmt, data: pubText, curve: useCurve, usage: "ECDSA" });
        }
        var signature = B.hexToBytes(sigText);
        var ok = await EC.verify({ publicKey: pub, hash: hash, message: msg, signature: signature, curve: useCurve });
        UI.renderResultCard($("#sign-result"), {
          status: ok ? { kind: "ok", icon: "✓", title: "验签通过", sub: useCurve + " · " + hash } : { kind: "bad", icon: "✗", title: "验签失败", sub: "签名、公钥、曲线或哈希不匹配" },
          bytes: null,
          extraHtml: '<div style="padding:16px;font-size:12px;color:var(--muted)">消息 ' + msg.length + " B · 签名 " + signature.length + " B" + (EC.isDerSignature(signature) ? " · DER" : " · raw R‖S") + "</div>",
          actions: ""
        });
      }
    } catch (e) { handleError($("#sign-result"), e); }
    finally { busy(btn, false); }
  }

  /* ============================================================
     证书
     ============================================================ */
  var certState = { certs: [], selected: 0 };

  function initCert() {
    $("#cert-parse").addEventListener("click", certParse);
    $("#cert-load-sample").addEventListener("click", function () {
      $("#cert-input").value = [V.certs.leafPem, V.certs.interPem, V.certs.rootPem].join("\n\n");
      certParse();
    });
    var fileInput = $("#cert-file");
    if (fileInput) {
      $("#cert-file-btn").addEventListener("click", function () { fileInput.click(); });
      fileInput.addEventListener("change", function () { if (this.files && this.files[0]) loadCertFile(this.files[0]); });
    }
    function loadCertFile(file) {
      var reader = new FileReader();
      reader.onload = function () {
        var buf = new Uint8Array(reader.result);
        var text = B.bytesToUtf8(buf);
        $("#cert-input").value = text.indexOf("BEGIN") >= 0 ? text : B.bytesToHex(buf);
        certParse();
      };
      reader.readAsArrayBuffer(file);
    }
    var dz = document.querySelector("#view-cert .dropzone");
    if (dz) {
      ["dragenter", "dragover"].forEach(function (ev) {
        dz.addEventListener(ev, function (e) { e.preventDefault(); e.stopPropagation(); });
      });
      dz.addEventListener("drop", function (e) {
        e.preventDefault(); e.stopPropagation();
        if (e.dataTransfer.files && e.dataTransfer.files[0]) loadCertFile(e.dataTransfer.files[0]);
      });
    }
  }

  function certParse() {
    try {
      var text = $("#cert-input").value.trim();
      if (!text) throw new Error("请粘贴 PEM 证书，或 HEX 形式的 DER");
      var ders;
      if (text.indexOf("BEGIN") >= 0) ders = X509.parsePem(text).map(function (b) { return b.der; });
      else ders = [B.hexToBytes(text)];
      certState.certs = ders.map(function (der) { return X509.parseCertificate(der); });
      certState.selected = 0;
      renderCertChain();
      renderCertDetail(0);
      toast("已解析 " + certState.certs.length + " 张证书");
    } catch (e) {
      $("#cert-detail").innerHTML = '<div class="status bad" style="margin:16px"><span class="status-ico">!</span><div><strong>解析失败</strong><small>' + UI.esc(e.message) + "</small></div></div>";
      toast(e.message);
    }
  }

  function renderCertChain() {
    var ul = $("#cert-chain");
    ul.innerHTML = certState.certs.map(function (c, i) {
      return '<li><button class="chain-item ' + (i === certState.selected ? "active" : "") + '" data-cert-index="' + i + '"><span class="dot"></span><div>' +
        UI.esc((c.subject.parts.find(function (p) { return p.name === "CN"; }) || { value: c.subject.text }).value) +
        "<small>" + UI.esc(c.issuer.text) + "</small></div></button></li>";
    }).join("");
    $$("[data-cert-index]", ul).forEach(function (b) {
      b.addEventListener("click", function () { certState.selected = parseInt(b.getAttribute("data-cert-index"), 10); renderCertChain(); renderCertDetail(certState.selected); });
    });
  }

  async function renderCertDetail(index) {
    var c = certState.certs[index];
    if (!c) return;
    var fp = await X509.fingerprint(c.der, "SHA-256");
    var ku = c.extensions["2.5.29.15"];
    var bc = c.extensions["2.5.29.19"];
    var san = c.extensions["2.5.29.17"];
    var pub = X509.extractPublicKey(c);
    var isEc = /^P-/.test(c.spki.curveName || "");
    var chainHtml = "";
    if (certState.certs.length > 1 && index === 0) {
      var chain = await X509.verifyChain(certState.certs);
      chainHtml = '<div class="cert-section"><h4>证书链验证</h4><div class="status ' + (chain.ok ? "ok" : "bad") + '" style="margin-bottom:6px"><span class="status-ico">' + (chain.ok ? "✓" : "!") + '</span><div><strong>' + (chain.ok ? "链式校验通过" : "链式校验失败") + "</strong><small>只做密码学校验，不做信任锚 / CRL / OCSP</small></div></div>" +
        chain.links.map(function (l, i) {
          return '<div class="hint" style="margin:3px 0">' + (i + 1) + ". " + UI.esc(l.subject) + " ← " + UI.esc(l.issuer) + "：" + (l.ok ? "✓ 通过" : "✗ " + (l.signature.reason || l.validity.reason || "失败")) + "</div>";
        }).join("") + "</div>";
    }
    var kvPairs = [
      ["Subject", c.subject.text],
      ["Issuer", c.issuer.text],
      ["Serial", c.serial],
      ["Version", "v" + c.version],
      ["Validity", c.notBefore.iso + " → " + c.notAfter.iso],
      ["Public key", isEc
        ? (c.spki.curveName || "EC") + " · X‖Y " + ((pub.rawXY.length + 1) / 3) + " B"
        : (c.spki.algorithm.name || "RSA") + " · " + c.spki.publicKeyBytes.length + " B（ASN.1，完整值见「复制 SPKI PEM」）"]
    ];
    if (isEc) kvPairs.push(["X‖Y", pub.rawXY, "kv-hex"]);
    kvPairs.push(["Signature", c.signatureAlgorithm.name], ["SHA-256", B.bytesToHex(fp)]);
    var removeHtml = '<div class="cert-section" id="cert-remove"><h4>remove_certificate 参数 <span class="hint">class_id 64 · method 8 · data ::= certificate_identification</span></h4>' +
      '<div class="control-grid single"><div><span class="control-label">识别方式</span><div class="seg" id="rc-mode"><button class="active" data-rc-mode="serial">by_serial</button><button data-rc-mode="entity">by_entity</button></div></div></div>' +
      '<div class="control-grid three" id="rc-entity-fields" hidden>' +
        '<div><span class="control-label">certificate_entity</span><select class="select" id="rc-entity-sel"><option value="0">0 · server</option><option value="1">1 · client</option><option value="2">2 · certification authority</option><option value="3">3 · other</option></select></div>' +
        '<div><span class="control-label">certificate_type</span><select class="select" id="rc-type-sel"><option value="0">0 · digital signature</option><option value="1">1 · key agreement</option><option value="2">2 · TLS</option><option value="3">3 · other</option></select></div>' +
        '<div><span class="control-label">system_title</span><input class="mono-input" id="rc-st" spellcheck="false" placeholder="16 HEX / 8 B"></div>' +
      "</div>" +
      '<div class="field"><div class="field-head"><label for="rc-hex">参数 HEX（A-XDR）</label><div class="field-tools"><button class="mini-btn" id="rc-copy">复制</button></div></div><textarea class="mono-input" id="rc-hex" spellcheck="false" readonly style="min-height:78px"></textarea></div>' +
      '<div id="rc-fields"></div>' +
      '<div class="hint" id="rc-hint" style="margin-top:6px"></div>' +
      "</div>";
    var html = '<h3>证书摘要 <span class="pill pill-ok">已解析</span></h3>' +
      UI.renderKV(kvPairs) +
      '<div class="cert-section"><h4>Key Usage</h4><div class="badge-row">' +
      (ku && ku.value && ku.value.usages ? ku.value.usages.map(function (u) { return '<span class="mini-badge">' + UI.esc(u) + "</span>"; }).join("") : '<span class="hint">未声明</span>') +
      "</div>" +
      '<div class="hint" style="margin-top:5px">BasicConstraints：CA=' + (bc && bc.value ? bc.value.ca : "未声明") + (bc && bc.value && bc.value.pathLen != null ? " · pathLen=" + bc.value.pathLen : "") + "</div>" +
      (san && san.value && san.value.names ? '<div class="hint" style="margin-top:3px">SAN：' + san.value.names.map(function (n) { return n.type + "=" + n.value; }).join(" · ") + "</div>" : "") +
      "</div>" +
      '<div class="cert-section"><h4>验证与提取</h4><div class="key-actions">' +
      '<button class="btn small primary" data-cert-verify>验证证书签名</button>' +
      (isEc ? '<button class="btn small ghost" data-copy="' + pub.rawXY + '">复制 X‖Y</button>' : "") +
      (isEc ? '<button class="btn small ghost" data-copy="' + pub.uncompressed + '">复制 04‖X‖Y</button>' : "") +
      '<button class="btn small ghost" data-copy="' + UI.esc(pub.spkiPem) + '">复制 SPKI PEM</button>' +
      (pub.jwk ? '<button class="btn small ghost" data-copy="' + UI.esc(JSON.stringify(pub.jwk)) + '">复制 JWK</button>' : "") +
      "</div>" +
      (isEc ? '<div class="hint" style="margin-top:6px">DLMS key_data 用原始 X‖Y；X.509 SPKI 里是 04‖X‖Y。不要把 04 一起塞进 key_data。</div>' : '<div class="hint" style="margin-top:6px">RSA 证书只做证书签名验证；DLMS 的 key_data / HLS-7 用 EC 公钥。</div>') +
      "</div>" +
      removeHtml +
      chainHtml +
      (isEc ? '<div class="cert-section"><h4>用此证书验 DLMS 签名</h4>' +
        '<div class="field"><div class="field-head"><label for="cert-dlms-msg">消息</label></div><textarea class="mono-input" id="cert-dlms-msg" spellcheck="false">DLMS</textarea></div>' +
        '<div class="field"><div class="field-head"><label for="cert-dlms-sig">签名（raw R‖S 或 DER）</label></div><textarea class="mono-input" id="cert-dlms-sig" spellcheck="false"></textarea></div>' +
        '<button class="btn small primary" data-cert-dlms-verify>验签</button>' +
        '<div class="hint" id="cert-dlms-status" style="margin-top:6px"></div></div>'
        : '<div class="cert-section"><h4>用此证书验 DLMS 签名</h4><div class="note">该证书是 RSA；DLMS 的 HLS-7 / general-signing 使用 ECDSA，不能用这张证书验 DLMS 签名。</div></div>');
    $("#cert-detail").innerHTML = html;

    var verifyBtn = $("#cert-detail").querySelector("[data-cert-verify]");
    if (verifyBtn) verifyBtn.addEventListener("click", async function () {
      var issuer = certState.certs[index + 1] || c;
      var r = await X509.verifyCertificate(c, issuer);
      toast(r.ok ? "证书签名验证通过" : "证书签名验证失败：" + r.reason);
    });
    var dlmsBtn = $("#cert-detail").querySelector("[data-cert-dlms-verify]");
    if (dlmsBtn) dlmsBtn.addEventListener("click", async function () {
      try {
        var msg = B.utf8ToBytes($("#cert-dlms-msg").value);
        var sig = B.hexToBytes($("#cert-dlms-sig").value);
        var curve = c.spki.curveName || "P-256";
        var pubKey = await EC.importPublicKey({ format: "raw", data: c.spki.publicKeyBytes, curve: curve, usage: "ECDSA" });
        var ok = await EC.verify({ publicKey: pubKey, hash: EC.hashForCurve(curve), message: msg, signature: sig, curve: curve });
        $("#cert-dlms-status").innerHTML = ok ? '<span class="ok-text">✓ 验签通过</span>' : '<span class="bad-text">✗ 验签失败</span>';
      } catch (e) { $("#cert-dlms-status").innerHTML = '<span class="bad-text">✗ ' + UI.esc(e.message) + "</span>"; }
    });
    initRemoveCertSection(c);
  }

  /* remove_certificate (class_id 64, method 8) 的参数：certificate_identification。
     蓝皮书 §4.4.7.3.7 / §4.4.7.3.8；两种定位方式，参数 HEX 与字段表联动。 */
  function initRemoveCertSection(c) {
    var box = document.getElementById("cert-remove");
    if (!box) return;
    var entitySel = document.getElementById("rc-entity-sel");
    var typeSel = document.getElementById("rc-type-sel");
    var stInput = document.getElementById("rc-st");
    var hexArea = document.getElementById("rc-hex");
    var fieldBox = document.getElementById("rc-fields");
    var hint = document.getElementById("rc-hint");
    var mode = "serial";

    var bcExt = c.extensions["2.5.29.19"];
    var kuExt = c.extensions["2.5.29.15"];
    var ekuExt = c.extensions["2.5.29.37"];
    var usages = kuExt && kuExt.value && kuExt.value.usages ? kuExt.value.usages : [];
    var ekuOids = ekuExt && ekuExt.value && ekuExt.value.usages ? ekuExt.value.usages : [];
    var cnPart = c.subject.parts.find(function (p) { return p.name === "CN"; });
    var cn = cnPart ? String(cnPart.value) : "";
    var isCa = !!(bcExt && bcExt.value && bcExt.value.ca);

    entitySel.value = isCa ? "2" : "0";
    typeSel.value = (ekuOids.indexOf("1.3.6.1.5.5.7.3.1") >= 0 || ekuOids.indexOf("1.3.6.1.5.5.7.3.2") >= 0)
      ? "2"
      : usages.indexOf("keyAgreement") >= 0 ? "1"
        : usages.indexOf("digitalSignature") >= 0 ? "0" : "3";
    stInput.value = /^[0-9A-Fa-f]{16}$/.test(cn) ? (cn.toUpperCase().match(/../g) || []).join(" ") : "";

    function update() {
      var opts;
      if (mode === "entity") {
        var st = stInput.value.replace(/[^0-9A-Fa-f]/g, "");
        opts = {
          mode: "entity",
          entity: parseInt(entitySel.value, 10),
          certType: parseInt(typeSel.value, 10),
          systemTitle: st ? B.hexToBytes(st) : null
        };
      } else {
        opts = { mode: "serial", serialDer: c.serialDer, issuerDer: c.issuer.raw };
      }
      try {
        var r = D.encodeCertificateIdentification(opts);
        hexArea.value = B.bytesToHex(r.bytes);
        hexArea.classList.remove("invalid");
        fieldBox.innerHTML = UI.renderFieldTable(r.fields);
        hint.className = "hint";
        hint.textContent = mode === "entity"
          ? "by_entity 按 实体 + 类型 + system title 定位；服务端自己的签名 / 协商 / TLS 证书不能删。"
          : "by_serial 用当前证书的 serial（DER INTEGER TLV）与 issuer（DER Name TLV）定位，CA 与终端证书都适用。";
        if (mode === "entity" && isCa) hint.textContent += "这张是 CA 证书，没有 system title，删除时建议用 by_serial。";
      } catch (e) {
        hexArea.value = "";
        fieldBox.innerHTML = "";
        hint.className = "hint bad-text";
        var msg = e.message;
        if (mode === "entity" && !st) {
          msg = isCa
            ? "这张是 CA 证书，通常没有 system title：删 CA 请切回 by_serial，或手工填 8 B system title"
            : "请填 system title（8 B / 16 HEX）";
        }
        hint.textContent = msg;
      }
    }

    $$("#rc-mode button").forEach(function (b) {
      b.addEventListener("click", function () {
        mode = b.getAttribute("data-rc-mode");
        UI.setSegment(document.getElementById("rc-mode"), "data-rc-mode", mode);
        document.getElementById("rc-entity-fields").hidden = mode !== "entity";
        update();
      });
    });
    [entitySel, typeSel].forEach(function (el) { el.addEventListener("change", update); });
    stInput.addEventListener("input", update);
    document.getElementById("rc-copy").addEventListener("click", function () {
      if (!hexArea.value) { toast("还没有可复制的参数"); return; }
      UI.copyText(hexArea.value);
    });
    update();
  }

  /* ============================================================
     证书签发
     ============================================================ */
  var lastCA = null;

  function normalizeSystemTitle(text) {
    var s = String(text || "").replace(/0x/gi, "").replace(/[\s:_,\-]/g, "");
    if (!/^[0-9A-Fa-f]{16}$/.test(s)) throw new Error("System Title 必须是 16 个十六进制字符（8 字节）");
    return s.toUpperCase();
  }

  function initCertgen() {
    var role = $("#cg-role");
    var usage = $("#cg-usage");

    function syncForm() {
      var isCSR = role.value === "csr";
      var isLeaf = role.value === "leaf" || isCSR;
      var isCA = !isLeaf;
      $("#cg-usage-wrap").hidden = !isLeaf;
      $("#cg-st-wrap").hidden = role.value !== "leaf";
      $("#cg-subject-wrap").hidden = isCSR;
      $("#cg-ou-wrap").hidden = isCSR;
      $("#cg-csr-wrap").hidden = !isCSR;
      $("#cg-extra-wrap").hidden = !isLeaf;
      $("#cg-path-wrap").hidden = !isCA;
      $("#cg-issuer-wrap").hidden = role.value === "root";
      $("#cg-cn").disabled = role.value === "leaf";
      $("#cg-tls-wrap").hidden = !(isLeaf && usage.value === "tls");
      $("#cg-life-wrap").hidden = !(isLeaf && usage.value === "sign");
      if (isCA) {
        $("#cg-cn").value = role.value === "root" ? "Root_CA" : "Sub_CA";
        $("#cg-path").value = role.value === "root" ? "1" : "0";
        $("#cg-cn-hint").textContent = role.value === "root"
          ? "自签 CA 名称，通常 Root_CA"
          : "Sub-CA 名称必须以 CA 结尾";
      } else {
        $("#cg-cn-hint").textContent = isCSR ? "CN 由 CSR 提供" : "终端证书 CN 自动取 System Title";
      }
      if (!lastCA) {
        $("#cg-ca-state").textContent = "本次会话还没有 CA；先生成 Root-CA。";
      }
    }

    role.addEventListener("change", syncForm);
    usage.addEventListener("change", syncForm);

    function csrDerFromText(text, mode) {
      var t = String(text || "").trim();
      if (!t) throw new Error("CSR 为空");
      if (mode === "hex") return B.hexToBytes(t);
      if (/-----BEGIN/.test(t)) return X509.parsePem(t)[0].der;
      var b64 = t.replace(/[^A-Za-z0-9+/=]/g, "");
      if (!b64) throw new Error("CSR 内容为空");
      return B.base64ToBytes(b64);
    }

    $$("#cg-csr-format button").forEach(function (b) {
      b.addEventListener("click", function () {
        var next = b.getAttribute("data-csr");
        if (UI.activeButton($("#cg-csr-format")).getAttribute("data-csr") === next) return;
        var input = $("#cg-csr");
        var text = input.value.trim();
        try {
          if (next === "hex") {
            if (text) input.value = B.bytesToHex(csrDerFromText(text, "pem"));
            $("#cg-csr-hint").textContent = "HEX 按字节解析；支持空格、冒号、0x 前缀";
          } else {
            if (text) input.value = X509.toPem(csrDerFromText(text, "hex"), "CERTIFICATE REQUEST");
            $("#cg-csr-hint").textContent = "支持 PEM 或裸 Base64；切到 HEX 可直接粘贴电表返回的 DER 十六进制";
          }
          UI.setSegment($("#cg-csr-format"), "data-csr", next);
        } catch (e) {
          toast("当前内容无法转换：" + (e.message || e));
        }
      });
    });

    function parseSerial(text) {
      var t = String(text).trim();
      var hex;
      if (/^0x/i.test(t)) {
        hex = t.slice(2).replace(/[^0-9A-Fa-f]/g, "");
        if (!hex) throw new Error("序列号 0x 后缺少十六进制数字");
      } else if (/[A-Fa-f]/.test(t)) {
        hex = t.replace(/[^0-9A-Fa-f]/g, "");
      } else {
        if (!/^\d+$/.test(t)) throw new Error("序列号需为十进制整数或 0x 开头的十六进制");
        var n = Number(t);
        if (!Number.isSafeInteger(n) || n <= 0) throw new Error("序列号必须为正整数");
        hex = n.toString(16);
      }
      if (hex.length % 2) hex = "0" + hex;
      var bytes = B.hexToBytes(hex);
      if (bytes.length > 20) throw new Error("序列号超过 20 字节（RFC 5280 上限）");
      return bytes;
    }

    function growTextarea(el) {
      if (!el || !el.style || el.offsetParent === null) return;
      el.style.height = "auto";
      el.style.height = Math.min(el.scrollHeight + 2, 640) + "px";
    }
    $$("#cg-life button").forEach(function (b) {
      b.addEventListener("click", function () { UI.setSegment($("#cg-life"), "data-cglife", b.getAttribute("data-cglife")); });
    });

    $("#cg-use-ca").addEventListener("click", function () {
      if (!lastCA) { toast("先生成 Root-CA 或 Sub-CA"); return; }
      $("#cg-issuer-cert").value = lastCA.certPem;
      $("#cg-issuer-key").value = lastCA.keyPem;
      toast("已填入本次 CA 的证书与私钥");
    });

    function copyOut(id, label) {
      var v = $(id).value;
      if (!v) { toast("还没有输出"); return; }
      UI.copyText(v);
      toast(label + "已复制");
    }
    $("#cg-copy-cert").addEventListener("click", function () { copyOut("#cg-out-cert", "证书 PEM"); });
    $("#cg-copy-key").addEventListener("click", function () { copyOut("#cg-out-key", "私钥 PEM"); });
    $("#cg-copy-der").addEventListener("click", function () { copyOut("#cg-out-der", "证书 DER"); });
    $("#cg-copy-keyhex").addEventListener("click", function () { copyOut("#cg-out-keyhex", "公钥/私钥 HEX"); });

    $("#cg-download").addEventListener("click", function () {
      var pem = $("#cg-out-cert").value;
      if (!pem) { toast("先生成证书"); return; }
      var cn = (lastOutput && lastOutput.cert.subject.parts.find(function (p) { return p.name === "CN"; }) || {}).value || "certificate";
      UI.download("dlms-" + cn.replace(/[^A-Za-z0-9_-]/g, "_") + ".pem", pem);
    });

    $("#cg-send-cert").addEventListener("click", function () {
      var pem = $("#cg-out-cert").value;
      if (!pem) { toast("先生成证书"); return; }
      $("#cert-input").value = pem;
      go("cert");
      $("#cert-parse").click();
    });

    $("#cg-run").addEventListener("click", cgRun);

    var lastOutput = null;

    async function cgRun() {
      var btn = $("#cg-run");
      busy(btn, true);
      try {
        var roleValue = role.value;
        var suite = $("#cg-suite").value;
        var curve = suite === "2" ? "P-384" : "P-256";
        var isCSR = roleValue === "csr";
        var isCA = roleValue === "root" || roleValue === "sub";
        var subject = isCSR ? null : {
          CN: roleValue === "leaf" ? normalizeSystemTitle($("#cg-st").value) : $("#cg-cn").value.trim(),
          O: $("#cg-o").value.trim(),
          OU: $("#cg-ou").value.trim(),
          C: $("#cg-c").value.trim()
        };
        if (!isCSR && !subject.CN) throw new Error("请填写 CN");
        if (roleValue === "sub" && !/CA$/.test(subject.CN)) throw new Error("Sub-CA 的 CN 必须以 CA 结尾");
        if (!isCA && usage.value === "tls" && !$("#cg-tls").value) throw new Error("请选择 TLS 用途");

        var opts = {
          role: roleValue,
          curve: curve,
          subject: subject,
          usageType: isCA ? "sign" : usage.value,
          tlsRole: $("#cg-tls").value,
          validityDays: parseInt($("#cg-days").value, 10) || 3650,
          pathLen: isCA ? parseInt($("#cg-path").value, 10) : null
        };

        if (!isCA && usage.value === "sign") {
          opts.lifetime = UI.activeButton($("#cg-life")).getAttribute("data-cglife") === "forever";
        }

        var serialText = $("#cg-serial").value.trim();
        if (serialText) opts.serial = parseSerial(serialText);
        var startText = $("#cg-notbefore").value.trim();
        if (startText) {
          var dparts = startText.split("-").map(function (x) { return parseInt(x, 10); });
          var start = new Date(Date.UTC(dparts[0], dparts[1] - 1, dparts[2], 0, 0, 0));
          if (dparts.length < 3 || isNaN(start.getTime())) throw new Error("起始日期格式无效");
          if (!opts.lifetime) {
            if (opts.validityDays <= 0) throw new Error("有效期天数必须大于 0");
            opts.notAfter = new Date(start.getTime() + opts.validityDays * 86400000);
          }
          opts.notBefore = start;
        }

        if (roleValue !== "root") {
          var issuerPem = $("#cg-issuer-cert").value.trim();
          var issuerKeyPem = $("#cg-issuer-key").value.trim();
          if (!issuerPem && lastCA) issuerPem = lastCA.certPem;
          if (!issuerKeyPem && lastCA) issuerKeyPem = lastCA.keyPem;
          if (!issuerPem || !issuerKeyPem) throw new Error("请粘贴签发者证书与私钥，或先生成 CA");
          var issuerCert = X509.parseCertificate(X509.parsePem(issuerPem)[0].der);
          var issuerCurve = issuerCert.spki.curveName;
          if (!CG.HASH[issuerCurve]) throw new Error("签发者证书曲线不支持：" + issuerCurve);
          var issuerKey = await CG.importIssuerKey(issuerKeyPem, issuerCurve);
          var probe = new Uint8Array([0x44, 0x4C, 0x4D, 0x53]);
          var probeSig = await EC.sign({ privateKey: issuerKey, hash: CG.HASH[issuerCurve], message: probe });
          var issuerPub = await EC.importPublicKey({ format: "raw", data: issuerCert.spki.publicKeyBytes, curve: issuerCurve, usage: "ECDSA" });
          var matched = await EC.verify({ publicKey: issuerPub, hash: CG.HASH[issuerCurve], message: probe, signature: probeSig, curve: issuerCurve });
          if (!matched) throw new Error("签发者私钥与证书公钥不匹配");
          opts.issuerCert = issuerCert;
          opts.issuerPrivateKey = issuerKey;
        }

        var out;
        var displayCN = subject ? subject.CN : "";
        if (isCSR) {
          var csrText = $("#cg-csr").value.trim();
          if (!csrText) throw new Error("请粘贴电表生成的 CSR（PEM / 裸 Base64 / DER HEX）");
          var csrFmt = UI.activeButton($("#cg-csr-format")).getAttribute("data-csr");
          var csrDer = csrDerFromText(csrText, csrFmt);
          var parsedCsr = CG.parseCsr(csrDer);
          var cnPart = parsedCsr.subject.parts.find(function (p) { return p.name === "CN"; });
          if (!cnPart || !/^[0-9A-Fa-f]{16}$/.test(cnPart.value)) {
            throw new Error("CSR 的 CN 不是 16 位 System Title，不能按 DLMS 终端证书签发");
          }
          displayCN = cnPart.value.toUpperCase();
          out = await CG.signCsr({
            csrDer: csrDer,
            issuerCert: opts.issuerCert,
            issuerPrivateKey: opts.issuerPrivateKey,
            usageType: opts.usageType,
            tlsRole: opts.tlsRole,
            validityDays: opts.validityDays,
            lifetime: opts.lifetime,
            serial: opts.serial,
            notBefore: opts.notBefore,
            notAfter: opts.notAfter
          });
        } else {
          out = await CG.create(opts);
        }
        lastOutput = out;
        $("#cg-out-cert").value = out.pem;
        $("#cg-out-key").value = out.privateKeyPem || "";
        $("#cg-out-key").placeholder = isCSR ? "CSR 模式：私钥在电表内，工具不接触" : "";
        $("#cg-out-der").value = B.bytesToHex(out.der);
        var pubRaw = out.publicRaw || new Uint8Array(0);
        var pubXY = pubRaw.length ? pubRaw.slice(1) : new Uint8Array(0);
        var keyLines = [];
        if (pubXY.length) keyLines.push("公钥 X‖Y (" + pubXY.length + " B): " + B.bytesToHexCompact(pubXY));
        if (pubRaw.length) keyLines.push("公钥 04‖X‖Y (" + pubRaw.length + " B): " + B.bytesToHexCompact(pubRaw));
        if (out.privateKeyRaw) keyLines.push("私钥 d (" + out.privateKeyRaw.length + " B): " + B.bytesToHexCompact(out.privateKeyRaw));
        else keyLines.push("私钥 d: （CSR 模式，私钥在设备内，不导出）");
        $("#cg-out-keyhex").value = keyLines.join("\n");
        ["cg-out-cert", "cg-out-key", "cg-out-der", "cg-out-keyhex"].forEach(function (id) {
          growTextarea(document.getElementById(id));
        });
        $("#cg-out-badge").textContent = isCSR ? "已签发 CSR" : "已生成";

        if (isCA) {
          lastCA = { certPem: out.pem, keyPem: out.privateKeyPem, der: out.der, cn: subject.CN, curve: curve };
          $("#cg-ca-state").textContent = "本次 CA：" + subject.CN + " · " + curve + " · SKI " + out.ski;
        }

        var ku = out.cert.extensions["2.5.29.15"].value.usages.join(", ");
        var where = roleValue === "root" || roleValue === "sub"
          ? "电表 + 客户端，作为信任锚"
          : usage.value === "sign" ? "server / client 的签名证书槽位"
            : usage.value === "keyAgreement" ? "server / client 的密钥协商证书槽位"
              : "TLS 证书槽位";
        $("#cg-meta").innerHTML = "<b>" + UI.esc(displayCN) + "</b> · " + UI.esc(out.curve) + " 密钥 · " + UI.esc(out.signatureAlgorithm) +
          "<br>Serial: " + UI.esc(out.serial || "—") +
          "<br>keyUsage: " + UI.esc(ku) +
          "<br>SKI: " + UI.esc(out.ski) +
          "<br>AKI: " + UI.esc(out.aki || "（自签，无）") +
          "<br>导入位置: " + UI.esc(where) + (isCSR ? "；私钥仍在电表内" : "；私钥留在本端");
        toast(isCSR ? "CSR 已签发" : "证书已生成");
      } catch (e) {
        toast(e.message || String(e));
      } finally {
        busy(btn, false);
      }
    }

    syncForm();
  }

  /* ============================================================
     报文解析
     ============================================================ */
  var lastParsed = null;

  function initParse() {
    var decrypt = "no";
    $$("#parse-decrypt button").forEach(function (b) {
      b.addEventListener("click", function () {
        UI.setSegment($("#parse-decrypt"), "data-decrypt", b.getAttribute("data-decrypt"));
        decrypt = b.getAttribute("data-decrypt");
      });
    });
    $("#parse-run").addEventListener("click", function () { parseRun(decrypt); });
    $("#parse-send").addEventListener("click", function () {
      if (!lastParsed) { toast("请先解析一段报文"); return; }
      var apdu = lastParsed.apdu;
      setAESMode("dec");
      setHexField("aes-input", B.bytesToHexCompact(apdu));
      var fam = lastParsed.family;
      if (["service-glo", "service-ded", "general-glo", "general-ded"].indexOf(fam) >= 0) $("#aes-family").value = fam;
      if (lastParsed.systemTitle) setHexField("aes-st", B.bytesToHexCompact(lastParsed.systemTitle));
      else if (lastParsed.originatorSystemTitle) setHexField("aes-st", B.bytesToHexCompact(lastParsed.originatorSystemTitle));
      if (lastParsed.ic) setHexField("aes-ic", B.bytesToHexCompact(lastParsed.ic));
      go("aes");
      toast("已填入报文保护页");
    });
  }

  async function parseRun(decrypt) {
    try {
      var bytes = B.hexToBytes($("#parse-input").value);
      if (!bytes.length) throw new Error("请输入报文");
      var frame = null;
      var apdu = bytes;
      if (bytes[0] === 0x7E || (bytes.length >= 8 && bytes[0] === 0x00 && bytes[1] === 0x01)) {
        frame = D.parseAnyFrame(bytes);
        apdu = frame.apdu;
      }
      var parsed = D.parse(apdu);
      lastParsed = parsed;
      var status = { kind: "ok", icon: "✓", title: "解析完成", sub: parsed.family + " · " + D.tagName(parsed.tag) };
      if (frame && frame.type === "HDLC" && !frame.fcsOk) status = { kind: "bad", icon: "!", title: "HDLC FCS 校验失败", sub: "帧可能被改动，或 FCS 计算范围不对" };
      if (frame && frame.type === "WRAPPER" && !frame.lengthOk) status = { kind: "warn", icon: "!", title: "wrapper 长度不一致", sub: "声明长度 " + frame.declaredLength + " B" };
      var extra = "";
      if (frame) {
        extra = '<div class="note" style="margin:0 16px 12px">帧类型：' + frame.type + (frame.type === "HDLC" ? " · FCS " + (frame.fcsOk ? "✓ 通过" : "✗ 失败") + " · 计算值 0x" + frame.fcsValue.toString(16).toUpperCase() : "") + "</div>";
      }
      var plain = null;
      if (decrypt === "yes" && parsed.family !== "plain" && parsed.family !== "general-signing") {
        try {
          var r = await D.decrypt({
            apdu: apdu, parsed: parsed,
            st: UI.readBytes("parse-st", 8, "System Title"),
            ek: UI.readBytes("parse-ek", null, "EK"),
            ak: ($("#parse-ak").value.trim() ? UI.readBytes("parse-ak", null, "AK") : null),
            raw: parsed.family === "raw"
          });
          plain = r;
        } catch (e) {
          extra += '<div class="status bad" style="margin:12px 16px"><span class="status-ico">!</span><div><strong>解密失败</strong><small>' + UI.esc(e.message) + "</small></div></div>";
        }
      }
      if (plain) {
        UI.renderResultCard($("#parse-result"), {
          status: status,
          io: { inLabel: "输入 · 报文", inCode: UI.shortHex(apdu, 72), inSize: apdu.length + " B", outLabel: "输出 · 明文", outCode: B.bytesToHex(plain.plaintext), outSize: plain.plaintext.length + " B" },
          bytes: apdu, fields: parsed.fields, extraHtml: extra,
          actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(plain.plaintext) + '">复制明文</button>'
        });
        $("#parse-result").innerHTML += '<div class="card card-pad" style="margin:12px"><h3>解密结果</h3><div class="byte-view">' + UI.renderByteView(plain.plaintext, [{ name: "明文", offset: 0, length: plain.plaintext.length, color: "plain" }]) + '</div><div style="margin-top:6px;font-family:var(--mono);font-size:10px">' + UI.esc(B.bytesToHex(plain.plaintext)) + "</div></div>";
      } else {
        UI.renderResultCard($("#parse-result"), {
          status: status, bytes: apdu, fields: parsed.fields, extraHtml: extra,
          actions: '<button class="btn small ghost" data-copy="' + B.bytesToHexCompact(apdu) + '">复制 APDU</button>'
        });
      }
    } catch (e) { handleError($("#parse-result"), e); }
  }

  /* ============================================================
     算法总览 / 测试向量
     ============================================================ */
  function initRegistry() {
    $$("#registry-filters .filter").forEach(function (b) {
      b.addEventListener("click", function () {
        $$("#registry-filters .filter").forEach(function (x) { x.classList.remove("active"); });
        b.classList.add("active");
        var cat = b.getAttribute("data-cat");
        $$("#algoGrid .algo-card").forEach(function (card) {
          var cats = (card.getAttribute("data-cat") || "").split(/\s+/);
          card.style.display = (cat === "all" || cats.indexOf(cat) >= 0) ? "" : "none";
        });
      });
    });
    $$("#algoGrid .planned").forEach(function (card) {
      card.addEventListener("click", function () { toast(card.getAttribute("data-plan") || "规划中"); });
    });
  }

  var vectorRows = [];
  function initVectors() {
    vectorRows = [
      { id: "t48a", name: "Table 48 · 仅认证", expected: "tag 06725D…7516" },
      { id: "t48b", name: "Table 48 · 仅加密", expected: "C 411312…C467BC" },
      { id: "t48c", name: "Table 48 · 认证+加密", expected: "C8 报文 32 B" },
      { id: "t51a", name: "Table 51 · f(StoC)", expected: "1A52…1E28" },
      { id: "t51b", name: "Table 51 · f(CtoS)", expected: "FE14…E2B7" },
      { id: "t52a", name: "Table 52 · 客户端签名", expected: "验签通过" },
      { id: "t52b", name: "Table 52 · 服务端签名", expected: "验签通过" },
      { id: "kdf", name: "Annex C.1 · KDF", expected: "C5F4…2F46" },
      { id: "kw", name: "AES-KW · RFC 3394", expected: "2E40…D924" },
      { id: "crc", name: "CRC-16/X.25", expected: "0x906E" },
      { id: "sha", name: "SHA-256(abc)", expected: "BA78…15AD" },
      { id: "md5", name: "MD5(abc)", expected: "9001…7F72" },
      { id: "cert", name: "示例证书链", expected: "链式校验通过" }
    ];
    $("#vectors-list").innerHTML = vectorRows.map(function (r) {
      return '<tr><td>' + UI.esc(r.name) + '</td><td class="mono">' + UI.esc(r.expected) + '</td><td class="status-cell" id="vec-' + r.id + '">—</td></tr>';
    }).join("");
    $("#vectors-run-all").addEventListener("click", runVectors);
  }

  function mark(id, ok, detail) {
    var el = document.getElementById("vec-" + id);
    if (!el) return;
    el.innerHTML = ok ? '<span class="ok">✓ 通过</span>' : '<span class="bad">✗ ' + UI.esc(detail || "失败") + "</span>";
  }

  async function runVectors() {
    var btn = $("#vectors-run-all");
    busy(btn, true);
    var pass = 0, total = 0;
    async function one(id, fn) {
      total++;
      try { var ok = await fn(); mark(id, ok, ""); if (ok) pass++; return ok; }
      catch (e) { mark(id, false, e.message || String(e)); return false; }
    }
    await one("t48a", async function () {
      var r = await D.protect({ plaintext: B.hexToBytes(V.table48.plaintext), st: B.hexToBytes(V.table48.st), ic: B.hexToBytes(V.table48.ic), ek: B.hexToBytes(V.table48.ek), ak: B.hexToBytes(V.table48.ak), suite: 0, auth: true, enc: false, family: "service-glo" });
      return B.bytesToHexCompact(r.apdu) === V.table48.authOnly;
    });
    await one("t48b", async function () {
      var r = await D.protect({ plaintext: B.hexToBytes(V.table48.plaintext), st: B.hexToBytes(V.table48.st), ic: B.hexToBytes(V.table48.ic), ek: B.hexToBytes(V.table48.ek), ak: B.hexToBytes(V.table48.ak), suite: 0, auth: false, enc: true, family: "service-glo" });
      return B.bytesToHexCompact(r.apdu) === V.table48.encOnly;
    });
    await one("t48c", async function () {
      var r = await D.protect({ plaintext: B.hexToBytes(V.table48.plaintext), st: B.hexToBytes(V.table48.st), ic: B.hexToBytes(V.table48.ic), ek: B.hexToBytes(V.table48.ek), ak: B.hexToBytes(V.table48.ak), suite: 0, auth: true, enc: true, family: "service-glo" });
      return B.bytesToHexCompact(r.apdu) === V.table48.authEnc;
    });
    await one("t51a", async function () {
      var r = await D.hls5({ challenge: B.hexToBytes(V.table51.stoC), ek: B.hexToBytes(V.table51.ek), ak: B.hexToBytes(V.table51.ak), st: B.hexToBytes(V.table51.clientST), ic: B.hexToBytes(V.table51.clientIC), suite: 0 });
      return B.bytesToHexCompact(r.output) === V.table51.fStoC;
    });
    await one("t51b", async function () {
      var r = await D.hls5({ challenge: B.hexToBytes(V.table51.ctoS), ek: B.hexToBytes(V.table51.ek), ak: B.hexToBytes(V.table51.ak), st: B.hexToBytes(V.table51.serverST), ic: B.hexToBytes(V.table51.serverIC), suite: 0 });
      return B.bytesToHexCompact(r.output) === V.table51.fCtoS;
    });
    await one("t52a", async function () {
      var pub = await EC.importPublicKey({ format: "raw", data: B.hexToBytes(V.table52.pubClient), curve: "P-256", usage: "ECDSA" });
      var msg = B.concat(B.hexToBytes(V.table52.sysTC), B.hexToBytes(V.table52.sysTS), B.hexToBytes(V.table52.stoC), B.hexToBytes(V.table52.ctoS));
      return await EC.verify({ publicKey: pub, hash: "SHA-256", message: msg, signature: B.hexToBytes(V.table52.fStoC), curve: "P-256" });
    });
    await one("t52b", async function () {
      var pub = await EC.importPublicKey({ format: "raw", data: B.hexToBytes(V.table52.pubServer), curve: "P-256", usage: "ECDSA" });
      var msg = B.concat(B.hexToBytes(V.table52.sysTS), B.hexToBytes(V.table52.sysTC), B.hexToBytes(V.table52.ctoS), B.hexToBytes(V.table52.stoC));
      return await EC.verify({ publicKey: pub, hash: "SHA-256", message: msg, signature: B.hexToBytes(V.table52.fCtoS), curve: "P-256" });
    });
    await one("kdf", async function () {
      var r = await KDF.concatKdf({ z: B.hexToBytes(V.kdf.z), hash: "SHA-256", keydatalenBits: 256, algId: B.hexToBytes(V.kdf.algId), partyU: B.hexToBytes(V.kdf.partyU), partyV: B.hexToBytes(V.kdf.partyV) });
      return B.bytesToHexCompact(r.key) === V.kdf.output;
    });
    await one("kw", async function () {
      var w = await KW.wrap(B.hexToBytes(V.aesKw.kek), B.hexToBytes(V.aesKw.key));
      return B.bytesToHexCompact(w) === V.aesKw.wrapped;
    });
    await one("crc", async function () {
      return CRC.crc16(CRC.CRC16.X25, B.utf8ToBytes("123456789")) === 0x906E;
    });
    await one("sha", async function () {
      return B.bytesToHexCompact(await H.hash("SHA-256", B.utf8ToBytes("abc"))) === V.hashes[0].expected;
    });
    await one("md5", async function () {
      return B.bytesToHexCompact(H.md5(B.utf8ToBytes("abc"))) === V.hashes[1].expected;
    });
    await one("cert", async function () {
      var certs = [V.certs.leafPem, V.certs.interPem, V.certs.rootPem].map(function (pem) { return X509.parseCertificate(X509.parsePem(pem)[0].der); });
      var r = await X509.verifyChain(certs);
      return r.ok;
    });
    $("#vectors-summary").textContent = pass + " / " + total + " 通过";
    $("#vectors-summary").className = "pill " + (pass === total ? "pill-ok" : "pill-bad");
    toast("自检完成：" + pass + " / " + total + " 通过");
    busy(btn, false);
  }

  /* ============================================================
     启动
     ============================================================ */
  function initKeyboard() {
    document.addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        var map = { aes: "aes-run", gmac: "gmac-run", hls: "hls-run", keys: "kw-run", hash: "hash-run", sign: "sign-run", cert: "cert-parse", certgen: "cg-run", parse: "parse-run" };
        var id = map[currentView];
        if (id) { e.preventDefault(); var b = document.getElementById(id); if (b) b.click(); }
      }
    });
    $("#mobile-run").addEventListener("click", function () {
      var map = { aes: "aes-run", gmac: "gmac-run", hls: "hls-run", keys: "kw-run", hash: "hash-run", sign: "sign-run", cert: "cert-parse", certgen: "cg-run", parse: "parse-run" };
      var id = map[currentView];
      if (id) { var b = document.getElementById(id); if (b) b.click(); }
    });
    $("[data-help]").addEventListener("click", function () {
      toast("所有计算在本地浏览器完成；算法口径与边界见 DESIGN.md。");
    });
  }

  UI.initByteFields();
  UI.initFormatGroups();
  UI.initFieldActions();
  UI.bindGlobalActions();
  initNav();
  initAES();
  initGMAC();
  initHLS();
  initKeys();
  initHash();
  initSign();
  initCert();
  initCertgen();
  initParse();
  initRegistry();
  initVectors();
  initKeyboard();
  document.body.classList.add("js-ready");
})();
