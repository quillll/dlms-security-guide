/* ============================================================
   DLMS/COSEM 课程 · 报文拆分器  (assets/frame-splitter.js)
   零依赖。把一条十六进制报文按 DLMS 的字段顺序切开，并对每个
   字段给出规范依据。支持两类布局：

     ① 服务特定 glo/ded 加密：Tag ‖ Len ‖ SH ‖ 内容 ‖ tag   （第 2 课）
     ② general-* 家族：Tag ‖ [system-title] ‖ … ‖ ciphered-content
        （第 3 课；ciphered-content 内部仍是 ① 的 SH ‖ 内容 ‖ tag）

   依据（绿皮书 Ed.11）：
     §9.2.7.2.4.2  SH = SC ‖ IC（Table 45）
     §9.2.7.2.4.3  保护方式与 P/AAD（Table 46）
     §9.2.7.2.4.6  service-specific glo/ded ciphering 结构（Figure 107）
     §9.2.7.2.4.8  general-ciphering 结构（Figure 109）
     §9.2.7.2.4.9  字段使用对照（Table 47）
     §9.2.7.2.4.10 完整示例（Table 48，32 字节）
     §9.2.5.2      key-info 三种 CHOICE（Table 29）
     Annex C.2     general-ciphering 完整示例（401 / 226 字节）

   用法：
     <div class="frame-splitter" data-frame-splitter></div>
   ============================================================ */

(function () {
  "use strict";

  var SUITES = {
    0: "AES-GCM-128（128 bit 密钥）",
    1: "ECDH-ECDSA-AES-GCM-128-SHA-256",
    2: "ECDH-ECDSA-AES-GCM-256-SHA-384"
  };

  var TAGS = {
    0xc8: { name: "glo-get-request", layout: "simple" },
    0xdb: { name: "general-glo-ciphering（ASN.1 标签 [219]）", layout: "glo" },
    0xdc: { name: "general-ded-ciphering（ASN.1 标签 [220]）", layout: "glo" },
    0xdd: { name: "general-ciphering（ASN.1 标签 [221]）", layout: "general" },
    0xdf: { name: "general-signing（ASN.1 标签 [223]）", layout: "signing" }
  };

  var KEY_INFO_CHOICE = {
    0: "identified-key（用 key-id 指出用哪把全局密钥，密钥已在两端）",
    1: "wrapped-key（把随机生成的密钥用 KEK 包起来传过去）",
    2: "agreed-key（用密钥协商现场算出一把密钥）"
  };

  var KEY_AGREEMENT_PARAMS = {
    "01": "0x01 = C(1e, 1s, ECC CDH) —— One-Pass Diffie-Hellman",
    "02": "0x02 = C(0e, 2s, ECC CDH) —— Static Unified Model"
  };

  // Annex C.2 的完整示例（长度与规范标注一致：401 / 226 字节）
  var GC_REQUEST =
    "DD080102030405060708084D4D4D0000BC614E084D4D4D00000000010000010201018180C323C2BD45711DE46886" +
    "37D919F92E9DB8FB2DFC213A88D21C9DC8DCBA917D8170511DE1BADB360D50058F794B0960AE11FA28D392CFF907" +
    "A62D13E3357B1DC0B51BE089D0B682863B2217201E73A1A9031968A9B4121DCBC3281A69739AF87429F5B3AC547" +
    "1E7B6A04A2C0F2F8A25FD772A317DF97FC5463FEAC248EB8AB8BE81EB3100000000F435069679270C5BF4425EE577" +
    "7402A6C8D51C620EED52DBB188378B836E2857D5C053E6DDF27FA87409AEF502CD9618AE47017C010224FD109CC0" +
    "BEB21E742D44AB40CD11908743EC90EC8C40E221D517F72228E1A26E827F43DC18ED27B5F458D66508B05A2A4CC6" +
    "FED178C881AFC3BC67064689BE8BB41C80ABB3C114A31F4CB03B8B64C7E0B4CE77B2399C93347858888F92239713" +
    "B38DF01C4858245827A92EF334172EA636B31CBBDF2A96AD5D035F66AA38F1A2D97D4BBA99622E6B5F18789CECB2" +
    "DFB3937D9F3E17F8B472098E6563238F37528374809836002AEA6E7012D2ADFAA7";

  var GC_RESPONSE =
    "DD080123456789012345084D4D4D0000000001084D4D4D0000BC614E00000102010181806439724714B47CD9CB98" +
    "8897D8424AB946DCD083D37A954637616011B9C2378773295F0F850D8DAFD1BBE9FE666E53E4F097CD10B38B6962" +
    "2152724A90987444E1FF47974A1F6931A6502F58147463F0E8CC517D47F55B0AC56DD8AC5C9D0E481934F2D90F9893" +
    "016BD82B6E3FFE21FF1588F3278B4E9D98EB4FB62ADD64B3803D3100000000B3FFCAA594642D8319CEC6B2A233E2" +
    "BF4621D6991B97E4565B986E8CCBE9A299D8E7869723638FF6BB20E66E175E6F2D762CFD26B3D58733";

  var PRESETS = [
    ["Annex C.2 · general-ciphering 请求（401 B）", GC_REQUEST],
    ["Annex C.2 · general-ciphering 响应（226 B）", GC_RESPONSE],
    ["Table 48 · glo-get-request 认证+加密", "C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B"],
    ["Table 48 · 仅认证", "C81E1001234567C0010000080000010000FF020006725D910F9221D263877516"],
    ["Table 48 · 仅加密", "C8122001234567411312FF935A47566827C467BC"]
  ];

  /* ---------- 基础工具 ---------- */

  function hex2bytes(s) {
    var clean = s.replace(/[^0-9a-fA-F]/g, "");
    if (clean.length % 2) clean = clean.slice(0, -1);
    var out = [];
    for (var i = 0; i < clean.length; i += 2) out.push(parseInt(clean.substr(i, 2), 16));
    return out;
  }
  function hx(n) { return n.toString(16).toUpperCase().padStart(2, "0"); }
  function bytesHex(a) { return a.map(hx).join(""); }

  // A-XDR 长度：<0x80 单字节；0x81/0x82 为长形式
  function readLen(b, i) {
    if (i >= b.length) return { value: 0, size: 0, error: true };
    if (b[i] < 0x80) return { value: b[i], size: 1 };
    if (b[i] === 0x81 && i + 1 < b.length) return { value: b[i + 1], size: 2 };
    if (b[i] === 0x82 && i + 2 < b.length) return { value: (b[i + 1] << 8) | b[i + 2], size: 3 };
    return { value: b[i], size: 1 };
  }

  function chip(cls, label, value, sub) {
    return '<div class="f ' + cls + '"><b>' + label + '</b><span>' + value + '</span>' +
           (sub ? '<span class="fs-sub">' + sub + '</span>' : "") + "</div>";
  }
  function row(name, value, why) {
    return "<tr><td>" + name + "</td><td><code>" + value + "</code></td><td class=\"fs-why\">" + why + "</td></tr>";
  }

  /* ---------- 拆 SH ‖ 内容 ‖ tag（第 2 课的逻辑，被两处复用） ---------- */

  function splitProtected(bytes) {
    if (bytes.length < 5) return { error: "长度不足 5 字节，装不下 SH（SC ‖ IC）" };
    var sc = bytes[0];
    var ic = bytes.slice(1, 5);
    var A = (sc & 0x10) !== 0;
    var E = (sc & 0x20) !== 0;
    var K = (sc & 0x40) !== 0;
    var C = (sc & 0x80) !== 0;
    var rest = bytes.slice(5);
    var tag = A ? rest.slice(rest.length - 12) : null;
    var payload = A ? rest.slice(0, rest.length - 12) : rest;
    return {
      sc: sc, ic: ic, A: A, E: E, K: K, C: C, suite: sc & 0x0f,
      payload: payload, tag: tag
    };
  }

  function innerHtml(bytes, indent) {
    var s = splitProtected(bytes);
    if (s.error) return '<p class="fs-err">' + s.error + "</p>";

    var prot = s.A && s.E ? "认证 + 加密" : s.A ? "仅认证（GMAC）" : s.E ? "仅加密" : "无保护";
    var html = '<div class="fs-inner">';
    html += '<div class="fs-head2">' + (indent || "ciphered-content 内部") + "：" + prot + "</div>";
    html += '<div class="bytes">';
    html += chip("sec", "SC", "0x" + hx(s.sc), "套件 " + s.suite + " · A=" + (s.A ? 1 : 0) + " E=" + (s.E ? 1 : 0));
    html += chip("sec", "IC", "4 B", bytesHex(s.ic));
    html += chip("enc", "内容", s.payload.length + " B", s.A && !s.E ? "明文" : "密文");
    html += chip("aut", "tag", s.tag ? "12 B" : "0 B", s.tag ? bytesHex(s.tag) : "A=0：不携带");
    html += "</div>";

    html += '<table class="fs-table"><tbody>';
    html += row("SC", "0x" + hx(s.sc),
      "bit7 压缩=" + (s.C ? 1 : 0) + " · bit6 Key_Set=" + (s.K ? "广播" : "单播") +
      " · bit5 E=" + (s.E ? 1 : 0) + " · bit4 A=" + (s.A ? 1 : 0) +
      " · bit3…0 套件=" + s.suite + (SUITES[s.suite] ? "（" + SUITES[s.suite] + "）" : "（保留值）"));
    html += row("IC", bytesHex(s.ic), "调用计数器：4 字节大端，同时也是 IV 的后 4 字节");
    html += row("内容（" + s.payload.length + " B）", bytesHex(s.payload).slice(0, 96) + (s.payload.length > 48 ? "…" : ""),
      s.A && !s.E ? "仅认证：这就是明文" : s.E ? "GCM 输出的密文" : "明文");
    html += row("认证 tag", s.tag ? bytesHex(s.tag) : "（无）",
      s.tag ? "固定 12 字节 = 96 bit（§9.2.3.3.7.6）" : "A = 0：tag 不计算也不携带");
    html += "</tbody></table>";
    html += "</div>";
    return html;
  }

  /* ---------- 主渲染 ---------- */

  function render(root) {
    var wrap = document.createElement("div");
    wrap.className = "fs-ui";
    wrap.innerHTML =
      '<div class="fs-input"><label>报文（hex，可粘贴任意空格/换行）<textarea rows="3" spellcheck="false"></textarea></label></div>' +
      '<div class="fs-presets"></div>' +
      '<div class="fs-out" aria-live="polite"></div>';
    root.innerHTML = "";
    root.appendChild(wrap);

    var ta = wrap.querySelector("textarea");
    var out = wrap.querySelector(".fs-out");
    var presetBox = wrap.querySelector(".fs-presets");
    ta.value = GC_REQUEST;

    PRESETS.forEach(function (p) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "fs-preset";
      btn.textContent = p[0];
      btn.addEventListener("click", function () { ta.value = p[1]; split(); });
      presetBox.appendChild(btn);
    });

    function split() {
      var b = hex2bytes(ta.value);
      if (b.length < 3) { out.innerHTML = '<p class="fs-err">报文太短。</p>'; return; }

      var tagByte = b[0];
      var info = TAGS[tagByte];
      var html = "";

      html += '<div class="fs-head">Tag <code>0x' + hx(tagByte) + "</code> " +
        (info ? "<b>" + info.name + "</b>" : "<b>本课未覆盖的 tag</b>（只按通用结构处理）") + "</div>";

      var layout = info ? info.layout : "simple";

      if (layout === "signing") {
        out.innerHTML = html + '<div class="callout"><span class="label">本课不拆 general-signing</span><p>' +
          "它是 <code>SEQUENCE { transaction-id, originator-system-title, recipient-system-title, date-time, other-information, content, signature }</code>" +
          "（绿皮书 §9.5），没有 SH、也没有 tag——签名的输入串规则与 ciphering 不同。留到讲数字签名时再拆。</p></div>";
        return;
      }

      /* ---------- 布局 ①：服务特定 glo/ded 加密 ---------- */
      if (layout === "simple") {
        var L = readLen(b, 1);
        var start = 1 + L.size;
        var body = b.slice(start, start + L.value);
        var actual = b.length - start;

        html += '<div class="bytes">';
        html += chip("plain", "Tag", "1 B", "0x" + hx(tagByte));
        html += chip("plain", "Len", L.size + " B", L.value + " = 0x" + L.value.toString(16).toUpperCase());
        html += chip("sec", "SH", body.length >= 5 ? "5 B" : "?", body.length >= 5 ? bytesHex(body.slice(0, 5)) : "—");
        html += "</div>";
        html += '<table class="fs-table"><caption>外层</caption><tbody>';
        html += row("Len", "0x" + L.value.toString(16).toUpperCase() + " = " + L.value,
          "从 SH 的第一个字节算起，<b>包含 tag，不包含 Tag 与 Len 自身</b>（口径由 Table 48 反推）");
        html += '<tr><td>实际剩余</td><td><code>' + actual + "</code></td><td class=\"fs-why\">" +
          (actual === L.value ? "与 Len 一致 ✓" : '<span class="warnline">与 Len 不一致（差 ' + (actual - L.value) + "）</span>") +
          "</td></tr></tbody></table>";
        html += innerHtml(body, "SH ‖ 内容 ‖ tag");
        out.innerHTML = html;
        return;
      }

      /* ---------- 布局 ②：general-glo / general-ded ---------- */
      if (layout === "glo") {
        var i = 1;
        var stLen = readLen(b, i); i += stLen.size;
        var st = b.slice(i, i + stLen.value); i += stLen.value;
        var ccLen = readLen(b, i); i += ccLen.size;
        var cc = b.slice(i, i + ccLen.value);

        html += '<div class="bytes">';
        html += chip("plain", "Tag", "1 B", "0x" + hx(tagByte));
        html += chip("sec", "system title", stLen.value + " B", bytesHex(st));
        html += chip("enc", "ciphered-content", ccLen.value + " B", "内含 SH ‖ 内容 ‖ tag");
        html += "</div>";
        html += '<table class="fs-table"><caption>外层字段（Table 47：system-title 只有这一族有）</caption><tbody>';
        html += row("system title", bytesHex(st), "发起者的 system title（8 字节）；这一族不带 transaction-id 与 key-info");
        html += row("ciphered-content 长度", String(ccLen.value), "A-XDR 长度：" + ccLen.size + " 字节");
        html += "</tbody></table>";
        html += innerHtml(cc, "ciphered-content 内部");
        out.innerHTML = html;
        return;
      }

      /* ---------- 布局 ③：general-ciphering ---------- */
      var p = 1;
      var names = ["transaction-id", "originator-system-title", "recipient-system-title", "date-time", "other-information"];
      var fields = [];
      for (var n = 0; n < names.length; n++) {
        var fLen = readLen(b, p); p += fLen.size;
        fields.push({ name: names[n], len: fLen.value, value: b.slice(p, p + fLen.value) });
        p += fLen.value;
      }

      var keyInfoOpt = b[p]; p += 1;
      var keyInfoHtml = "";
      if (keyInfoOpt === 1) {
        var choice = b[p]; p += 1;
        keyInfoHtml += row("key-info → CHOICE", String(choice),
          (KEY_INFO_CHOICE[choice] || "保留值") + "（§9.2.5.2 Table 29 / §9.5 ASN.1）");
        if (choice === 2) {
          var kpLen = readLen(b, p); p += kpLen.size;
          var kp = b.slice(p, p + kpLen.value); p += kpLen.value;
          var kcLen = readLen(b, p); p += kcLen.size;
          var kc = b.slice(p, p + kcLen.value); p += kcLen.value;
          keyInfoHtml += row("　key-parameters", bytesHex(kp), KEY_AGREEMENT_PARAMS[bytesHex(kp)] || "未在 Table 29 中列出");
          keyInfoHtml += row("　key-ciphered-data（" + kcLen.value + " B）", bytesHex(kc).slice(0, 64) + "…",
            "取决于方案：C(1e,1s) 是「临时公钥 ‖ 它的签名」；C(0e,2s) 是空");
        } else if (choice === 1) {
          var kekId = b[p]; p += 1;
          var wkLen = readLen(b, p); p += wkLen.size;
          var wk = b.slice(p, p + wkLen.value); p += wkLen.value;
          keyInfoHtml += row("　kek-id", String(kekId), kekId === 0 ? "0 = master key (KEK)" : "保留值");
          keyInfoHtml += row("　key-ciphered-data（" + wkLen.value + " B）", bytesHex(wk).slice(0, 48) + "…",
            "用 KEK（AES key wrap，RFC 3394）包起来的随机密钥");
        } else if (choice === 0) {
          var keyId = b[p]; p += 1;
          keyInfoHtml += row("　key-id", String(keyId),
            keyId === 0 ? "0 = global-unicast-encryption-key（GUEK）" : keyId === 1 ? "1 = global-broadcast-encryption-key（GBEK）" : "保留值");
        }
      } else {
        keyInfoHtml += row("key-info", "不存在（optional flag = 0）", "两端已各自持有密钥，报文里不再携带 key-info");
      }

      var ccl = readLen(b, p); p += ccl.size;
      var content = b.slice(p, p + ccl.value); p += ccl.value;
      var left = b.length - p;

      html += '<div class="bytes">';
      html += chip("plain", "Tag", "1 B", "0x" + hx(tagByte));
      html += chip("sec", "transaction-id", fields[0].len + " B", bytesHex(fields[0].value));
      html += chip("sec", "两端 system title", (fields[1].len + fields[2].len) + " B", "originator ‖ recipient");
      html += chip("plain", "date-time / other-info", (fields[3].len + fields[4].len) + " B", "长度为 0 = 本报文未带");
      html += chip("sec", "key-info", (keyInfoOpt === 1 ? "有" : "无"), "见下表");
      html += chip("enc", "ciphered-content", ccl.value + " B", "内含 SH ‖ 内容 ‖ tag");
      html += "</div>";

      html += '<table class="fs-table"><caption>外层字段（Figure 109 / Table 47）</caption><tbody>';
      for (var k = 0; k < fields.length; k++) {
        var f = fields[k];
        html += row(f.name, f.len ? bytesHex(f.value) : "（长度 0，未携带）",
          f.len === 0 ? "字段存在但长度为 0：A-XDR OCTET STRING 的空值" :
          f.name === "transaction-id" ? "本次交易的标识；在 C(0e,2s) 方案里它同时充当 NonceU" :
          "参与 KDF 的 PartyUInfo / PartyVInfo（§9.2.3.4.6.5）");
      }
      html += keyInfoHtml;
      html += row("ciphered-content 长度", String(ccl.value), "A-XDR 长度：" + ccl.size + " 字节");
      html += '<tr><td>剩余未用字节</td><td><code>' + Math.max(0, left) + "</code></td><td class=\"fs-why\">" +
        (left === 0 ? "为 0：字段全部自洽 ✓" : '<span class="warnline">不为 0：报文被截断或粘包</span>') + "</td></tr>";
      html += "</tbody></table>";
      html += innerHtml(content, "ciphered-content 内部");

      html += '<div class="callout"><span class="label">这一族的两个记忆点</span><p>' +
        "① <b>只有 general-ciphering 带 key-info</b>——它能在报文里说明「这次用哪把密钥、或现场协商一把」；" +
        "general-glo/ded 只是把已约定的全局密钥用上。<br>" +
        "② Table 47 注：general-ciphering 里 SC 的 <b>Key_Set 位不适用，必须置 0</b>。</p></div>";

      out.innerHTML = html;
    }

    ta.addEventListener("input", split);
    split();
  }

  function init() {
    document.querySelectorAll("[data-frame-splitter]").forEach(render);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
