/* ============================================================
   DLMS/COSEM 课程 · Security Control 字节解码器  (assets/sc-decoder.js)
   零依赖。把"读 SC 字节"变成可点、可验的反馈闭环。

   依据（绿皮书 Ed.11）：
     §9.2.7.2.4.2  Table 45 – Security control byte
     §9.2.7.2.4.3  Table 46 – Plaintext and AAD
     §9.2.3.7      Table 27 – DLMS/COSEM security suites
     §9.2.3.3.7.4/6  EK 长度、tag 长度

   用法：
     <div class="sc-decoder" data-sc-decoder>
       <noscript>…静态说明…</noscript>
     </div>
   组件自行渲染输入控件、位开关、预设与解读结果。
   ============================================================ */

(function () {
  "use strict";

  var SUITES = {
    0: { name: "AES-GCM-128", ek: 128, kek: 128, tag: 96, note: "只有对称算法；无签名、无密钥协商" },
    1: { name: "ECDH-ECDSA-AES-GCM-128-SHA-256", ek: 128, kek: 128, tag: 96, note: "ECDSA P-256 · ECDH P-256 · SHA-256 · V.44 压缩" },
    2: { name: "ECDH-ECDSA-AES-GCM-256-SHA-384", ek: 256, kek: 256, tag: 96, note: "ECDSA P-384 · ECDH P-384 · SHA-384 · V.44 压缩" }
  };

  // bit7 … bit4，低位 4 bit 是 suite id（单独处理）
  var HIGH_BITS = [
    { mask: 0x80, bit: 7, label: "C", title: "Compression", desc: "使用 V.44 压缩" },
    { mask: 0x40, bit: 6, label: "K", title: "Key_Set", desc: "1 = 广播密钥（0 = 单播）；dedicated / general ciphering 时该位不适用，应为 0" },
    { mask: 0x20, bit: 5, label: "E", title: "Encryption", desc: "对明文做加密" },
    { mask: 0x10, bit: 4, label: "A", title: "Authentication", desc: "附加认证标签（GCM tag）" }
  ];

  function hx(n) { return n.toString(16).toUpperCase().padStart(2, "0"); }

  function protectionOf(A, E) {
    if (A && E) return {
      name: "Encrypted and authenticated（加密 + 认证）",
      P: "(C) I —— 明文是要保护的 APDU/数据，加密后成为密文",
      AAD: "SC ‖ AK（general-ciphering 还要加 transaction-id、两端 system title、date-time、other-information）"
    };
    if (A && !E) return {
      name: "Authenticated only（仅认证，即 GMAC）",
      P: "—— P 为空：没有内容被加密",
      AAD: "SC ‖ AK ‖ (C) I —— 内容整体进 AAD，报文里以明文携带并附 tag：完整性有保护，机密性没有"
    };
    if (!A && E) return {
      name: "Encrypted only（仅加密）",
      P: "(C) I",
      AAD: "—— 规范未把任何字段列为 AAD；§9.2.3.3.7.1 明确说明这一档 “the authentication tags are simply not computed and checked”，报文结构中也没有 tag 字段：只有机密性，没有完整性"
    };
    return {
      name: "None（无保护）",
      P: "——",
      AAD: "—— 这是 security policy = 0 或未加保护的普通 APDU"
    };
  }

  function render(root) {
    var state = { sc: 0x30 };

    var presets = root.getAttribute("data-presets");
    if (presets === null) {
      presets = "0x30|Suite 0 · 认证+加密;0x11|Suite 1 · 仅认证（GMAC）;0x21|Suite 1 · 仅加密（对照 0x11）;0x32|Suite 2 · 认证+加密;0x91|Suite 1 · 压缩+仅认证;0x40|Key_Set=广播（对照）";
    }

    var wrap = document.createElement("div");
    wrap.className = "sc-ui";
    wrap.innerHTML =
      '<div class="sc-row sc-top">' +
        '<label class="sc-hexwrap">SC 字节（hex） <input class="sc-hex" type="text" inputmode="latin" spellcheck="false" maxlength="4" size="4" value="30" aria-label="Security control 字节，十六进制"></label>' +
        '<span class="sc-presets"></span>' +
      '</div>' +
      '<div class="sc-row sc-bitrow"></div>' +
      '<div class="sc-row sc-suite"></div>' +
      '<div class="sc-readout" aria-live="polite"></div>';

    root.innerHTML = "";
    root.appendChild(wrap);

    var hexInput = wrap.querySelector(".sc-hex");
    var bitRow = wrap.querySelector(".sc-bitrow");
    var suiteRow = wrap.querySelector(".sc-suite");
    var readout = wrap.querySelector(".sc-readout");
    var presetBox = wrap.querySelector(".sc-presets");

    // 高位开关
    var toggles = HIGH_BITS.map(function (b) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "sc-bit";
      btn.dataset.mask = String(b.mask);
      btn.innerHTML = '<b>bit' + b.bit + '</b><span class="nm">' + b.label + '</span><span class="full">' + b.title + '</span>';
      btn.title = b.title + " — " + b.desc;
      btn.addEventListener("click", function () {
        state.sc ^= b.mask;
        sync();
      });
      bitRow.appendChild(btn);
      return btn;
    });

    // 低位：suite id 选择器
    var suiteLabel = document.createElement("span");
    suiteLabel.className = "sc-suitelabel";
    suiteLabel.textContent = "bit3…0 · Security_Suite_Id";
    var suiteSel = document.createElement("select");
    suiteSel.className = "sc-suitesel";
    for (var i = 0; i < 16; i++) {
      var opt = document.createElement("option");
      opt.value = String(i);
      opt.textContent = i + (SUITES[i] ? " — " + SUITES[i].name : " — reserved（保留）");
      suiteSel.appendChild(opt);
    }
    suiteSel.addEventListener("change", function () {
      state.sc = (state.sc & 0xF0) | parseInt(suiteSel.value, 10);
      sync();
    });
    suiteRow.appendChild(suiteLabel);
    suiteRow.appendChild(suiteSel);

    // 预设
    presets.split(";").forEach(function (p) {
      var parts = p.split("|");
      if (parts.length < 2) return;
      var val = parseInt(parts[0], 16);
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "sc-preset";
      btn.textContent = parts[1];
      btn.addEventListener("click", function () { state.sc = val; sync(); });
      presetBox.appendChild(btn);
    });

    hexInput.addEventListener("input", function () {
      var m = hexInput.value.replace(/[^0-9a-fA-F]/g, "").slice(0, 2);
      if (!m) return;
      state.sc = parseInt(m, 16);
      sync(true);
    });

    function sync(fromHex) {
      var sc = state.sc & 0xFF;
      if (!fromHex) hexInput.value = hx(sc);

      toggles.forEach(function (btn) {
        var on = (sc & Number(btn.dataset.mask)) !== 0;
        btn.classList.toggle("on", on);
        btn.setAttribute("aria-pressed", on ? "true" : "false");
      });
      var id = sc & 0x0F;
      suiteSel.value = String(id);

      var A = (sc & 0x10) !== 0;
      var E = (sc & 0x20) !== 0;
      var K = (sc & 0x40) !== 0;
      var C = (sc & 0x80) !== 0;
      var pr = protectionOf(A, E);
      var suite = SUITES[id];
      var bits = sc.toString(2).padStart(8, "0").replace(/(....)(....)/, "$1 $2");

      var suiteHtml = suite
        ? '<b>Suite ' + id + '</b> · ' + suite.name +
          '<span class="sc-meta">EK/KEK ' + suite.ek + '/' + suite.kek + ' bit · tag ' + suite.tag + ' bit · ' + suite.note + '</span>'
        : '<b>Suite ' + id + '</b> · <span class="warnline">保留值：规范未定义（Table 27: “All other reserved”）</span>';

      readout.innerHTML =
        '<div class="sc-out-head">SC = <code>0x' + hx(sc) + '</code> <span class="sc-bin">0b' + bits + '</span></div>' +
        '<div class="sc-out-line">' + suiteHtml + '</div>' +
        '<div class="sc-out-line"><b>保护方式</b> ' + pr.name + '</div>' +
        '<div class="sc-out-line"><b>P（明文）</b> ' + pr.P + '</div>' +
        '<div class="sc-out-line"><b>A（AAD）</b> ' + pr.AAD + '</div>' +
        '<div class="sc-out-line"><b>Key_Set</b> ' + (K ? "1 = 广播密钥（GBEK）" : "0 = 单播（GUEK）") +
          (C ? ' · <b>压缩</b> 已启用（V.44）' : "") + '</div>' +
        '<div class="sc-out-foot">尺寸口径见绿皮书 §9.2.3.3.7.4 / §9.2.3.3.7.6；A/E 与 P/AAD 的对应见 §9.2.7.2.4.3 Table 46。</div>';
    }

    sync();
  }

  function init() {
    document.querySelectorAll("[data-sc-decoder]").forEach(render);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
