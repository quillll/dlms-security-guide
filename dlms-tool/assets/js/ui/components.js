/* ============================================================
   DLMS 安全算法工作台 · 通用 UI 组件
   ============================================================ */
(function (global) {
  "use strict";

  var DLMS = global.DLMS = global.DLMS || {};
  var B = DLMS.Bytes;

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function hex(bytes) { return B.bytesToHex(bytes); }
  function hexCompact(bytes) { return B.bytesToHexCompact(bytes); }

  var toastTimer = null;
  function toast(msg) {
    var el = $("#toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove("show"); }, 2800);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () { toast("已复制到剪贴板"); }, function () { toast("浏览器拒绝了剪贴板访问"); });
    }
    var ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); toast("已复制到剪贴板"); }
    catch (e) { toast("复制失败"); }
    document.body.removeChild(ta);
    return Promise.resolve();
  }

  function download(filename, text) {
    var blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
    toast("已开始下载 " + filename);
  }

  function activeButton(seg) {
    return seg ? seg.querySelector("button.active") : null;
  }

  function setSegment(seg, attr, value) {
    if (!seg) return;
    $$("button", seg).forEach(function (b) { b.classList.toggle("active", b.getAttribute(attr) === value); });
  }

  function formatBytesInput(input, bytes, fmt) {
    fmt = fmt || "hex";
    input.dataset.fmt = fmt;
    if (fmt === "hex") input.value = B.bytesToHex(bytes);
    else if (fmt === "raw") input.value = B.bytesToHexCompact(bytes).toUpperCase();
    else if (fmt === "ascii") input.value = B.bytesToAscii(bytes);
    else if (fmt === "b64") input.value = B.bytesToBase64(bytes);
    else if (fmt === "dec") {
      try { input.value = String(B.readU32be(bytes)); } catch (e) { input.value = ""; }
    } else if (fmt === "pem" || fmt === "jwk") {
      // key material formats are handled separately
    }
  }

  function bytesFromInput(input) {
    var fmt = input.dataset.fmt || "hex";
    var v = input.value;
    if (fmt === "hex" || fmt === "raw") return B.hexToBytes(v);
    if (fmt === "ascii") return B.utf8ToBytes(v);
    if (fmt === "b64") return B.base64ToBytes(v);
    if (fmt === "dec") return B.u32be(B.parseUint32(v));
    return B.hexToBytes(v);
  }

  function readBytes(id, expected, label) {
    var input = document.getElementById(id);
    if (!input) throw { field: id, message: "找不到输入框 " + id };
    var bytes;
    try { bytes = bytesFromInput(input); }
    catch (e) { throw { field: id, message: (label || id) + "：" + e.message }; }
    if (!bytes.length) throw { field: id, message: (label || id) + " 不能为空" };
    if (expected != null) {
      var ok = Array.isArray(expected) ? expected.indexOf(bytes.length) >= 0 : bytes.length === expected;
      if (!ok) {
        var want = Array.isArray(expected) ? expected.join(" / ") : expected;
        throw { field: id, message: (label || id) + " 需要 " + want + " B，当前 " + bytes.length + " B" };
      }
    }
    return bytes;
  }

  function readText(id) {
    var el = document.getElementById(id);
    return el ? el.value.trim() : "";
  }

  function clearFieldError(id) {
    var input = document.getElementById(id);
    if (!input) return;
    input.classList.remove("invalid");
    var field = input.closest(".field");
    if (!field) return;
    var foot = field.querySelector(".field-foot");
    if (!foot) return;
    var first = foot.querySelector("span");
    if (!first) return;
    try {
      var n = bytesFromInput(input).length;
      first.textContent = n ? "✓ " + n + " 字节" : "待输入";
      first.className = n ? "ok-text" : "warn-text";
    } catch (e) {
      first.textContent = "待输入";
      first.className = "warn-text";
    }
  }

  function setFieldError(id, message) {
    var input = document.getElementById(id);
    if (!input) return;
    input.classList.add("invalid");
    var field = input.closest(".field");
    if (!field) return;
    var foot = field.querySelector(".field-foot");
    if (foot) {
      var first = foot.querySelector("span");
      if (first) { first.textContent = "✗ " + message; first.className = "bad-text"; }
    }
  }

  function clearAllErrors() {
    $$(".mono-input.invalid").forEach(function (input) { clearFieldError(input.id); });
  }

  function initByteFields() {
    $$(".mono-input[data-hex]").forEach(function (input) {
      if (input.readOnly) return;
      if (input.dataset.noInit === "true") return;
      try {
        var bytes = B.hexToBytes(input.dataset.hex || "");
        formatBytesInput(input, bytes, input.dataset.fmt || "hex");
      } catch (e) { /* leave as-is */ }
    });
  }

  function initFormatGroups() {
    $$(".fmt-group").forEach(function (group) {
      var target = group.getAttribute("data-target");
      $$(".fmt", group).forEach(function (btn) {
        btn.addEventListener("click", function () {
          var fmt = btn.getAttribute("data-fmt");
          $$(".fmt", group).forEach(function (b) { b.classList.remove("active"); });
          btn.classList.add("active");
          var input = document.getElementById(target);
          if (!input) return;
          if (target === "hls-priv") {
            input.dataset.keyFormat = fmt;
            input.dataset.fmt = fmt === "raw" ? "raw" : "text";
            if (fmt === "raw" && !input.value.trim()) {
              try { formatBytesInput(input, B.hexToBytes(input.dataset.hex || ""), "raw"); } catch (e) {}
            }
            toast("私钥格式已切换为 " + fmt.toUpperCase() + "；请粘贴对应格式的内容");
            return;
          }
          try {
            var bytes = bytesFromInput(input);
            formatBytesInput(input, bytes, fmt);
            clearFieldError(target);
          } catch (e) {
            toast("无法转换：" + e.message);
          }
        });
      });
    });
  }

  function initFieldActions() {
    $$("[data-clear]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var input = document.getElementById(btn.getAttribute("data-clear"));
        if (!input) return;
        input.value = "";
        input.dataset.hex = "";
        input.classList.remove("invalid");
        var field = input.closest(".field");
        if (field) {
          var first = field.querySelector(".field-foot span");
          if (first) { first.textContent = "待输入"; first.className = "warn-text"; }
        }
        toast("已清空该字段");
      });
    });

    $$("[data-random]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.getAttribute("data-random");
        var input = document.getElementById(id);
        if (!input) return;
        var len = parseInt(btn.getAttribute("data-len") || "16", 10);
        if (id === "aes-ek" || id === "aes-ak") {
          var aesSuite = document.getElementById("aes-suite");
          if (aesSuite) len = parseInt(aesSuite.value, 10) === 2 ? 32 : 16;
        }
        if (id === "gmac-ek" || id === "gmac-ak") {
          var gmacSuite = document.getElementById("gmac-suite");
          if (gmacSuite) len = parseInt(gmacSuite.value, 10) === 2 ? 32 : 16;
        }
        if (id === "hls-ek" || id === "hls-ak") {
          var hlsSuite = document.getElementById("hls-suite");
          if (hlsSuite) len = parseInt(hlsSuite.value, 10) === 2 ? 32 : 16;
        }
        var bytes = B.randomBytes(len);
        input.dataset.hex = hexCompact(bytes);
        formatBytesInput(input, bytes, input.dataset.fmt || "hex");
        clearFieldError(id);
        toast("已生成 " + len + " B 随机值");
      });
    });

    $$("[data-mask]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var input = document.getElementById(btn.getAttribute("data-mask"));
        if (input) input.classList.toggle("masked");
      });
    });

    $$("[data-step]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var input = document.getElementById(btn.getAttribute("data-step"));
        if (!input) return;
        try {
          var bytes = bytesFromInput(input);
          if (bytes.length !== 4) throw new Error("IC 需要 4 B");
          var n = (B.readU32be(bytes) + 1) >>> 0;
          var out = B.u32be(n);
          input.dataset.hex = hexCompact(out);
          formatBytesInput(input, out, input.dataset.fmt || "hex");
          var field = input.closest(".field");
          if (field) {
            var last = field.querySelector(".field-foot span:last-child");
            if (last) last.textContent = "十进制 " + n;
          }
          toast("IC 已 +1");
        } catch (e) { toast(e.message); }
      });
    });

    $$(".mono-input[data-hex]").forEach(function (input) {
      input.addEventListener("input", function () {
        var fmt = input.dataset.fmt || "hex";
        if (fmt === "text" || fmt === "pem" || fmt === "jwk") {
          var fieldText = input.closest(".field");
          if (fieldText) {
            var ft = fieldText.querySelector(".field-foot span");
            if (ft) { ft.textContent = "已输入文本"; ft.className = "hint"; }
          }
          return;
        }
        if (fmt === "hex" || fmt === "raw") {
          try { input.dataset.hex = hexCompact(B.hexToBytes(input.value)); } catch (e) { /* don't normalize while typing */ }
        }
        var field = input.closest(".field");
        if (!field) return;
        var first = field.querySelector(".field-foot span");
        if (!first) return;
        try {
          var n = bytesFromInput(input).length;
          first.textContent = n ? "✓ " + n + " 字节" : "待输入";
          first.className = n ? "ok-text" : "warn-text";
        } catch (e) {
          first.textContent = "格式待修正";
          first.className = "bad-text";
        }
      });
    });
  }

  function bindGlobalActions() {
    document.addEventListener("click", function (e) {
      var copyBtn = e.target.closest("[data-copy]");
      if (copyBtn) {
        e.preventDefault();
        copyText(copyBtn.getAttribute("data-copy") || "");
        return;
      }
      var dlBtn = e.target.closest("[data-download]");
      if (dlBtn) {
        e.preventDefault();
        download(dlBtn.getAttribute("data-download-name") || "dlms-output.txt", dlBtn.getAttribute("data-download") || "");
        return;
      }
      var toastBtn = e.target.closest("[data-toast]");
      if (toastBtn) { toast(toastBtn.getAttribute("data-toast")); }
    });
  }

  var COLOR_LABEL = {
    tag: "APDU tag", len: "长度", sc: "SC", ic: "IC", ct: "密文",
    auth: "认证 tag", plain: "明文 / 内容"
  };

  function renderByteView(bytes, fields) {
    if (!bytes || !bytes.length) return "";
    var colors = new Array(bytes.length).fill("plain");
    (fields || []).forEach(function (f) {
      if (f.offset == null || f.length == null || !f.color) return;
      for (var i = f.offset; i < f.offset + f.length && i < colors.length; i++) colors[i] = f.color;
    });
    var rows = [];
    for (var off = 0; off < bytes.length; off += 16) {
      var cells = [];
      for (var i = off; i < Math.min(off + 16, bytes.length); i++) {
        var b = bytes[i];
        cells.push('<span class="byte b-' + colors[i] + '">' + (b < 16 ? "0" : "") + b.toString(16).toUpperCase() + "</span>");
      }
      rows.push('<div class="byte-row"><span class="offset">' + off.toString(16).toUpperCase().padStart(4, "0") + "</span>" + cells.join("") + "</div>");
    }
    var present = {};
    colors.forEach(function (c) { present[c] = true; });
    var legend = Object.keys(present).map(function (c) {
      var cls = c === "plain" ? "plain" : c;
      return '<span class="lg"><i class="sw ' + cls + '"></i>' + esc(COLOR_LABEL[c] || c) + "</span>";
    }).join("");
    return '<div class="byte-view">' + rows.join("") + '</div><div class="legend">' + legend + "</div>";
  }

  function renderFieldTable(fields) {
    if (!fields || !fields.length) return "";
    var rows = fields.map(function (f) {
      var val = f.value == null ? "" : String(f.value);
      var short = val.length > 80 ? val.slice(0, 80) + "…" : val;
      return "<tr><td><i class=\"dot " + esc(f.color || "plain") + "\"></i>" + esc(f.name) + "</td>" +
        '<td class="mono">' + (f.offset == null ? "" : f.offset) + "</td>" +
        '<td class="mono">' + (f.length == null ? "" : f.length) + "</td>" +
        '<td class="mono" title="' + esc(val) + '">' + esc(short) + "</td>" +
        "<td>" + esc(f.note || "") + "</td></tr>";
    }).join("");
    return '<div class="field-table-wrap"><table class="field-table"><thead><tr><th>字段</th><th>偏移</th><th>长度</th><th>值</th><th>说明</th></tr></thead><tbody>' + rows + "</tbody></table></div>";
  }

  function traceList(items) {
    if (!items || !items.length) return "";
    return '<ol class="trace">' + items.map(function (it, i) {
      return '<li><span class="trace-num">' + (i + 1) + "</span><div><b>" + esc(it.label) + "</b><code>" + esc(it.value || "") + "</code><small>" + esc(it.note || "") + "</small></div></li>";
    }).join("") + "</ol>";
  }

  function renderResultCard(container, opts) {
    if (!container) return;
    opts = opts || {};
    var st = opts.status || { kind: "ok", icon: "✓", title: "完成", sub: "" };
    var icon = st.icon || (st.kind === "bad" ? "!" : st.kind === "warn" ? "!" : "✓");
    var statusHtml = '<div class="status ' + (st.kind || "ok") + '"><span class="status-ico">' + esc(icon) + '</span><div><strong>' + esc(st.title || "") + "</strong>" + (st.sub ? "<small>" + esc(st.sub) + "</small>" : "") + "</div></div>";
    var actions = opts.headerActions || "";
    var ioHtml = "";
    if (opts.io) {
      ioHtml = '<div class="io-compare">' +
        '<div class="io-cell"><span>' + esc(opts.io.inLabel) + "</span><code>" + esc(opts.io.inCode || "") + "</code><small>" + esc(opts.io.inSize || "") + "</small></div>" +
        '<div class="io-arrow">→</div>' +
        '<div class="io-cell"><span>' + esc(opts.io.outLabel) + "</span><code>" + esc(opts.io.outCode || "") + "</code><small>" + esc(opts.io.outSize || "") + "</small></div>" +
        "</div>";
    }
    var body = "";
    if (opts.bytes && opts.bytes.length) {
      var uid = container.id || "res";
      var bytes = opts.bytes;
      body += '<div class="tabs"><button class="tab active" data-pane-target="' + uid + '-hex">HEX</button><button class="tab" data-pane-target="' + uid + '-b64">BASE64</button><button class="tab" data-pane-target="' + uid + '-ascii">ASCII</button><span class="tab-meta">' + bytes.length + " B</span></div>" +
        '<div class="pane active" id="' + uid + '-hex">' + renderByteView(bytes, opts.fields) + "</div>" +
        '<div class="pane" id="' + uid + '-b64"><textarea readonly spellcheck="false">' + esc(B.bytesToBase64(bytes)) + "</textarea></div>" +
        '<div class="pane" id="' + uid + '-ascii"><pre>' + esc(B.bytesToAscii(bytes)) + "</pre></div>";
    }
    if (opts.fields && opts.fields.length) body += renderFieldTable(opts.fields);
    if (opts.extraHtml) body += opts.extraHtml;
    if (opts.trace && opts.trace.length) body += '<div style="padding:0 16px 12px"><div class="section-title">计算轨迹</div>' + traceList(opts.trace) + "</div>";
    var foot = "";
    if (opts.actions) foot = '<div class="result-foot">' + opts.actions + "</div>";
    container.classList.remove("is-empty");
    container.innerHTML = '<div class="result-head">' + statusHtml + '<div class="result-actions">' + actions + "</div></div>" +
      ioHtml + '<div class="result-body">' + body + foot + "</div>";
    $$("[data-pane-target]", container).forEach(function (tab) {
      tab.addEventListener("click", function () {
        $$(".tab", container).forEach(function (t) { t.classList.remove("active"); });
        tab.classList.add("active");
        $$(".pane", container).forEach(function (p) { p.classList.remove("active"); });
        var pane = document.getElementById(tab.getAttribute("data-pane-target"));
        if (pane) pane.classList.add("active");
      });
    });
  }

  function emptyResult(container, title, sub, icon) {
    if (!container) return;
    container.classList.add("is-empty");
    container.innerHTML = '<div class="empty-state"><div class="big"><svg class="ico"><use href="#' + (icon || "i-grid") + '"/></svg></div><strong>' + esc(title || "等待参数") + "</strong>" + (sub ? '<div style="font-size:9.5px;margin-top:3px">' + esc(sub) + "</div>" : "") + "</div>";
  }

  function renderKV(pairs) {
    return '<dl class="kv">' + pairs.map(function (p) {
      return "<dt>" + esc(p[0]) + "</dt><dd" + (p[2] ? ' class="' + esc(p[2]) + '"' : "") + ">" + esc(p[1] == null ? "" : p[1]) + "</dd>";
    }).join("") + "</dl>";
  }

  function shortHex(bytes, n) {
    var s = hexCompact(bytes);
    return s.length > (n || 32) ? s.slice(0, n || 32) + "…" : s;
  }

  DLMS.UI = {
    $: $, $$: $$, esc: esc, toast: toast, copyText: copyText, download: download,
    activeButton: activeButton, setSegment: setSegment,
    hex: hex, hexCompact: hexCompact, shortHex: shortHex,
    formatBytesInput: formatBytesInput, bytesFromInput: bytesFromInput,
    readBytes: readBytes, readText: readText,
    initByteFields: initByteFields, initFormatGroups: initFormatGroups, initFieldActions: initFieldActions,
    clearFieldError: clearFieldError, setFieldError: setFieldError, clearAllErrors: clearAllErrors,
    bindGlobalActions: bindGlobalActions,
    renderResultCard: renderResultCard, emptyResult: emptyResult,
    renderByteView: renderByteView, renderFieldTable: renderFieldTable, traceList: traceList,
    renderKV: renderKV
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
