/* ============================================================
   DLMS 安全完全教程 · 侧边导航
   - 桌面端常驻；移动端抽屉
   - 滚动高亮当前章节
   - 打印时由 CSS 隐藏
   ============================================================ */
(function () {
  "use strict";

  var sidebar = document.getElementById("sidebar");
  var toggle = document.getElementById("navToggle");
  var mask = document.getElementById("navMask");
  if (!sidebar || !toggle || !mask) return;

  var links = Array.prototype.slice.call(sidebar.querySelectorAll(".side-link"));
  // 子锚点被选中时，父章节也保持高亮
  var parentOf = { "#table48": "#ch6", "#matrix": "#ch7" };
  var sections = [];
  var seen = {};
  links.forEach(function (a) {
    var id = a.getAttribute("href");
    if (!id || id.charAt(0) !== "#") return;
    var sec = document.querySelector(id);
    if (sec && !seen[id]) {
      seen[id] = true;
      sections.push(sec);
    }
  });

  function setOpen(open) {
    if (window.innerWidth >= 1180) open = false;
    sidebar.classList.toggle("open", open);
    mask.classList.toggle("show", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    document.body.style.overflow = open ? "hidden" : "";
  }

  toggle.addEventListener("click", function () {
    setOpen(!sidebar.classList.contains("open"));
  });
  mask.addEventListener("click", function () { setOpen(false); });
  sidebar.addEventListener("click", function (e) {
    if (e.target.closest("a")) setOpen(false);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") setOpen(false);
  });

  function update() {
    if (!sections.length) return;
    var y = window.scrollY + 150;
    var active = sections[0];
    sections.forEach(function (sec) {
      var top = sec.getBoundingClientRect().top + window.scrollY;
      if (top <= y) active = sec;
    });
    links.forEach(function (a) {
      var href = a.getAttribute("href");
      var on = href === "#" + active.id || parentOf["#" + active.id] === href;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "true");
      else a.removeAttribute("aria-current");
    });
  }

  var ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    window.requestAnimationFrame(function () {
      update();
      ticking = false;
    });
  }

  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", function () {
    if (window.innerWidth >= 1180) setOpen(false);
    update();
  });
  window.addEventListener("load", update);
  update();

  // 便于分享“直接打开目录”的链接：?menu=1
  try {
    if (new URLSearchParams(window.location.search).get("menu") === "1") {
      setOpen(true);
    }
  } catch (e) {}

})();
