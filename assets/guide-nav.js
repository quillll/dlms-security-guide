/* ============================================================
   DLMS 安全完全教程 · 侧边导航
   - 桌面端常驻；移动端抽屉
   - 章内小节可展开；滚动高亮当前小节
   - 打印时由 CSS 隐藏
   ============================================================ */
(function () {
  "use strict";

  var sidebar = document.getElementById("sidebar");
  var toggle = document.getElementById("navToggle");
  var mask = document.getElementById("navMask");
  if (!sidebar || !toggle || !mask) return;

  var links = Array.prototype.slice.call(sidebar.querySelectorAll(".side-link"));
  var groups = Array.prototype.slice.call(sidebar.querySelectorAll(".side-group"));

  var sections = [];
  var seen = {};
  links.forEach(function (a) {
    var href = a.getAttribute("href");
    if (!href || href.charAt(0) !== "#") return;
    var sec = document.querySelector(href);
    if (sec && !seen[href]) {
      seen[href] = true;
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

  function openGroup(group, exclusive) {
    if (!group) return;
    if (exclusive) {
      groups.forEach(function (g) {
        if (g !== group) g.classList.remove("open");
      });
    }
    group.classList.add("open");
  }

  toggle.addEventListener("click", function () {
    setOpen(!sidebar.classList.contains("open"));
  });
  mask.addEventListener("click", function () { setOpen(false); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") setOpen(false);
  });

  // 展开/收起章内小节
  sidebar.querySelectorAll(".side-caret").forEach(function (btn) {
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      var group = btn.closest(".side-group");
      if (group.classList.contains("open")) group.classList.remove("open");
      else openGroup(group, false);
    });
  });

  // 点章标题时顺便展开该章
  sidebar.querySelectorAll(".side-chapter").forEach(function (a) {
    a.addEventListener("click", function () {
      openGroup(a.closest(".side-group"), false);
    });
  });

  // 移动端点链接后关闭抽屉
  sidebar.addEventListener("click", function (e) {
    if (e.target.closest("a")) setOpen(false);
  });

  var lastActiveHref = null;

  function update() {
    if (!sections.length) return;
    var y = window.scrollY + 150;
    var active = sections[0];
    sections.forEach(function (sec) {
      var top = sec.getBoundingClientRect().top + window.scrollY;
      if (top <= y) active = sec;
    });

    var activeHref = "#" + active.id;
    links.forEach(function (a) {
      var on = a.getAttribute("href") === activeHref;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "true");
      else a.removeAttribute("aria-current");
    });

    // 小节高亮时，所属章标题也保持高亮
    groups.forEach(function (g) {
      var chap = g.querySelector(".side-chapter");
      var sub = g.querySelector(".side-sub2.active");
      var on = !!sub || chap.getAttribute("href") === activeHref;
      chap.classList.toggle("active", on);
      if (on) chap.setAttribute("aria-current", "true");
      else chap.removeAttribute("aria-current");
    });

    // 仅在“当前小节变化”时切换手风琴，避免用户手动展开的组被普通滚动关掉
    if (activeHref !== lastActiveHref) {
      lastActiveHref = activeHref;
      var exact = links.filter(function (a) {
        return a.getAttribute("href") === activeHref;
      })[0];
      if (exact) openGroup(exact.closest(".side-group"), true);
    }
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

  // 初始展开：优先当前 hash，否则第 1 章
  var initial = location.hash && document.querySelector(location.hash) ? location.hash : "#ch1";
  var initialLink = links.filter(function (a) {
    return a.getAttribute("href") === initial;
  })[0];
  if (initialLink) openGroup(initialLink.closest(".side-group"), true);
  else if (groups[0]) openGroup(groups[0], true);

  update();

  // 便于分享“直接打开目录”的链接：?menu=1
  try {
    if (new URLSearchParams(window.location.search).get("menu") === "1") {
      setOpen(true);
    }
  } catch (e) {}
})();
