/* ============================================================
   DLMS/COSEM 课程 · 测验组件  (assets/quiz.js)
   零依赖、渐进增强：无 JS 时题面与解析仍然可读。

   用法（HTML）：
     <div class="quiz" data-quiz>
       <p class="q">题干？</p>
       <ul class="opts">
         <li data-correct="true">正确答案</li>
         <li>干扰项</li>
       </ul>
       <p class="feedback"><b>解析。</b>补充说明。</p>
       <p class="hint">提示文字（可选）</p>
     </div>

   约定：每个选项词数尽量相同，不给格式线索。
   ============================================================ */

(function () {
  "use strict";

  var MARKS = "ABCDEFGH";

  function initQuiz(root) {
    var opts = Array.prototype.slice.call(root.querySelectorAll(".opts li"));
    if (!opts.length) return;

    var feedback = root.querySelector(".feedback");
    var hint = root.querySelector(".hint");
    var answered = false;

    opts.forEach(function (li, i) {
      var mark = document.createElement("span");
      mark.className = "mark";
      mark.textContent = MARKS[i] || String(i + 1);
      li.insertBefore(mark, li.firstChild);
      li.setAttribute("role", "button");
      li.setAttribute("tabindex", "0");
      li.setAttribute("aria-pressed", "false");

      function choose() {
        if (answered) return;
        answered = true;

        opts.forEach(function (other) {
          other.classList.add("locked");
          other.setAttribute("tabindex", "-1");
          if (other.hasAttribute("data-correct")) other.classList.add("correct");
        });
        if (!li.hasAttribute("data-correct")) li.classList.add("wrong");

        if (hint) hint.style.display = "none";
        if (feedback) {
          feedback.classList.add("show");
          var verdict = document.createElement("span");
          verdict.className = "score";
          verdict.textContent = li.hasAttribute("data-correct") ? "答对了。" : "再想一次：";
          feedback.insertBefore(verdict, feedback.firstChild);
        }
        root.dispatchEvent(new CustomEvent("quiz:answered", {
          bubbles: true,
          detail: { correct: li.hasAttribute("data-correct"), index: i }
        }));
      }

      li.addEventListener("click", choose);
      li.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choose(); }
      });
    });
  }

  function initAll() {
    document.querySelectorAll("[data-quiz]").forEach(initQuiz);

    // 未运行 JS 时 details 默认展开，运行后收紧为检索练习
    document.querySelectorAll(".recall details[open]").forEach(function (d) {
      d.removeAttribute("open");
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAll);
  } else {
    initAll();
  }
})();
