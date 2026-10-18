/* Shroud — меню, тема, язык, копирование, появление блоков. Без фреймворков. */
(function () {
  "use strict";
  var THEME_KEY = "shroud-theme";
  function systemTheme() {
    try {
      if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) return "paper";
    } catch (e) {}
    return "ink";
  }
  function getTheme() {
    try {
      var t = localStorage.getItem(THEME_KEY);
      if (t === "paper" || t === "ink") return t;
    } catch (e) {}
    return systemTheme();
  }
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    document.querySelectorAll("[data-theme-btn]").forEach(function (b) {
      b.classList.toggle("on", b.getAttribute("data-theme-btn") === theme);
      b.setAttribute("aria-pressed", b.getAttribute("data-theme-btn") === theme ? "true" : "false");
    });
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.setAttribute("aria-pressed", theme === "paper" ? "true" : "false");
    });
    try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
  }
  var MODE_KEY = "shroud-mode";
  function applyMode(mode) {
    if (mode !== "pro" && mode !== "new") mode = "new";
    document.documentElement.setAttribute("data-mode", mode);
    document.querySelectorAll("[data-mode-btn]").forEach(function (b) {
      var on = b.getAttribute("data-mode-btn") === mode;
      b.classList.toggle("on", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    try { localStorage.setItem(MODE_KEY, mode); } catch (e) {}
  }
  function ready(fn) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn);
    else fn();
  }
  function tr(k) {
    try { if (window.I18N) return window.I18N.t(k); } catch (e) {}
    return k;
  }
  ready(function () {
    applyTheme(document.documentElement.getAttribute("data-theme") || getTheme());
    var modeNow = "new";
    try {
      var m = localStorage.getItem(MODE_KEY);
      if (m === "pro" || m === "new") modeNow = m;
    } catch (e) {}
    applyMode(document.documentElement.getAttribute("data-mode") || modeNow);
    document.querySelectorAll("[data-mode-btn]").forEach(function (b) {
      b.addEventListener("click", function () { applyMode(b.getAttribute("data-mode-btn")); });
    });
    document.querySelectorAll("[data-theme-btn]").forEach(function (b) {
      b.addEventListener("click", function () { applyTheme(b.getAttribute("data-theme-btn")); });
    });
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.addEventListener("click", function () {
        var cur = document.documentElement.getAttribute("data-theme") === "paper" ? "paper" : "ink";
        applyTheme(cur === "paper" ? "ink" : "paper");
      });
    });
    document.querySelectorAll("[data-lang]").forEach(function (b) {
      b.addEventListener("click", function () {
        if (window.I18N) window.I18N.setLang(b.getAttribute("data-lang"));
      });
    });
    var burger = document.querySelector("[data-burger]");
    var nav = document.querySelector("[data-nav]");
    function syncBurger() {
      if (!burger) return;
      var open = nav && nav.classList.contains("open");
      burger.textContent = open ? tr("close") : tr("menu");
    }
    if (burger && nav) {
      burger.addEventListener("click", function () {
        nav.classList.toggle("open");
        syncBurger();
      });
      document.addEventListener("shroud:lang", syncBurger);
    }
    syncBurger();
    Array.prototype.forEach.call(document.querySelectorAll("pre.code"), function (pre) {
      var wrap = document.createElement("div");
      wrap.className = "prewrap";
      if (pre.parentNode) pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      var cbtn = document.createElement("button");
      cbtn.className = "copybtn";
      cbtn.type = "button";
      cbtn.textContent = tr("ui.copy");
      cbtn.setAttribute("data-copied", tr("ui.copied"));
      cbtn.setAttribute("data-copy", pre.textContent);
      wrap.appendChild(cbtn);
    });
    document.querySelectorAll("[data-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var text = btn.getAttribute("data-copy") || "";
        var label = btn.getAttribute("data-copied") || "OK";
        function done() {
          var prev = btn.textContent;
          btn.textContent = label;
          setTimeout(function () { btn.textContent = prev; }, 1200);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () {});
        } else {
          var ta = document.createElement("textarea");
          ta.value = text; document.body.appendChild(ta); ta.select();
          try { document.execCommand("copy"); done(); } catch (e) {}
          document.body.removeChild(ta);
        }
      });
    });
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var targets = document.querySelectorAll(".rv");
    if (!reduce && targets.length && "IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (en.isIntersecting) { en.target.classList.add("on"); io.unobserve(en.target); }
        });
      }, { threshold: 0.06 });
      targets.forEach(function (el) { io.observe(el); });
      setTimeout(function () {
        targets.forEach(function (el) { el.classList.add("on"); });
      }, 2600);
    } else {
      targets.forEach(function (el) { el.classList.add("on"); });
    }

    // --- живое chrome: оглавление, прогресс, «наверх», наблюдатели ---
    var visibleSections = function () {
      return Array.prototype.slice.call(document.querySelectorAll("main > section.sect"))
        .filter(function (s) { return s.offsetParent !== null; });
    };
    var tocEl = null, tocLinks = [], spyObs = null;
    function placeToc() {
      if (!tocEl) return;
      var m = document.querySelector(".masthead");
      tocEl.style.top = ((m ? m.offsetHeight : 58) + 6) + "px";
    }
    function spy() {
      if (!tocLinks.length || !("IntersectionObserver" in window)) return;
      if (!spyObs) {
        spyObs = new IntersectionObserver(function (entries) {
          entries.forEach(function (en) {
            tocLinks.forEach(function (l) { if (l.s === en.target) l.a.classList.toggle("on", en.isIntersecting); });
          });
        }, { rootMargin: "-18% 0px -72% 0px" });
      }
      tocLinks.forEach(function (l) { spyObs.observe(l.s); });
    }
    function buildToc() {
      var secs = visibleSections();
      if (secs.length < 2) { if (tocEl && tocEl.parentNode) tocEl.parentNode.removeChild(tocEl); tocEl = null; tocLinks = []; return; }
      if (!tocEl) {
        tocEl = document.createElement("nav");
        tocEl.className = "toc";
        tocEl.setAttribute("aria-label", tr("ui.toc"));
        document.body.appendChild(tocEl);
        placeToc();
      }
      tocEl.innerHTML = "";
      tocLinks = [];
      secs.forEach(function (sec, i) {
        var head = sec.querySelector(".sect-head");
        if (!head) return;
        if (!sec.id) sec.id = "sec-" + (i + 1);
        var num = head.querySelector(".sect-num"), title = head.querySelector(".sect-title");
        var a = document.createElement("a");
        a.href = "#" + sec.id;
        a.textContent = num ? num.textContent : (title ? title.textContent : "");
        if (title) a.title = title.textContent;
        tocEl.appendChild(a);
        tocLinks.push({ a: a, s: sec });
      });
      if (spyObs) spyObs.disconnect();
      spy();
    }
    buildToc();

    // проявление заголовков секций и «текущих» стрелок схемы
    var seen = document.querySelectorAll(".sect-head, .scheme");
    if (!reduce && seen.length && "IntersectionObserver" in window) {
      var io2 = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (en.isIntersecting) { en.target.classList.add("onshown"); io2.unobserve(en.target); }
        });
      }, { threshold: 0.15 });
      Array.prototype.forEach.call(seen, function (el) { io2.observe(el); });
    } else {
      Array.prototype.forEach.call(seen, function (el) { el.classList.add("onshown"); });
    }

    // бегущая строка: дублируем содержимое для бесшовного цикла
    var tick = document.querySelector(".ticker-in");
    if (tick && !reduce && tick.children.length) {
      tick.innerHTML += tick.innerHTML;
      tick.style.animation = "shroudTicker 38s linear infinite";
    }

    // прогресс прокрутки + кнопка «наверх»
    var bar = document.createElement("div");
    bar.className = "progress";
    bar.setAttribute("aria-hidden", "true");
    bar.appendChild(document.createElement("i"));
    document.body.appendChild(bar);
    var fill = bar.firstChild;
    var toTop = document.createElement("button");
    toTop.className = "iconbtn totop";
    toTop.type = "button";
    toTop.textContent = "↑";
    toTop.title = tr("ui.top");
    toTop.setAttribute("aria-label", tr("ui.top"));
    toTop.addEventListener("click", function () {
      if (window.scrollTo) window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
    });
    document.body.appendChild(toTop);
    function onScroll() {
      var y = window.pageYOffset || document.documentElement.scrollTop;
      var max = document.documentElement.scrollHeight - window.innerHeight;
      fill.style.transform = "scaleX(" + (max > 0 ? Math.min(1, Math.max(0, y / max)) : 0) + ")";
      toTop.classList.toggle("show", y > 600);
    }
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", function () { onScroll(); placeToc(); });
    onScroll();

    // перевод и смена режима меняют подписи — обновляем
    document.addEventListener("shroud:lang", function () {
      buildToc();
      Array.prototype.forEach.call(document.querySelectorAll(".prewrap"), function (w) {
        var b = w.querySelector(".copybtn"), p = w.querySelector("pre");
        if (!b || !p) return;
        b.textContent = tr("ui.copy");
        b.setAttribute("data-copied", tr("ui.copied"));
        b.setAttribute("data-copy", p.textContent);
      });
      if (tocEl) tocEl.setAttribute("aria-label", tr("ui.toc"));
      toTop.title = tr("ui.top");
      toTop.setAttribute("aria-label", tr("ui.top"));
      onScroll();
    });
    document.querySelectorAll("[data-mode-btn]").forEach(function (b) {
      b.addEventListener("click", buildToc);
    });
  });
})();
