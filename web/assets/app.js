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
  });
})();
