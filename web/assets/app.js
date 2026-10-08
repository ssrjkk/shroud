/* ==========================================================================
   Shroud — site behaviour
   --------------------------------------------------------------------------
   Dependency-free on purpose. A protocol site should not ship a framework to
   render text it already has, and a visitor must be able to read the honest
   security table with JavaScript disabled.

   Everything here is progressive enhancement and degrades to a still image.
   ========================================================================== */

(function () {
  "use strict";

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------------------------
     The background: the peer mesh.

     An earlier version of this file drew "ciphertext rain" — columns of hex
     characters. It looked like noise rather than like anything on-theme: a
     screen-wide canvas got roughly one glyph per column, so the result read as
     scattered specks, and it said nothing about the system.

     This is a graph of the peer mesh instead, which is what the protocol
     actually is: nodes holding shares, edges carrying shards. It also follows
     the diagram's colour rule — cyan where a node is working under the network
     key, violet where a payload is still sealed — so the background and the
     pipeline diagram use one visual language instead of two.
     ------------------------------------------------------------------------ */

  function initField() {
    var canvas = document.getElementById("mesh");
    if (!canvas) return;

    var ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    var CYAN = "52,224,200";
    var VIOLET = "139,92,246";

    var NODE_COUNT = 46;   // tuned by eye against a 1440px viewport
    var LINK_DIST = 210;   // connect nodes closer than this
    var FONT = 12;

    var nodes = [];
    var pulses = [];
    var w = 0;
    var h = 0;
    var dpr = 1;
    var running = false;

    /** Jittered grid rather than pure random: random leaves clumps and holes,
     *  which reads as noise. Jitter keeps it even but not mechanical. */
    function layout() {
      var cols = Math.max(3, Math.round(Math.sqrt(NODE_COUNT * (w / Math.max(h, 1)))));
      var rows = Math.max(3, Math.ceil(NODE_COUNT / cols));
      nodes = [];
      for (var r = 0; r < rows; r++) {
        for (var c = 0; c < cols; c++) {
          if (nodes.length >= NODE_COUNT) break;
          var cx = ((c + 0.5) / cols) * w;
          var cy = ((r + 0.5) / rows) * h;
          nodes.push({
            x: cx + (Math.random() - 0.5) * (w / cols) * 0.8,
            y: cy + (Math.random() - 0.5) * (h / rows) * 0.8,
            r: 0.9 + Math.random() * 1.7,
            // ~1 node in 6 is violet: a shard that is still sealed.
            violet: Math.random() < 0.17,
            // Slow, directionless drift. Nodes never leave the viewport, so the
            // field cannot thin out over time.
            vx: (Math.random() - 0.5) * 0.055,
            vy: (Math.random() - 0.5) * 0.055
          });
        }
      }
      pulses = [];
      for (var i = 0; i < 7; i++) pulses.push(newPulse(true));
    }

    function newPulse(anywhere) {
      return {
        // A pulse starts on a random edge and walks to the far end, then is
        // retired. `t` is 0..1 along the edge.
        from: Math.floor(Math.random() * nodes.length),
        t: anywhere ? Math.random() : 0,
        speed: 0.0012 + Math.random() * 0.0022,
        violet: Math.random() < 0.3
      };
    }

    function measure() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = w + "px";
      canvas.style.height = h + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    /** Recompute edges. O(n²) over ~46 nodes is ~1000 comparisons, which is
     *  far cheaper than maintaining an incremental neighbour list, and it only
     *  runs when the drift moves a node a meaningful distance. */
    function edges() {
      var out = [];
      for (var i = 0; i < nodes.length; i++) {
        for (var j = i + 1; j < nodes.length; j++) {
          var dx = nodes[j].x - nodes[i].x;
          var dy = nodes[j].y - nodes[i].y;
          var d2 = dx * dx + dy * dy;
          if (d2 < LINK_DIST * LINK_DIST) out.push([i, j, d2]);
        }
      }
      return out;
    }

    function paint() {
      // Not a fade-to-dark fill: the mesh is redrawn over a fully cleared
      // canvas so node positions stay exact. Glyph rain needed an accumulating
      // trail buffer; a graph does not, and rebuilding it each frame keeps the
      // two halves of the file from disagreeing about how the canvas works.
      ctx.clearRect(0, 0, w, h);

      var link = edges();
      var maxD2 = LINK_DIST * LINK_DIST;

      // Edges first, so nodes sit on top of them.
      for (var e = 0; e < link.length; e++) {
        var a = nodes[link[e][0]];
        var b = nodes[link[e][1]];
        // Fade with distance: a near link is a direct handover, a far one is
        // barely worth drawing.
        var t = 1 - link[e][2] / maxD2;
        ctx.strokeStyle = "rgba(" + CYAN + "," + (0.055 + t * 0.1).toFixed(3) + ")";
        ctx.lineWidth = 0.6 + t * 0.7;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }

      // Pulses: the reason the background is a *mesh* and not a decoration.
      for (var p = 0; p < pulses.length; p++) {
        var pu = pulses[p];
        var n0 = nodes[pu.from];
        if (!n0) continue;
        // Recompute the destination each frame from proximity, so a pulse stays
        // glued to real geometry while everything drifts.
        var target = null;
        var best = LINK_DIST * LINK_DIST;
        for (var q = 0; q < nodes.length; q++) {
          if (q === pu.from) continue;
          var ddx = nodes[q].x - n0.x;
          var ddy = nodes[q].y - n0.y;
          var dd2 = ddx * ddx + ddy * ddy;
          if (dd2 < best) {
            best = dd2;
            target = nodes[q];
          }
        }
        if (!target) {
          pulses[p] = newPulse(true);
          continue;
        }
        var col = pu.violet ? VIOLET : CYAN;
        var px = n0.x + (target.x - n0.x) * pu.t;
        var py = n0.y + (target.y - n0.y) * pu.t;
        // A short comet tail behind the head, so a pulse reads as direction.
        var tailT = Math.max(0, pu.t - 0.09);
        var tx = n0.x + (target.x - n0.x) * tailT;
        var ty = n0.y + (target.y - n0.y) * tailT;
        var grad = ctx.createLinearGradient(tx, ty, px, py);
        grad.addColorStop(0, "rgba(" + col + ",0)");
        grad.addColorStop(1, "rgba(" + col + ",0.75)");
        ctx.strokeStyle = grad;
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        ctx.moveTo(tx, ty);
        ctx.lineTo(px, py);
        ctx.stroke();

        pu.t += pu.speed;
        if (pu.t >= 1) pulses[p] = newPulse(false);
      }

      // Nodes last.
      for (var n = 0; n < nodes.length; n++) {
        var nd = nodes[n];
        var nc = nd.violet ? VIOLET : CYAN;
        ctx.fillStyle = "rgba(" + nc + ",0.5)";
        ctx.beginPath();
        ctx.arc(nd.x, nd.y, nd.r, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "rgba(" + nc + ",0.16)";
        ctx.beginPath();
        ctx.arc(nd.x, nd.y, nd.r + 3.4, 0, Math.PI * 2);
        ctx.fill();
      }

      ctx.font = FONT + "px ui-monospace, Menlo, Consolas, monospace";
      ctx.textBaseline = "top";
    }

    function drift() {
      for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;
        // Reflect at the edges. Wrapping would let a node leave and reappear on
        // the far side, which is visible as a pop.
        if (n.x < 0) { n.x = 0; n.vx = Math.abs(n.vx); }
        if (n.x > w) { n.x = w; n.vx = -Math.abs(n.vx); }
        if (n.y < 0) { n.y = 0; n.vy = Math.abs(n.vy); }
        if (n.y > h) { n.y = h; n.vy = -Math.abs(n.vy); }
      }
    }

    function frame() {
      drift();
      paint();
      requestAnimationFrame(frame);
    }

    measure();
    layout();

    // Draw one frame immediately. A canvas that has never been painted is a
    // blank rectangle, and this is the frame a screenshot, a print, or a
    // reduced-motion visitor sees — it must not be the empty one.
    paint();

    if (!reduceMotion) {
      running = true;
      requestAnimationFrame(frame);
    }

    var resizeTimer = null;
    window.addEventListener(
      "resize",
      function () {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function () {
          measure();
          layout();
          // While paused, repaint once so the resize is reflected instead of
          // leaving a stale frame stretched.
          if (!running) paint();
        }, 180);
      },
      { passive: true }
    );

    // Dim rather than remove once the reader engages: the page keeps its
    // character but stops competing with the text.
    var engaged = false;
    function onScroll() {
      if (engaged) return;
      engaged = true;
      canvas.style.transition = "opacity 700ms ease";
      canvas.style.opacity = "0.3";
    }
    window.addEventListener("scroll", onScroll, { passive: true });
  }

  /* ------------------------------------------------------------------------
     Reveal on scroll. One IntersectionObserver for the whole page, skipped
     entirely under reduced motion, with a hard timeout so content can never be
     left invisible if the observer misbehaves.
     ------------------------------------------------------------------------ */

  function initReveal() {
    if (reduceMotion) return;

    var targets = document.querySelectorAll(".card, .props li, .flow, .row, .tally-item");
    if (!targets.length || typeof IntersectionObserver === "undefined") return;

    targets.forEach(function (el, i) {
      el.style.opacity = "0";
      el.style.transform = "translateY(10px)";
      var delay = Math.min(i % 6, 5) * 55;
      el.style.transition = "opacity 520ms ease " + delay + "ms, transform 520ms ease " + delay + "ms";
    });

    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.style.opacity = "1";
          entry.target.style.transform = "none";
          io.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -6% 0px", threshold: 0.05 }
    );

    targets.forEach(function (el) {
      io.observe(el);
    });

    window.setTimeout(function () {
      targets.forEach(function (el) {
        if (el.style.opacity === "0") {
          el.style.opacity = "1";
          el.style.transform = "none";
        }
      });
    }, 2500);
  }

  /* ------------------------------------------------------------------------
     Copy short hashes/addresses. A real <button>, so it is keyboard reachable.
     ------------------------------------------------------------------------ */

  function initCopy() {
    document.querySelectorAll("[data-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var text = btn.getAttribute("data-copy") || "";
        var done = function () {
          var prev = btn.textContent;
          btn.textContent = "copied";
          btn.classList.add("copied");
          setTimeout(function () {
            btn.textContent = prev;
            btn.classList.remove("copied");
          }, 1200);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () {});
        }
      });
    });
  }

  function boot() {
    initField();
    initReveal();
    initCopy();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();