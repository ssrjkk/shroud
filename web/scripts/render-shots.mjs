/**
 * Re-render the README screenshots (`docs/shots/*.png`) from the current `web/`.
 *
 * The shots are checked into git and embedded in README.md, but no tool in the
 * repo produces them: they are viewport screenshots of the static site, and the
 * last render is recorded only by `git log -- docs/shots/`. Run this after any
 * change that moves pixels on the shot pages (copy, layout, theme, breakpoints)
 * so the README keeps showing the site as it is.
 *
 * Usage (needs a one-time browser download, nothing is added to the repo):
 *
 *   npm install -g playwright   # or: npx -y playwright install chromium
 *   npx -y playwright install chromium --only-shell
 *   node web/scripts/render-shots.mjs
 *
 * Deterministic by construction: RU locale, ink theme, newcomer mode, no
 * network (the site is fully static), fixed viewports. If a shot diffs after
 * a change that was supposed to be invisible, the change was not invisible.
 */
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const WEB = resolve(here, "..");
const OUT = resolve(here, "..", "..", "docs", "shots");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".json": "application/json",
};

function serve() {
  return new Promise((done) => {
    const srv = createServer((req, res) => {
      try {
        let path = decodeURIComponent(new URL(req.url, "http://x").pathname);
        if (path.endsWith("/")) path += "index.html";
        const data = readFileSync(join(WEB, path));
        res.writeHead(200, { "content-type": MIME[extname(path)] ?? "application/octet-stream" });
        res.end(data);
      } catch {
        res.writeHead(404);
        res.end("nope");
      }
    });
    srv.listen(0, "127.0.0.1", () => done(srv));
  });
}

/** Fresh-profile defaults the shots pin: RU, ink, newcomer. */
const INIT = `
try {
  localStorage.setItem("shroud-theme", "ink");
  localStorage.setItem("shroud-lang", "ru");
  localStorage.setItem("shroud-mode", "new");
} catch (e) {}
`;

const SHOTS = [
  { page: "index.html", file: "home.png", width: 1440, height: 900, mobile: false },
  { page: "playground.html", file: "lab.png", width: 1440, height: 900, mobile: false },
  { page: "protocol.html", file: "protocol.png", width: 1440, height: 900, mobile: false },
  { page: "index.html", file: "mobile.png", width: 390, height: 844, mobile: true },
];

let chromium;
const errors = [];
try {
  ({ chromium } = await import("playwright"));
} catch (e) {
  errors.push(String(e));
  // ESM `import()` ignores NODE_PATH and refuses directory imports, but CJS
  // `require()` resolves a package directory fine — use it for the override.
  if (process.env.PLAYWRIGHT_DIR) {
    const { createRequire } = await import("node:module");
    const req = createRequire(join(process.env.PLAYWRIGHT_DIR, "package.json"));
    ({ chromium } = req(process.env.PLAYWRIGHT_DIR));
  } else {
    console.error("render-shots: playwright is not installed. Either run");
    console.error("`npm install -g playwright`, or set PLAYWRIGHT_DIR to the package");
    console.error("directory (it is enough to `npm install playwright-core` in a scratch");
    console.error("dir — no browser download needed when one already exists), and");
    console.error("`npx -y playwright install chromium --only-shell`, then re-run this script.");
    process.exit(2);
  }
}

const srv = await serve();
const port = srv.address().port;
const browser = await chromium.launch();
try {
  for (const s of SHOTS) {
    const ctx = await browser.newContext({
      viewport: { width: s.width, height: s.height },
      deviceScaleFactor: 1,
      isMobile: s.mobile,
      hasTouch: s.mobile,
    });
    await ctx.addInitScript(INIT);
    const pg = await ctx.newPage();
    await pg.goto(`http://127.0.0.1:${port}/${s.page}`, { waitUntil: "networkidle" });
    // Below-fold sections render on intersection: walk the page top to bottom
    // first, otherwise a fullPage capture stitches empty bodies under the headers.
    await pg.evaluate(async () => {
      const h = () => document.documentElement.scrollHeight;
      for (let y = 0; y < h(); y += 600) {
        window.scrollTo(0, y);
        await new Promise((r) => setTimeout(r, 60));
      }
      window.scrollTo(0, h());
      await new Promise((r) => setTimeout(r, 200));
    });
    await pg.waitForTimeout(300);
    await pg.screenshot({ path: join(OUT, s.file), fullPage: true });
    console.log(`wrote docs/shots/${s.file}`);
    await ctx.close();
  }
} finally {
  await browser.close();
  srv.close();
}
