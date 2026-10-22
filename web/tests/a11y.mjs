// web/tests/a11y.mjs — доступность статического сайта без браузера.
//
// axe-core (через Lighthouse) нашёл на сайте то, чего не видно на скриншоте:
// заголовки прыгали с h1 на h5 в футере, страницы кроме главной вообще не
// имели h1, а поля лаборатории стояли рядом с label, но не были с ними
// связаны. Этот гейт фиксирует ровно те правила, чтобы они не вернулись.
//
// Что проверяет:
//   1. Ровно один h1, и он — первый заголовок документа. Иначе у страницы нет
//      имени, по которому скринридер строит оглавление.
//   2. Уровни не прыгают вниз (h1 → h3). Пропуск читается как отсутствующий
//      раздел: «заголовок 3 уровня» там, где не было второго.
//   3. У каждого поля есть доступное имя: label[for], aria-label,
//      aria-labelledby или объемлющий label. Иначе диктор говорит «поле
//      ввода» и просит угадать, какое.
//   4. У каждой картинки есть alt. Пустой alt — тоже ответ: картинка
//      декоративная, и её нужно пропустить.
//   5. У каждой ссылки и кнопки есть текст или aria-label/labelledby.
//   6. У <html> есть lang — без него диктор читает русский текст английской
//      фонетикой.
//
// Чего не проверяет: контент, который рисует JS (журнал playground.js,
// подписи к графикам) — для этого нужен настоящий DOM. Если добавляешь
// заголовки в JS, держи их уровень сразу под h1.
//
// Запуск из корня репозитория:  node web/tests/a11y.mjs
// Зависимостей нет.
import { readFileSync, readdirSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(HERE, "..");

let fails = 0;
const fail = (m) => {
  fails++;
  console.log("FAIL:", m);
};

const pages = readdirSync(WEB)
  .filter((n) => n.endsWith(".html"))
  .sort();
if (!pages.length) {
  console.log("FAIL: в web/ нет ни одной страницы");
  process.exit(1);
}

const read = (name) => readFileSync(path.join(WEB, name), "utf8");
// Заголовки в комментариях и в скриптах — не заголовки документа.
const visible = (html) =>
  html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script\b[\s\S]*?<\/script>/gi, "")
    .replace(/<style\b[\s\S]*?<\/style>/gi, "");

for (const p of pages) {
  const raw = read(p);
  const html = visible(raw);

  // --- 1. один h1, и он первый ---------------------------------------------
  const headings = [...html.matchAll(/<h([1-6])\b/g)].map((m) => Number(m[1]));
  const h1s = headings.filter((h) => h === 1).length;
  if (h1s !== 1) fail(`${p}: заголовков h1 — ${h1s}, ожидался ровно один`);
  else if (headings[0] !== 1) fail(`${p}: первый заголовок h${headings[0]}, а не h1`);

  // --- 2. уровни не прыгают вниз -------------------------------------------
  let prev = 0;
  for (const h of headings) {
    if (prev && h > prev + 1) fail(`${p}: заголовок h${h} сразу после h${prev}`);
    prev = h;
  }

  // --- 3. доступные имена полей -------------------------------------------
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
  const forIds = new Set([...html.matchAll(/<label\b[^>]*\bfor="([^"]+)"/g)].map((m) => m[1]));
  const labelRanges = [...html.matchAll(/<label\b[^>]*>[\s\S]*?<\/label>/g)].map((m) => [m.index, m.index + m[0].length]);
  // Кнопки отправки и скрытые поля не нуждаются в подписи.
  const NAMELESS = new Set(["hidden", "submit", "button", "reset", "image"]);
  const controls = [...html.matchAll(/<(input|select|textarea)\b([^>]*)>/g)];
  let named = 0;
  let labelable = 0;
  for (const m of controls) {
    const attrs = m[2];
    const type = (/type="([^"]+)"/.exec(attrs) || [])[1];
    if (NAMELESS.has(type)) continue;
    labelable++;
    const id = (/id="([^"]+)"/.exec(attrs) || [])[1];
    const ariaLabel = (/aria-label="([^"]*)"/.exec(attrs) || [])[1];
    const labelledBy = (/aria-labelledby="([^"]*)"/.exec(attrs) || [])[1];
    const inside = labelRanges.some(([a, b]) => m.index > a && m.index < b);
    const byId = id && forIds.has(id);
    const byRef = labelledBy && labelledBy.split(/\s+/).every((ref) => ids.has(ref));
    if (ariaLabel || byRef || byId || inside) named++;
    else fail(`${p}: поле ${id ? "#" + id : m[1]} без доступного имени`);
  }

  // --- 4. alt у картинок ----------------------------------------------------
  for (const m of html.matchAll(/<img\b([^>]*)>/g)) {
    if (!/\balt=/.test(m[1])) fail(`${p}: <img> без alt: ${m[0].slice(0, 60)}`);
  }

  // --- 5. имена ссылок и кнопок --------------------------------------------
  // Текстом считается и alt вложенной картинки, и <title> внутри svg.
  const hasName = (attrs, body) =>
    /aria-label="[^"]+"/.test(attrs) ||
    /aria-labelledby="[^"]+"/.test(attrs) ||
    body.replace(/<[^>]*>/g, "").trim().length > 0 ||
    /<title\b[^>]*>[^<]+<\/title>/.test(body) ||
    /<img\b[^>]*\balt="[^"]+"/.test(body);
  for (const m of html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/g)) {
    if (!hasName(m[1], m[2])) fail(`${p}: ссылка без текста: ${m[0].slice(0, 60)}`);
  }
  for (const m of html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)) {
    if (!hasName(m[1], m[2])) fail(`${p}: кнопка без подписи: ${m[0].slice(0, 60)}`);
  }

  // --- 6. язык документа ----------------------------------------------------
  if (!/<html\b[^>]*\blang="[a-z]{2,}/i.test(raw)) fail(`${p}: у <html> нет lang`);

  console.log(`${p}: h1 на месте, уровни без пропусков, полей с именем ${named}/${labelable}, alt и подписи на месте`);
}

console.log(fails === 0 ? "A11Y OK" : `fails=${fails}`);
process.exit(fails ? 1 : 0);
