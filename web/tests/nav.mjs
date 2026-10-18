// web/tests/nav.mjs — целостность навигации многостраничного сайта.
//
// Сайт статический и без сборки: меню, футер и подсветка активного пункта
// скопированы в каждый HTML. С семью страницами главный источник регрессии —
// разъехавшиеся копии: пункт есть на одной странице и забыт на другой.
//
// Что проверяет:
//   1. Полный набор страниц: любая новая web/*.html обязана попасть в меню
//      (404.html — служебная, в меню её нет, но она должна существовать).
//   2. Меню одинаково на всех страницах, один и тот же порядок.
//   3. Ровно один class="active" на страницу, он указывает на неё же и несёт
//      aria-current="page" — иначе скринридер текущую страницу не объявляет.
//   4. Все внутристраничные якоря (#id) существуют в своём документе.
//   5. Каждая страница достижима с главной по обычным ссылкам.
//   6. Переключатель режима new/pro есть ровно на тех страницах, где есть
//      блоки only-new / only-pro — иначе он либо недостижим, либо мёртв.
//
// Запуск из корня репозитория:  node web/tests/nav.mjs
// Зависимостей нет.
import { readFileSync, readdirSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(HERE, "..");

let fails = 0;
const fail = (m) => { fails++; console.log("FAIL:", m); };

const read = (name) => readFileSync(path.join(WEB, name), "utf8");
const pages = readdirSync(WEB).filter((n) => n.endsWith(".html")).sort();
if (!pages.includes("index.html")) {
  console.log("FAIL: нет web/index.html");
  process.exit(1);
}
const SERVICE = new Set(["404.html"]);
const inMenu = pages.filter((p) => !SERVICE.has(p));
const html = {};
for (const p of pages) html[p] = read(p);

// --- 1. набор страниц --------------------------------------------------------
const navOf = (p) => {
  const block = html[p].match(/<nav class="nav" data-nav>([\s\S]*?)<\/nav>/);
  if (!block) return null;
  return [...block[1].matchAll(/href="\.\/([^"#]+\.html)"/g)].map((m) => m[1]);
};
const reference = navOf("index.html");
if (!reference) {
  console.log("FAIL: в index.html нет блока <nav class=\"nav\" data-nav>");
  process.exit(1);
}
const missingFromNav = inMenu.filter((p) => !reference.includes(p));
const ghostInNav = reference.filter((p) => !pages.includes(p));
for (const p of missingFromNav) fail(`${p}: страница есть, но её нет в меню index.html`);
for (const p of ghostInNav) fail(`меню ссылается на ${p}, файла нет`);
if (!missingFromNav.length && !ghostInNav.length) {
  console.log(`1. набор страниц совпадает: ${inMenu.length} в меню + ${[...SERVICE].filter((p) => pages.includes(p)).join(", ")}`);
}

// --- 2. одинаковое меню ------------------------------------------------------
let menuOk = true;
for (const p of inMenu) {
  const nav = navOf(p);
  if (!nav) { fail(`${p}: нет блока меню`); menuOk = false; continue; }
  if (nav.join(" ") !== reference.join(" ")) {
    fail(`${p}: меню отличается — ${nav.join(" ")} вместо ${reference.join(" ")}`);
    menuOk = false;
  }
}
if (menuOk) console.log(`2. меню совпадает на ${inMenu.length} страницах: ${reference.join(" · ")}`);

// --- 3. ровно один активный пункт, и он про эту страницу --------------------
// Скринридер объявляет текущую страницу только через aria-current: без него
// класс active виден глазами, но молчит в доступности.
for (const p of inMenu) {
  const block = html[p].match(/<nav class="nav" data-nav>([\s\S]*?)<\/nav>/)[1];
  const active = [...block.matchAll(/<a href="\.\/([^"#]+\.html)"[^>]*class="active"/g)].map((m) => m[1]);
  if (active.length !== 1) fail(`${p}: активных пунктов ${active.length} (${active.join(", ") || "нет"}), ожидался 1`);
  else if (active[0] !== p) fail(`${p}: активен ${active[0]}, а страница — ${p}`);
  const withCurrent = [...block.matchAll(/<a href="\.\/([^"#]+\.html)"[^>]*aria-current="page"/g)].map((m) => m[1]);
  if (withCurrent.length !== 1) fail(`${p}: aria-current="page" стоит на ${withCurrent.length} ссылках (${withCurrent.join(", ") || "нет"})`);
  else if (withCurrent[0] !== p) fail(`${p}: aria-current="page" на ${withCurrent[0]}, а страница — ${p}`);
}
console.log(`3. активный пункт ровно один, совпадает со страницей и несёт aria-current (${inMenu.length} проверено)`);

// --- 4. внутристраничные якоря ----------------------------------------------
let anchors = 0;
for (const p of pages) {
  for (const m of html[p].matchAll(/href="#([^"]+)"/g)) {
    anchors++;
    if (!html[p].includes(`id="${m[1]}"`)) fail(`${p}: якорь #${m[1]} не существует`);
  }
  const mainId = /<main id="([^"]+)"/.exec(html[p]);
  if (mainId && !html[p].includes(`href="#${mainId[1]}"`)) fail(`${p}: нет skip-ссылки на #${mainId[1]}`);
}
console.log(`4. внутристраничные якоря живы (${anchors} шт.)`);

// --- 5. достижимость с главной ----------------------------------------------
const reach = new Set(["index.html"]);
const queue = ["index.html"];
while (queue.length) {
  const cur = queue.shift();
  for (const m of html[cur].matchAll(/href="\.\/([^"#]+\.html)/g)) {
    if (!reach.has(m[1])) { reach.add(m[1]); queue.push(m[1]); }
  }
}
const unreachable = inMenu.filter((p) => !reach.has(p));
for (const p of unreachable) fail(`${p}: недостижима с главной`);
if (!unreachable.length) console.log(`5. все ${inMenu.length} страниц достижимы с главной`);

// --- 6. режим чтения: переключатель там, где он что-то переключает ----------
// Контент, помеченный only-new / only-pro, виден только в одном режиме.
// Если такой блок есть, а кнопки режима на странице нет — переключиться
// нечем, и блок просто недостижим (так было на 5 страницах до этого теста).
// Обратное тоже ошибка: кнопка, которая ничего не переключает.
for (const p of pages) {
  const gated = /class="[^"]*\b(only-new|only-pro)\b/.test(html[p]);
  const ctl = /data-mode-btn/.test(html[p]);
  if (gated && !ctl) fail(`${p}: есть блоки only-new/only-pro, но нет переключателя режима`);
  if (!gated && ctl) fail(`${p}: переключатель режима есть, а блоков only-new/only-pro нет — кнопка ничего не делает`);
}
console.log(`6. режим чтения: кнопка есть ровно там, где есть переключаемый контент`);

console.log(fails === 0 ? "NAV OK" : `fails=${fails}`);
process.exit(fails ? 1 : 0);
