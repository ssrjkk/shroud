// web/tests/i18n.mjs — целостность словаря перевода сайта.
//
// Что проверяет:
//   1. Симметрия ru/en: множества ключей DICT совпадают. Забытая копия
//      в en молча отдаёт русский текст (см. t() в assets/i18n.js), а
//      отсутствующий в обоих — сырой ключ прямо в вёрстке.
//   2. Покрытие разметки: каждый ключ из data-i18n / -html / -desc / -aria
//      в web/*.html есть и в ru, и в en.
//   3. Мёртвые ключи: в словаре есть то, что не читается ни разметкой, ни JS.
//      Забытый после переноса текст — это либо сырой ключ на странице, либо
//      мёртвый вес в i18n.js.
//
// Запуск из корня репозитория:  node web/tests/i18n.mjs
// Зависимостей нет. DICT достаётся без правки исходника: выполняем файл в
// vm-контексте и подставляем экспорт перед последней строкой.
import { readFileSync, readdirSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";
import vm from "vm";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(HERE, "..");

let fails = 0;
const fail = (m) => { fails++; console.log("FAIL:", m); };

// --- 1. достаём DICT ---------------------------------------------------------
const src = readFileSync(path.join(WEB, "assets", "i18n.js"), "utf8");
const patched = src.replace("window.I18N = {", "globalThis.__DICT = DICT;\n  window.I18N = {");
if (patched === src) {
  console.log("FAIL:", "не найдена точка экспорта window.I18N = { в assets/i18n.js");
  process.exit(1);
}
const sandbox = {
  window: {},
  document: { readyState: "loading", addEventListener() {}, documentElement: {} },
  localStorage: { getItem: () => null, setItem() {} },
  CustomEvent: class {},
  console,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(patched, sandbox, { filename: "i18n.js" });

const ru = sandbox.__DICT.ru || {};
const en = sandbox.__DICT.en || {};
const ruKeys = Object.keys(ru);
const enKeys = Object.keys(en);
const ruSet = new Set(ruKeys);
const enSet = new Set(enKeys);

// --- 2. симметрия ------------------------------------------------------------
const onlyRu = ruKeys.filter((k) => !enSet.has(k));
const onlyEn = enKeys.filter((k) => !ruSet.has(k));
if (onlyRu.length) fail(`ключи только в ru (${onlyRu.length}): ${onlyRu.slice(0, 12).join(", ")}`);
if (onlyEn.length) fail(`ключи только в en (${onlyEn.length}): ${onlyEn.slice(0, 12).join(", ")}`);
if (!onlyRu.length && !onlyEn.length) {
  console.log(`1. ru/en симметричны: ${ruKeys.length} ключей в каждом языке`);
}

// --- 3. покрытие разметки ----------------------------------------------------
const used = new Map(); // ключ -> [файлы]
for (const name of readdirSync(WEB).filter((n) => n.endsWith(".html"))) {
  const text = readFileSync(path.join(WEB, name), "utf8");
  for (const m of text.matchAll(/data-i18n(?:-html|-desc|-aria)?="([^"]+)"/g)) {
    if (!used.has(m[1])) used.set(m[1], new Set());
    used.get(m[1]).add(name);
  }
}
const files = (k) => [...used.get(k)].sort().join(",");
const missRu = [...used.keys()].filter((k) => !ruSet.has(k));
const missEn = [...used.keys()].filter((k) => !enSet.has(k));
for (const k of missRu) fail(`ключ ${k} (${files(k)}) есть в разметке, но нет в ru`);
for (const k of missEn) fail(`ключ ${k} (${files(k)}) есть в разметке, но нет в en`);
if (!missRu.length && !missEn.length) {
  console.log(`2. разметка покрыта: ${used.size} ключей из web/*.html есть в обоих словарях`);
}

// --- 4. мёртвые ключи: определены, но не используются ------------------------
// Ключи читаются не только из разметки, но и из JS: лаборатория собирает журнал
// и сообщения через t("lab.…"), а app.js — через tr("ui.…"). Сканируем оба.
const jsUsed = new Set();
const jsPrefixes = [];
for (const name of readdirSync(path.join(WEB, "assets")).filter((n) => n.endsWith(".js"))) {
  const text = readFileSync(path.join(WEB, "assets", name), "utf8");
  for (const m of text.matchAll(/\btr?\("([a-z][a-z0-9.]*)"/g)) {
    if (m[1].endsWith(".")) jsPrefixes.push(m[1]); // ключ собирается конкатенацией
    else jsUsed.add(m[1]);
  }
}
const referenced = (k) => used.has(k) || jsUsed.has(k) || jsPrefixes.some((p) => k.startsWith(p));
const dead = [...ruSet].filter((k) => !referenced(k));
if (dead.length) fail(`ключи есть в словаре, но нигде не используются (${dead.length}): ${dead.join(", ")}`);
else console.log(`3. мёртвых ключей нет (${jsUsed.size} ключей читается из JS)`);

console.log(fails === 0 ? "I18N OK" : `fails=${fails}`);
process.exit(fails ? 1 : 0);
