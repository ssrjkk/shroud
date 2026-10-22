// web/tests/findings.mjs — согласованность карты находок.
//
// Что проверяет:
//   1. Нумерация находок в docs/04-threat-model.md сплошная (1..N, без дыр и
//      дублей). Дыра означает, что находку удалили, не перенумеровав остальные:
//      карта, которую читает аудитор, перестаёт быть перечислимой.
//   2. У каждой находки есть статус. Заголовок без статуса — это не находка, а
//      заметка: читатель не может понять, чинить её или принять.
//   3. Число находок, которое цитирует сайт, равно числу находок в модели.
//      Сайт ссылается на модель как на «N находок» — и это обещание читателю.
//      Расхождение появилось уже дважды: находки дописывались, а цифра на
//      сайте оставалась прежней.
//   4. Сводная карточка «N — enforced» совпадает с числом строк в таблице
//      «enforced»: там стояло 18 при 14 строках, и проверить цифру было нечем.
//
// Запуск из корня репозитория:  node web/tests/findings.mjs
// Зависимостей нет.
import { readFileSync, readdirSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");
const WEB = path.resolve(HERE, "..");

let fails = 0;
const fail = (m) => { fails++; console.log("FAIL:", m); };

// --- 1. заголовки находок -----------------------------------------------------
const model = readFileSync(path.join(ROOT, "docs", "04-threat-model.md"), "utf8");
const heads = [...model.matchAll(/^### (F-(\d+))\s*[-—]\s*(.*)$/gm)].map((m) => ({
  id: m[1],
  n: Number(m[2]),
  title: m[3],
}));

if (!heads.length) {
  fail("в docs/04-threat-model.md не найдено ни одной находки вида '### F-NN - …'");
}
const count = heads.length;

// --- 2. сплошная нумерация ----------------------------------------------------
const nums = heads.map((h) => h.n);
const dupes = [...new Set(nums.filter((v, i) => nums.indexOf(v) !== i))];
if (dupes.length) fail(`номера находок повторяются: ${dupes.join(", ")}`);
const gaps = [];
for (let i = 1; i <= count; i++) if (!nums.includes(i)) gaps.push(i);
if (gaps.length) fail(`в нумерации находок дыры: ${gaps.join(", ")}`);

// --- 3. у каждой находки есть статус -----------------------------------------
const noStatus = heads.filter((h) => !/\*\*.+\*\*/.test(h.title)).map((h) => h.id);
if (noStatus.length) {
  fail(`у находок нет статуса в заголовке: ${noStatus.join(", ")}`);
}

// --- 4. число на цитируемых страницах ---------------------------------------
// Цитата выглядит как «docs/04-threat-model.md (46 находок)» / «(46 findings)»;
// берём число рядом с именем файла, независимо от формулировки.
const QUOTE = /docs\/04-threat-model\.md\s*\((\d+)\s+[^)]+\)/g;
const sources = [
  ["web/assets/i18n.js", path.join(WEB, "assets", "i18n.js")],
  ["web/security.html", path.join(WEB, "security.html")],
];
let quoted = 0;
for (const [label, file] of sources) {
  const text = readFileSync(file, "utf8");
  const found = [...text.matchAll(QUOTE)];
  if (!found.length) {
    fail(`${label}: нет ссылки вида 'docs/04-threat-model.md (N …)' — цифра находок потеряна`);
    continue;
  }
  for (const m of found) {
    quoted++;
    if (Number(m[1]) !== count) {
      fail(`${label}: цитирует ${m[1]} находок, а в модели их ${count}`);
    }
  }
}
if (quoted) console.log(`цитат находок проверено: ${quoted}`);

// --- 3b. короткие цитаты в подвалах ------------------------------------------
// `threats 39` в f.base3/f.base4 — та же цифра другим форматом, и она дрейфовала
// ровно так же, пока гейт смотрел только на длинные цитаты. Проверяем все
// страницы и словарь: любое `threats N` обязано равняться числу находок.
const SHORT = /threats (\d+)/g;
const htmlPages = readdirSync(WEB)
  .filter((n) => n.endsWith(".html"))
  .sort();
const shortFiles = [
  ["web/assets/i18n.js", path.join(WEB, "assets", "i18n.js")],
  ...htmlPages.map((p) => [`web/${p}`, path.join(WEB, p)]),
];
let shorts = 0;
for (const [label, file] of shortFiles) {
  const text = readFileSync(file, "utf8");
  for (const m of text.matchAll(SHORT)) {
    shorts++;
    if (Number(m[1]) !== count) {
      fail(`${label}: цитирует threats ${m[1]}, а в модели их ${count}`);
    }
  }
}
if (shorts) console.log(`коротких цитат проверено: ${shorts}`);

// --- 5. сводная карточка совпадает с таблицей --------------------------------
// На карточке стояло «18 — enforced», пока в таблице было 14 строк: цифру никто
// не мог проверить, и она разошлась с содержимым страницы. Теперь число обязано
// совпадать с числом строк — и обе языковые версии обязаны называть одно и то же.
const sec = readFileSync(path.join(WEB, "security.html"), "utf8");
const i18n = readFileSync(path.join(WEB, "assets", "i18n.js"), "utf8");
const rows = [...sec.matchAll(/data-i18n="sec\.e\d+"/g)].length;
const cards = [...i18n.matchAll(/"sec\.c1t": "(\d+)/g)].map((m) => Number(m[1]));
if (!cards.length) {
  fail("в i18n нет ключа sec.c1t — сводная цифра потеряна");
} else if (new Set(cards).size !== 1) {
  fail(`ru и en называют разное число enforced-пунктов: ${cards.join(" / ")}`);
} else if (cards[0] !== rows) {
  fail(`карточка обещает ${cards[0]} enforced-пунктов, а в таблице их ${rows}`);
} else {
  console.log(`сводная карточка совпадает с таблицей: ${rows}`);
}

if (fails === 0) {
  console.log(`1. нумерация сплошная: F-01..F-${String(count).padStart(2, "0")}`);
  console.log(`2. статус есть у всех ${count} находок`);
  console.log(`3. сайт цитирует столько же, сколько в модели: ${count}`);
}
console.log(fails === 0 ? "FINDINGS OK" : `fails=${fails}`);
process.exit(fails ? 1 : 0);
