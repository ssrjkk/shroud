// web/tests/a11y.mjs — доступность статического сайта без браузера.
//
// axe-core (через Lighthouse) нашёл на сайте то, чего не видно на скриншоте:
// заголовки прыгали с h1 на h5 в футере, страницы кроме главной вообще не
// имели h1, а поля лаборатории стояли рядом с label, но не были с ними
// связаны. Этот гейт фиксирует ровно те правила, чтобы они не вернулись.
//
// Что проверяет:
//   1. Ровно один h1, и он — первый заголовок документа.
//   2. Уровни не прыгают вниз (h1 → h3).
//   3. У каждого поля есть доступное имя: label[for], aria-label,
//      aria-labelledby или объемлющий label.
//   4. У каждой картинки есть alt (пустой alt допустим).
//   5. У каждой ссылки и кнопки есть текст или aria-label/labelledby.
//   6. У <html> есть lang.
//
// parse5 строит HTML5-дерево, но не запускает JS и не загружает ресурсы.
// Это статический гейт, не полная реализация Accessible Name: CSS, динамику,
// клавиатуру и screen reader по-прежнему нужно проверять в браузере.
//
// Из корня: npm ci --prefix web/tests && node web/tests/a11y.mjs
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { parse, serializeOuter } from "parse5";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(HERE, "..");
const HTML_NS = "http://www.w3.org/1999/xhtml";
const INERT = new Set(["script", "style", "template", "noscript"]);
const HEADING_LEVEL = new Map(["h1", "h2", "h3", "h4", "h5", "h6"].map((tag, i) => [tag, i + 1]));
const CONTROL_TAGS = new Set(["input", "select", "textarea"]);
const LABELABLE_TAGS = new Set(["button", "input", "meter", "output", "progress", "select", "textarea"]);
// Кнопки отправки и скрытые поля не нуждаются в отдельной подписи.
const NAMELESS_INPUTS = new Set(["hidden", "submit", "button", "reset", "image"]);
const attr = (node, name) => node.attrs?.find((a) => a.name === name)?.value;
const isHtml = (node, tag = node.tagName) => node.namespaceURI === HTML_NS && node.tagName === tag;
const isLabelable = (node) => isHtml(node) && LABELABLE_TAGS.has(node.tagName) &&
  !(node.tagName === "input" && attr(node, "type")?.toLowerCase() === "hidden");

// Do not descend into inert/raw-text elements. In particular, markup-looking
// strings in scripts, styles, comments and template contents are not controls.
function* elements(node) {
  if (INERT.has(node.tagName)) return;
  if (node.tagName) yield node;
  for (const child of node.childNodes ?? []) yield* elements(child);
}

// Work on parsed nodes only: entities and quoted '>' characters are already
// decoded by the parser. Never strip tags or comments out of source strings.
function nameText(node, { skipControls = false, includeHidden = false } = {}) {
  if (INERT.has(node.tagName)) return "";
  if (!includeHidden && (attr(node, "hidden") !== undefined || attr(node, "aria-hidden") === "true")) return "";
  if (skipControls && isLabelable(node)) return "";
  if (node.nodeName === "#text") return node.value;
  if (!node.tagName) return ""; // comments and doctypes do not name anything
  const ariaLabel = attr(node, "aria-label");
  if (ariaLabel?.trim()) return ariaLabel;
  if (isHtml(node, "img")) return attr(node, "alt") ?? "";
  return (node.childNodes ?? []).map((child) => nameText(child, { skipControls, includeHidden })).join("");
}

export function auditPage(raw, page = "page") {
  const nodes = [...elements(parse(raw))];
  const failures = [];
  const fail = (message) => failures.push(`${page}: ${message}`);
  const describe = (node) => serializeOuter(node).slice(0, 60);

  // --- 1. один h1, и он первый ---------------------------------------------
  const headings = nodes.filter((node) => isHtml(node) && HEADING_LEVEL.has(node.tagName))
    .map((node) => HEADING_LEVEL.get(node.tagName));
  const h1s = headings.filter((h) => h === 1).length;
  if (h1s !== 1) fail(`заголовков h1 — ${h1s}, ожидался ровно один`);
  else if (headings[0] !== 1) fail(`первый заголовок h${headings[0]}, а не h1`);

  // --- 2. уровни не прыгают вниз -------------------------------------------
  let prev = 0;
  for (const h of headings) {
    if (prev && h > prev + 1) fail(`заголовок h${h} сразу после h${prev}`);
    prev = h;
  }

  // --- 3. доступные имена полей -------------------------------------------
  const byId = new Map();
  for (const node of nodes) {
    const id = attr(node, "id");
    if (id && !byId.has(id)) byId.set(id, node); // browser's first matching id
  }
  const hasAriaName = (node) => {
    if (attr(node, "aria-label")?.trim()) return true;
    const refs = attr(node, "aria-labelledby")?.trim().split(/\s+/).filter(Boolean) ?? [];
    return refs.length > 0 && refs.every((ref) => byId.has(ref)) &&
      refs.some((ref) => nameText(byId.get(ref), { includeHidden: true }).trim());
  };
  const labelled = new Set();
  for (const label of nodes.filter((node) => isHtml(node, "label"))) {
    const forId = attr(label, "for");
    const control = forId !== undefined ? byId.get(forId) : [...elements(label)].find(isLabelable);
    if (control && isLabelable(control) && nameText(label, { skipControls: true }).trim()) labelled.add(control);
  }
  let named = 0;
  let labelable = 0;
  for (const control of nodes.filter((node) => isHtml(node) && CONTROL_TAGS.has(node.tagName))) {
    if (control.tagName === "input" && NAMELESS_INPUTS.has(attr(control, "type")?.toLowerCase())) continue;
    labelable++;
    const id = attr(control, "id");
    if (hasAriaName(control) || labelled.has(control)) named++;
    else fail(`поле ${id ? "#" + id : control.tagName} без доступного имени`);
  }

  // --- 4. alt у картинок ----------------------------------------------------
  for (const img of nodes.filter((node) => isHtml(node, "img"))) {
    if (attr(img, "alt") === undefined) fail(`<img> без alt: ${describe(img)}`);
  }

  // --- 5. имена ссылок и кнопок --------------------------------------------
  // Текстом считается и alt вложенной картинки, и <title> внутри svg.
  for (const node of nodes) {
    if (!isHtml(node, "a") && !isHtml(node, "button")) continue;
    if (hasAriaName(node) || nameText(node).trim()) continue;
    fail(`${node.tagName === "a" ? "ссылка без текста" : "кнопка без подписи"}: ${describe(node)}`);
  }

  // --- 6. язык документа ----------------------------------------------------
  const html = nodes.find((node) => isHtml(node, "html"));
  if (!/^[a-z]{2,}/i.test(attr(html, "lang") ?? "")) fail("у <html> нет lang");

  return { failures, headings, named, labelable };
}

// Importing the audit for regression tests must not run the CLI or exit Node.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const pages = readdirSync(WEB).filter((name) => name.endsWith(".html")).sort();
  let fails = 0;
  if (!pages.length) {
    console.log("FAIL: в web/ нет ни одной страницы");
    fails++;
  }
  for (const page of pages) {
    const { failures, named, labelable } = auditPage(readFileSync(path.join(WEB, page), "utf8"), page);
    fails += failures.length;
    for (const failure of failures) console.log("FAIL:", failure);
    if (!failures.length) console.log(`${page}: h1 на месте, уровни без пропусков, полей с именем ${named}/${labelable}, alt и подписи на месте`);
  }
  console.log(fails === 0 ? "A11Y OK" : `fails=${fails}`);
  process.exitCode = fails ? 1 : 0;
}
