import assert from "node:assert/strict";
import { test } from "node:test";
import { auditPage } from "./a11y.mjs";

const page = (body) => `<!doctype html><html lang="en"><head><title>Test</title></head><body>${body}</body></html>`;
const audit = (body) => auditPage(page(body), "fixture.html");
const ok = (body) => {
  const result = audit(body);
  assert.deepEqual(result.failures, []);
  return result;
};
const hasFailure = (result, message) => assert.ok(result.failures.some((failure) => failure.includes(message)), result.failures.join("\n"));

test("HTML5 parsing accepts mixed-case tags, quotes, unquoted values and boolean alt", () => {
  const result = auditPage(`<!DOCTYPE html><HTML LANG='en'><BODY>
    <H1 title='not a > delimiter'>Title</H1><H2>Section</H2>
    <LABEL FOR=field>Field</LABEL><INPUT ID=field>
    <LABEL>Choice<SELECT><OPTION>One</OPTION></SELECT></LABEL>
    <TEXTAREA ARIA-LABEL='notes > details'></TEXTAREA>
    <INPUT TYPE=HIDDEN><INPUT TYPE=SUBMIT>
    <IMG ALT><A HREF='/'>Tom &amp; Jerry</A><BUTTON ARIA-LABEL=Close></BUTTON>
    </BODY></HTML>`);
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.headings, [1, 2]);
  assert.equal(result.named, 3);
  assert.equal(result.labelable, 3);
});

test("comments, script/style raw text and template contents are not document elements", () => {
  const result = ok(`<h1>Title</h1>
    <!-- <h1>Comment</h1><input><img><a></a><button></button> -->
    <ScRiPt>globalThis.a11yExecuted = true; const html = '<h1>Fake</h1><input><img><a></a>';
      const comparison = 2 < 3 && 5 > 4;</ScRiPt >
    <StYlE>.example::before { content: '<h1>Fake</h1><input><img>'; }</StYlE >
    <template><h1>Inert</h1><input><img><button></button></template>
    <textarea aria-label='Source'><h1>Text, not an element</h1><input></textarea>`);
  assert.deepEqual(result.headings, [1]);
  assert.equal(result.labelable, 1);
  assert.equal(globalThis.a11yExecuted, undefined);
});

test("raw script text, comments and styles do not give a link or button a name", () => {
  const result = audit(`<h1>Title</h1>
    <a href='/'><script>const text = 'not a link name';</script><!-- no name --></a>
    <button><style>button { color: red }</style><template>Not a name</template></button>`);
  assert.equal(result.failures.length, 2);
  hasFailure(result, "ссылка без текста");
  hasFailure(result, "кнопка без подписи");
});

test("malformed comment termination follows HTML5 instead of hiding subsequent controls", () => {
  const result = audit("<h1>Title</h1><!--><INPUT id=unlabelled><IMG src=x><A href=/></A><BUTTON></BUTTON>");
  assert.equal(result.failures.length, 4);
  hasFailure(result, "поле #unlabelled");
  hasFailure(result, "<img> без alt");
  hasFailure(result, "ссылка без текста");
  hasFailure(result, "кнопка без подписи");
});

test("unclosed raw-text elements consume fake tags; mixed-case closing tags expose real ones", () => {
  ok("<h1>Title</h1><script>const html = '<h1>Fake</h1><input><img>'; ");
  const result = audit("<h1>Title</h1><script>const text = '<input>'; </ScRiPt ><input id=real>");
  assert.equal(result.labelable, 1);
  hasFailure(result, "поле #real");
});

test("HTML parser's script escaped state is respected", () => {
  // The first </script> ends the double-escaped state, NOT the outer script.
  const result = ok("<h1>Title</h1><script><!--<script></script><h1>Still raw text</h1>--></script><h2>Real</h2>");
  assert.deepEqual(result.headings, [1, 2]);
});

test("heading checks still reject missing, duplicate, non-first and skipped levels", () => {
  hasFailure(audit("<h2>No title</h2>"), "заголовков h1 — 0");
  hasFailure(audit("<h1>One</h1><H1>Two</H1>"), "заголовков h1 — 2");
  hasFailure(audit("<h2>First</h2><h1>Title</h1>"), "первый заголовок h2");
  hasFailure(audit("<h1>Title</h1><h3>Skipped</h3>"), "заголовок h3 сразу после h1");
  // A new heading implicitly closes the preceding heading in HTML.
  assert.deepEqual(ok("<h1>Title<h2>Section").headings, [1, 2]);
});

test("attributes containing fake markup cannot introduce headings, labels, ids or alt", () => {
  const result = audit(`<h1 title='<h1>fake</h1>'>Title</h1>
    <div data-fake='<label for="field">False label</label><span id="fake">False name</span>'></div>
    <input id=field><input aria-labelledby=fake><img data-alt='alt="fake"'>`);
  assert.deepEqual(result.headings, [1]);
  assert.equal(result.failures.length, 3);
  hasFailure(result, "поле #field");
  hasFailure(result, "<img> без alt");
});

test("real nonempty label associations and ID references name controls", () => {
  const result = ok(`<h1>Title</h1><label for='f'>Field</label><input id=f>
    <label>Wrapped <input></label><span id=one hidden>Shared</span><span id=two>Name</span>
    <input aria-labelledby=' one  two '><select aria-label='Choice'></select>
    <a href='/' aria-labelledby=one></a><button aria-labelledby='one two'></button>`);
  assert.equal(result.named, 4);
  assert.equal(result.labelable, 4);
});

test("empty labels, dangling references, and unrelated enclosing labels do not name controls", () => {
  const result = audit(`<h1>Title</h1><span id=empty> </span>
    <label for=a> </label><input id=a>
    <label for=other>Not this field <input id=b></label>
    <input id=c aria-label=' '><input id=d aria-labelledby=missing>
    <input id=e aria-labelledby=empty><input id=f aria-labelledby='empty missing'>
    <label><select id=g><option>Not a label</option></select></label>
    <label>Only first <input id=first><input id=second></label>`);
  assert.equal(result.labelable, 9);
  assert.equal(result.named, 1);
  assert.equal(result.failures.length, 8);
});

test("link names use text, image alt and SVG title, not markup or entity whitespace", () => {
  ok(`<h1>Title</h1><a href='/'><img src=x alt='Home'></a>
    <button><svg><title>Close &amp; exit</title><path d='M0 0'/></svg></button>
    <a href='/'>2 &lt; 3 &amp; 5 &gt; 4</a><button><span aria-label=Save></span></button>`);
  const result = audit(`<h1>Title</h1><a href='/'>&nbsp; &#32;</a>
    <button><img src=x alt=''></button><a href='/' aria-labelledby=missing></a>
    <button><span aria-hidden=true>Decorative</span></button>`);
  assert.equal(result.failures.length, 4);
});

test("language is read from the real html attribute, not a string in a comment", () => {
  hasFailure(auditPage("<!-- <html lang=en> --><h1>Title</h1>"), "у <html> нет lang");
  hasFailure(auditPage("<html data-lang=en><h1>Title</h1></html>"), "у <html> нет lang");
});
