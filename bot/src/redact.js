// bot/src/redact.js — keeping the provider's secret out of everything the bot prints.
//
// A managed RPC URL carries the provider's API key in it, and that key is the one
// thing in the configuration that must never reach a log line, a Telegram
// message, or a support screenshot. It has two carriers: the URL itself, and any
// text that quotes the URL — a provider that answers an error with the key in
// its body, or a stack that prints the request target. Both are handled here,
// from one place, so no call site has to remember to ask for it.

/**
 * A path segment that describes the endpoint rather than identifying the caller.
 *
 * `v1`, `v2`, `v3` are API versions: they say which service is being talked to,
 * and they are not secret. Every other segment is treated as a credential — the
 * key is not always the last one, and a rule that only masked the last segment
 * leaked the key in every URL shape that puts something after it.
 */
const SHAPE = /^v\d+$/i;

/** What a credential is replaced with. */
const MASK = "***";

/**
 * The RPC endpoint without its secret.
 *
 * The host (and its port) and the API version stay visible — the operator has to
 * know *which* endpoint — and everything that could be a credential is masked:
 * the path segments that are not version tokens, the query string, the fragment,
 * and the URL's own credentials.
 */
export function redactRpcUrl(url) {
  try {
    const u = new URL(url);
    const segments = u.pathname
      .split("/")
      .filter(Boolean)
      .map((s) => (SHAPE.test(s) ? s : MASK));
    u.pathname = segments.length ? `/${segments.join("/")}` : "";
    u.search = "";
    u.hash = "";
    u.username = "";
    u.password = "";
    return u.toString();
  } catch {
    // Not a URL we can parse: show only the shape, never the tail.
    return "<rpc url>";
  }
}

/**
 * Remove the RPC secret from a piece of text.
 *
 * Used on every error the bot prints or sends: the message may quote the URL, or
 * the provider may have echoed the key back in an error body. The URL is
 * replaced by its redacted form (so the operator still sees which endpoint), and
 * the credentials themselves are replaced wherever they appear.
 *
 * A credential shorter than eight characters is left alone: a short string is
 * far more likely to be a coincidence than a key, and replacing it would mangle
 * the message without protecting anything.
 */
export function scrubRpcSecret(text, url) {
  if (typeof text !== "string" || !text) return text;
  let out = text;
  let u;
  try {
    u = new URL(url);
  } catch {
    return out;
  }

  // The whole URL, if the text quotes it.
  const raw = String(url);
  if (raw && out.includes(raw)) out = out.split(raw).join(redactRpcUrl(raw));

  // The credentials themselves, wherever they appear: userinfo, path, query, fragment.
  const secrets = [];
  if (u.username) secrets.push(u.username);
  if (u.password) secrets.push(u.password);
  for (const seg of u.pathname.split("/").filter(Boolean)) {
    if (!SHAPE.test(seg)) secrets.push(seg);
  }
  if (u.search) {
    for (const [, value] of new URLSearchParams(u.search)) {
      if (value) secrets.push(value);
    }
  }
  if (u.hash && u.hash.length > 1) secrets.push(u.hash.slice(1));
  for (const secret of secrets) {
    if (secret.length < 8) continue;
    out = out.split(secret).join(MASK);
  }
  return out;
}
