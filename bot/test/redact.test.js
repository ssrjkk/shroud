// bot/test/redact.test.js — the provider's key must not survive anywhere.
//
// A managed RPC URL carries the provider's API key in it. The bot prints that
// URL (the operator has to see *which* endpoint) and prints error messages that
// may quote it. Both paths are covered here: the key is in the path, the query,
// the fragment, or the URL's own credentials - and not always in the last
// segment.
import { test } from "node:test";
import assert from "node:assert/strict";
import { redactRpcUrl, scrubRpcSecret } from "../src/redact.js";

const KEY = "SuperSecretKey123";

test("the key does not survive when it is not the last path segment", () => {
  // A gateway that puts something after the key: masking only the last segment
  // (the old rule) printed the key in clear.
  const redacted = redactRpcUrl(`https://gateway.example.com/${KEY}/v2/extra`);
  assert.ok(!redacted.includes(KEY), `the key survived: ${redacted}`);
  assert.ok(redacted.includes("gateway.example.com"), `the endpoint must stay visible: ${redacted}`);
});

test("the key does not survive in the query or the fragment", () => {
  const withQuery = redactRpcUrl(`https://rpc.example.com/v2?apikey=${KEY}`);
  assert.ok(!withQuery.includes(KEY), `the key survived in the query: ${withQuery}`);
  const withFragment = redactRpcUrl(`https://rpc.example.com/v2#apikey=${KEY}`);
  assert.ok(!withFragment.includes(KEY), `the key survived in the fragment: ${withFragment}`);
});

test("the URL's own credentials do not survive", () => {
  const redacted = redactRpcUrl(`https://user:${KEY}@rpc.example.com/v2`);
  assert.ok(!redacted.includes(KEY), `the key survived as a password: ${redacted}`);
  assert.ok(!redacted.includes("user"), `the user name survived: ${redacted}`);
});

test("the endpoint and the API version stay visible", () => {
  const redacted = redactRpcUrl(`https://eth-mainnet.g.alchemy.com/v2/${KEY}`);
  assert.ok(redacted.includes("alchemy.com"), `the endpoint must stay visible: ${redacted}`);
  assert.ok(redacted.includes("v2"), `the API version must stay visible: ${redacted}`);
  assert.ok(!redacted.includes(KEY), `the key survived: ${redacted}`);
});

test("a URL we cannot parse is not printed at all", () => {
  assert.ok(!redactRpcUrl("not a url").includes("not a url"));
  assert.ok(!redactRpcUrl("not a url").includes("not a url"));
});

test("a message that quotes the RPC URL is scrubbed", () => {
  const url = `https://eth-mainnet.g.alchemy.com/v2/${KEY}`;
  const message = `request to ${url} failed`;
  const scrubbed = scrubRpcSecret(message, url);
  assert.ok(!scrubbed.includes(KEY), `the key survived: ${scrubbed}`);
  assert.ok(scrubbed.includes("alchemy.com"), `the endpoint must stay visible: ${scrubbed}`);
});

test("a provider that echoes the key back does not leak it", () => {
  // Some providers answer an error with the key in the body.
  const url = `https://eth-mainnet.g.alchemy.com/v2/${KEY}`;
  const message = `bad response (error={"code":401,"message":"invalid key ${KEY}"})`;
  const scrubbed = scrubRpcSecret(message, url);
  assert.ok(!scrubbed.includes(KEY), `the key survived: ${scrubbed}`);
  assert.ok(scrubbed.includes("invalid key"), `the diagnosis must survive: ${scrubbed}`);
});

test("a short segment is not treated as a credential", () => {
  // Replacing a short string would mangle the message without protecting anything.
  const url = "https://rpc.example.com/v2/abcd";
  const message = "the node answered with abcd in it";
  assert.equal(scrubRpcSecret(message, url), message);
});

test("scrubbing a message without a URL is a no-op", () => {
  assert.equal(scrubRpcSecret("plain text", "not a url"), "plain text");
  assert.equal(scrubRpcSecret("", "not a url"), "");
});
