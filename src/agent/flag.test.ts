import test from "node:test";
import assert from "node:assert/strict";
import { flagOracle } from "./flag.js";

test("flag: a flag token in the response is proven", () => {
  const r = flagOracle({ body: 'draft content: flag{5f7d543b-2625-4b62} more' });
  assert.equal(r.verdict, "proven");
  assert.equal(r.flag, "flag{5f7d543b-2625-4b62}");
});

test("flag: no flag token is denied", () => {
  const r = flagOracle({ body: '{"status":"ok","user":"alice"}' });
  assert.equal(r.verdict, "denied");
});

test("flag: a flag we sent ourselves (echo) is not a capture", () => {
  const r = flagOracle({ body: "you searched for flag{abcd1234}", sent: "GET /q?x=flag{abcd1234} {} " });
  assert.equal(r.verdict, "denied");
});

test("flag: a different retrieved flag is still proven even if we sent an unrelated token", () => {
  const r = flagOracle({ body: "admin draft: flag{real-one-9999}", sent: "GET /q?x=flag{our-echo-0000} {} " });
  assert.equal(r.verdict, "proven");
  assert.equal(r.flag, "flag{real-one-9999}");
});

test("flag: a custom pattern matches a non-default marker", () => {
  const r = flagOracle({ body: "secret: CTF{deadbeef}", pattern: "CTF\\{[^}]+\\}" });
  assert.equal(r.verdict, "proven");
  assert.equal(r.flag, "CTF{deadbeef}");
});

test("flag: an invalid custom pattern falls back to the default format", () => {
  const r = flagOracle({ body: "flag{fallback-ok}", pattern: "(" });
  assert.equal(r.verdict, "proven");
  assert.equal(r.flag, "flag{fallback-ok}");
});
