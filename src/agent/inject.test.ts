import { test } from "node:test";
import assert from "node:assert/strict";
import { xssOracle, sqliOracle, templateOracle, nosqlOracle, nonce } from "./inject.js";

test("nonce is unique and url-safe", () => {
  const a = nonce("x"), b = nonce("x");
  assert.notEqual(a, b);
  assert.match(a, /^cr[0-9a-f]{10}$/);
});

test("xss: unescaped markup is proven", () => {
  const t = "crABC123";
  const r = xssOracle({ token: t, status: 200, body: `<div>hi <svg/onload=1>${t}</div>` });
  assert.equal(r.verdict, "proven");
});

test("xss: escaped reflection is only a lead", () => {
  const t = "crABC123";
  const r = xssOracle({ token: t, status: 200, body: `search: &lt;svg/onload=1&gt;${t}` });
  assert.equal(r.verdict, "lead");
});

test("xss: no reflection is denied", () => {
  const r = xssOracle({ token: "crZZZ", status: 200, body: "nothing here" });
  assert.equal(r.verdict, "denied");
});

test("sqli: error-based is proven", () => {
  const r = sqliOracle({
    baseline: { status: 200, body: "ok" },
    truthy: { status: 500, body: "You have an error in your SQL syntax near ''" },
    falsy: { status: 200, body: "ok" },
  });
  assert.equal(r.verdict, "proven");
  assert.equal(r.kind, "sqli-error");
});

test("sqli: boolean-based is proven when TRUE==baseline and FALSE diverges", () => {
  const r = sqliOracle({
    baseline: { status: 200, body: "<h1>Welcome Alice</h1> items: 5" },
    truthy: { status: 200, body: "<h1>Welcome Alice</h1> items: 5" },
    falsy: { status: 200, body: "<h1>No results</h1>" },
  });
  assert.equal(r.verdict, "proven");
  assert.equal(r.kind, "sqli-boolean");
});

test("sqli: identical true/false is denied (no differential)", () => {
  const r = sqliOracle({
    baseline: { status: 200, body: "same" },
    truthy: { status: 200, body: "same" },
    falsy: { status: 200, body: "same" },
  });
  assert.equal(r.verdict, "denied");
});

test("sqli: a static page that ignores input is not a false positive", () => {
  // baseline, truthy, falsy all identical -> denied, never proven.
  const page = { status: 200, body: "<html>static marketing page</html>" };
  const r = sqliOracle({ baseline: page, truthy: page, falsy: page });
  assert.notEqual(r.verdict, "proven");
});

test("template: evaluated expression adjacent to nonce is proven", () => {
  const t = "crT9";
  const r = templateOracle({ token: t, product: "49", body: `result: ${t}49 done` });
  assert.equal(r.verdict, "proven");
});

test("template: nonce reflected without evaluation is a lead", () => {
  const t = "crT9";
  const r = templateOracle({ token: t, product: "49", body: `result: ${t}\${7*7}` });
  assert.equal(r.verdict, "lead");
});

test("template: nothing reflected is denied", () => {
  const r = templateOracle({ token: "crT9", product: "49", body: "error" });
  assert.equal(r.verdict, "denied");
});

test("nosql: always-true operator matches baseline, always-false diverges -> proven", () => {
  const r = nosqlOracle({ baseline: { status: 200, body: '{"ok":1}' }, truthy: { status: 200, body: '{"ok":1}' }, falsy: { status: 401, body: "denied" } });
  assert.equal(r.verdict, "proven");
});
test("nosql: parse error surfaces -> proven", () => {
  const r = nosqlOracle({ baseline: { status: 200, body: "ok" }, truthy: { status: 500, body: "MongoError: unknown operator" }, falsy: { status: 200, body: "ok" } });
  assert.equal(r.verdict, "proven");
});
test("nosql: no differential -> denied", () => {
  const r = nosqlOracle({ baseline: { status: 200, body: "x" }, truthy: { status: 200, body: "same" }, falsy: { status: 200, body: "same" } });
  assert.equal(r.verdict, "denied");
});
