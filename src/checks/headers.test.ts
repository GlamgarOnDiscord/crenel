import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeHeaders, headers as headersCheck } from "./headers.js";
import { Scope } from "../core/scope.js";

test("flags every missing security header", () => {
  const found = analyzeHeaders(new Headers(), "https://staging.example.com");
  const ids = found.map((f) => f.id.split(":")[1]);
  for (const id of ["csp", "hsts", "xcto", "xfo", "refpol"]) assert.ok(ids.includes(id), `missing ${id}`);
});

test("a fully hardened response yields no header findings", () => {
  const h = new Headers({
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
  });
  assert.equal(analyzeHeaders(h, "https://staging.example.com").length, 0);
});

test("a cookie missing flags is reported", () => {
  const h = new Headers({ "set-cookie": "sid=abc; Path=/" });
  // Add the security headers so only the cookie finding remains.
  h.set("content-security-policy", "x"); h.set("strict-transport-security", "x");
  h.set("x-content-type-options", "x"); h.set("x-frame-options", "x"); h.set("referrer-policy", "x");
  const found = analyzeHeaders(h, "https://staging.example.com");
  assert.equal(found.length, 1);
  assert.match(found[0]!.title, /secure|httponly|samesite/i);
});

test("CSP frame-ancestors covers framing, so X-Frame-Options is not flagged", () => {
  const h = new Headers({
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
  });
  const ids = analyzeHeaders(h, "https://staging.example.com").map((f) => f.id.split(":")[1]);
  assert.ok(!ids.includes("xfo"), "frame-ancestors should satisfy the framing control");
});

test("a permissive frame-ancestors does NOT suppress the X-Frame-Options finding", () => {
  for (const csp of ["frame-ancestors *", "default-src 'self'; frame-ancestors https:", "frame-ancestors"]) {
    const h = new Headers({
      "content-security-policy": csp,
      "strict-transport-security": "max-age=31536000",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
    });
    const ids = analyzeHeaders(h, "https://staging.example.com").map((f) => f.id.split(":")[1]);
    assert.ok(ids.includes("xfo"), `permissive CSP (${csp}) should still flag XFO`);
  }
});

test("a restrictive frame-ancestors suppresses XFO", () => {
  for (const csp of ["frame-ancestors 'none'", "frame-ancestors 'self'", "frame-ancestors https://app.example.com"]) {
    const h = new Headers({
      "content-security-policy": csp,
      "strict-transport-security": "max-age=31536000",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
    });
    const ids = analyzeHeaders(h, "https://staging.example.com").map((f) => f.id.split(":")[1]);
    assert.ok(!ids.includes("xfo"), `restrictive CSP (${csp}) should satisfy framing`);
  }
});

test("CORS credentials + wildcard/null origin is a proven high finding", () => {
  for (const origin of ["*", "null"]) {
    const h = new Headers({
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "strict-transport-security": "max-age=31536000",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "access-control-allow-credentials": "true",
      "access-control-allow-origin": origin,
    });
    const f = analyzeHeaders(h, "https://staging.example.com").find((x) => x.id.includes(":cors:"));
    assert.ok(f, `expected a CORS finding for origin ${origin}`);
    assert.equal(f!.severity, "high");
    assert.equal(f!.state, "proven");
  }
});

test("credentials with a specific origin, or wildcard without credentials, is not flagged", () => {
  const specific = new Headers({
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "access-control-allow-credentials": "true",
    "access-control-allow-origin": "https://app.example.com",
  });
  assert.ok(!analyzeHeaders(specific, "https://s.example.com").some((f) => f.id.includes(":cors:")));
  const noCreds = new Headers({
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "access-control-allow-origin": "*",
  });
  assert.ok(!analyzeHeaders(noCreds, "https://s.example.com").some((f) => f.id.includes(":cors:")));
});

test("live: runs against a staging response and flags its missing headers", async () => {
  const http = await import("node:http");
  const server = http.createServer((_req, res) => { res.writeHead(200); res.end("ok"); }); // no security headers
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: `http://127.0.0.1:${port}` });
    const found = await headersCheck.run({ scope, projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options: {}, log: () => {} });
    const ids = found.map((f) => f.id.split(":")[1]);
    for (const id of ["csp", "hsts", "xcto", "refpol"]) assert.ok(ids.includes(id), `expected missing ${id}`);
    assert.ok(found.every((f) => f.state === "proven"), "missing headers are proven on the live response");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("live: no stagingUrl yields a single lead", async () => {
  const found = await headersCheck.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 1);
  assert.equal(found[0]!.id, "headers:no-staging");
  assert.equal(found[0]!.state, "unproven");
});
