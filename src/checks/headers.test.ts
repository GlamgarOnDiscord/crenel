import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeHeaders } from "./headers.js";

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
