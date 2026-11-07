import { test } from "node:test";
import assert from "node:assert/strict";
import { Scope, ScopeError } from "./scope.js";

test("scope allows a declared host and refuses others", () => {
  const s = new Scope({ allowedHosts: ["staging.example.com"] });
  assert.equal(s.isHostAllowed("https://staging.example.com/api"), true);
  assert.equal(s.isHostAllowed("https://evil.example.com/"), false);
  assert.throws(() => s.assertUrlAllowed("https://evil.example.com/"), ScopeError);
});

test("active testing is off by default and gated on", () => {
  const off = new Scope({ allowedHosts: ["a.com"] });
  assert.throws(() => off.assertActiveAllowed("x"), ScopeError);
  const on = new Scope({ allowedHosts: ["a.com"], allowActiveTesting: true });
  assert.doesNotThrow(() => on.assertActiveAllowed("x"));
});

test("a staging url outside the allowlist fails at construction", () => {
  assert.throws(
    () => new Scope({ allowedHosts: ["a.com"], stagingUrl: "https://b.com" }),
    ScopeError,
  );
});

test("userinfo in the URL cannot spoof an allowed host", () => {
  const s = new Scope({ allowedHosts: ["staging.example.com"] });
  // The real host is evil.com; the allowed name is only in the userinfo.
  assert.equal(s.isHostAllowed("https://staging.example.com@evil.com/"), false);
  assert.throws(() => s.assertUrlAllowed("https://staging.example.com@evil.com/"), ScopeError);
});

test("host matching is case-insensitive", () => {
  const s = new Scope({ allowedHosts: ["Staging.Example.com"] });
  assert.equal(s.isHostAllowed("HTTPS://STAGING.EXAMPLE.COM/x"), true);
});

test("a port does not change the host decision", () => {
  const s = new Scope({ allowedHosts: ["staging.example.com"] });
  assert.equal(s.isHostAllowed("https://staging.example.com:8443/"), true);
});

test("a trailing-dot host is not treated as the allowed host (fails closed)", () => {
  const s = new Scope({ allowedHosts: ["staging.example.com"] });
  assert.equal(s.isHostAllowed("https://staging.example.com./"), false);
});

test("a non-URL string is refused, not thrown through", () => {
  const s = new Scope({ allowedHosts: ["a.com"] });
  assert.equal(s.isHostAllowed("not a url"), false);
});
