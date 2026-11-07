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
