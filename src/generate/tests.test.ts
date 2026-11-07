import { test } from "node:test";
import assert from "node:assert/strict";
import { generateRegressionFile } from "./tests.js";
import type { Finding } from "../core/types.js";

function f(over: Partial<Finding>): Finding {
  return {
    id: "x", check: "exposed-secrets", title: "t", severity: "critical", state: "proven",
    location: "dist/app.js:5", description: "d", remediation: "r", ...over,
  };
}

test("generates a test per supported finding, with imports", () => {
  const out = generateRegressionFile([
    f({ check: "exposed-secrets", location: "dist/app.js:5" }),
    f({ check: "dependency-risk", title: "Known-malicious package locked: @tanstack/react-router@1.169.5" }),
    f({ check: "ci-hardening", location: ".github/workflows/deploy.yml:4" }),
    f({ check: "authz-matrix" }),
  ]);
  assert.match(out, /import \{ test, expect \} from "vitest"/);
  assert.equal((out.match(/\btest\(/g) ?? []).length, 4);
  assert.match(out, /@tanstack\/react-router@1\.169\.5/);
  assert.match(out, /pull_request_target/);
  assert.match(out, /STAGING_URL/); // authz env header included
});

test("skips findings it cannot assert", () => {
  const out = generateRegressionFile([f({ check: "headers", title: "CSP manquant" })]);
  assert.equal((out.match(/\btest\(/g) ?? []).length, 0);
});
