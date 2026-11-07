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

test("generates tests for committed-env, sourcemaps and public-env", () => {
  const out = generateRegressionFile([
    f({ check: "committed-env", title: "Committed env file: .env.production", location: ".env.production" }),
    f({ id: "sourcemaps:file:dist/app.js.map", check: "sourcemaps", title: "Source map in the bundle: dist/app.js.map", location: "dist/app.js.map" }),
    f({ check: "public-env", title: "Secret-named var with a client-exposed prefix: NEXT_PUBLIC_API_SECRET", location: "src/config.ts:3" }),
  ]);
  assert.match(out, /import \{ readFileSync, existsSync \}/);
  assert.match(out, /existsSync\(".env.production"\)/);
  assert.match(out, /existsSync\("dist\/app.js.map"\)/);
  assert.match(out, /not\.toContain\("NEXT_PUBLIC_API_SECRET"\)/);
  assert.equal((out.match(/\btest\(/g) ?? []).length, 3);
});
