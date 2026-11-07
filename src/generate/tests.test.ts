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
    f({ id: "authz-matrix:attachment:GET:att_b_7", check: "authz-matrix", location: "https://staging.example.com/api/attachments/att_b_7" }),
    f({ id: "authz-matrix:file:GET:f1", check: "authz-matrix", state: "unproven", location: "https://staging.example.com/api/files/f1" }),
  ]);
  assert.match(out, /import \{ test, expect \} from "vitest"/);
  assert.equal((out.match(/\btest\(/g) ?? []).length, 4);
  assert.match(out, /@tanstack\/react-router@1\.169\.5/);
  assert.match(out, /pull_request_target/);
  assert.match(out, /STAGING_URL/); // authz env header included
  assert.match(out, /\/api\/attachments\/att_b_7/, "the test targets the exact object that leaked");
  assert.doesNotMatch(out, /\/api\/files\/f1/, "a lead gets no test");
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

test("generates tests for tls-verification and jwt-config", () => {
  const out = generateRegressionFile([
    f({ check: "tls-verification", title: "sets algorithm", location: "src/http.ts:4" }),
    f({ check: "jwt-config", title: "sets algorithm none", location: "src/auth.ts:2" }),
  ]);
  assert.match(out, /rejectUnauthorized/);
  assert.match(out, /none/);
  assert.equal((out.match(/\btest\(/g) ?? []).length, 2);
});
