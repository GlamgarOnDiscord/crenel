import { test } from "node:test";
import assert from "node:assert/strict";
import { demo, toData, type ServerState } from "./api.ts";

const now = new Date().toISOString();
const state: ServerState = {
  project: "demo", llm: null,
  scope: { allowedHosts: ["127.0.0.1"], stagingUrl: "http://127.0.0.1:4580/", allowActiveTesting: true },
  scannedAt: now,
  findings: [
    { id: "authz-matrix:project:GET:proj_b_1:a", uid: "f-1", check: "authz-matrix", title: "Le compte A lit le project du compte B", severity: "critical", state: "proven", location: "GET /api/projects/proj_b_1", description: "d", remediation: "r", firstSeen: now, lastSeen: now, validator: "authz-replay" },
    { id: "headers:no-staging", uid: "f-2", check: "headers", title: "lead", severity: "low", state: "unproven", location: ".", description: "d", remediation: "r", firstSeen: now, lastSeen: now, verdict: "no validator" },
    { id: "exposed-secrets:x", uid: "f-3", check: "exposed-secrets", title: "Stripe", severity: "critical", state: "fixed", location: "app.js:1", description: "d", remediation: "r", firstSeen: now, lastSeen: now },
  ],
  runs: [{ id: "r-1", title: "/scan", startedAt: now, endedAt: now, status: "waiting", proven: 1, leads: 1, fixed: 1 }],
  authz: null,
  authzResources: [{ name: "project", path: "/api/projects/:id" }],
  tests: [{ uid: "f-1", name: "A cannot read B", check: "authz-matrix", status: "draft", at: now, code: "test('x', () => {})" }],
  audit: [{ at: now, kind: "scan", findings: [{ state: "proven" }, { state: "unproven" }] }],
};

test("maps the server state to the console model, without inventing anything", () => {
  const d = toData(state);
  assert.equal(d.live, true);
  assert.deepEqual(d.findings.map((f) => [f.id, f.sev, f.state]), [["f-1", "crit", "proven"], ["f-2", "low", "lead"], ["f-3", "crit", "fixed"]]);
  assert.match(d.findings[1]!.description, /no validator/, "an unproven verdict says why");
  assert.equal(d.findings[0]!.regression, "test('x', () => {})");
  assert.ok(d.findings.every((f) => f.guarded === false), "CI status is never claimed");
  assert.equal(d.guardedCount, 0);
  assert.equal(d.tasks[0]!.status, "waiting");
  assert.equal(d.targets[0]!.proven, 1, "fixed findings are not open");
  assert.equal(d.daily.proven.at(-1), 1);
  assert.equal(d.daily.tasks.at(-1), 1);
  assert.deepEqual(d.authzResources, [{ id: "project", label: "project", route: "GET /api/projects/:id" }]);
  assert.ok(d.secrets.every((s) => s.valid === "inconnue"), "liveness is not checked, so never 'active'");
});

test("demo data stays the fallback", () => {
  assert.equal(demo.live, false);
  assert.ok(demo.findings.length > 0);
});
