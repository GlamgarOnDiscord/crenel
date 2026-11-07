import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { authzOracle, claimFor, validateClaim, type Claim, type ValidatorEnv } from "./validators.js";
import { Scope } from "../core/scope.js";
import { exposedSecrets } from "../checks/exposed-secrets.js";
import { startDemoTarget, DEMO_TOKENS } from "../testing/demo-target.js";

const owner = { status: 200, body: '{"id":"proj_b_1","owner":"acct_b","name":"B roadmap"}' };

test("oracle: a 200 is not proof by itself", () => {
  const r = authzOracle({ attacker: { status: 200, body: '{"id":"x"}' }, control: { status: 404, body: "" }, ownerMarkers: [] });
  assert.equal(r.verdict, "lead");
});

test("oracle: the owner's marker in the attacker's body is a leak", () => {
  const r = authzOracle({ attacker: owner, control: { status: 404, body: "" }, ownerMarkers: ["acct_b"] });
  assert.equal(r.verdict, "leak");
});

test("oracle: a body identical to the owner's own response is a leak; a different body is a lead", () => {
  assert.equal(authzOracle({ attacker: owner, owner, control: { status: 404, body: "" }, ownerMarkers: [] }).verdict, "leak");
  assert.equal(authzOracle({ attacker: { status: 200, body: '{"id":"proj_a_9","owner":"acct_a"}' }, owner, control: { status: 404, body: "" }, ownerMarkers: [] }).verdict, "lead");
});

test("oracle: volatile fields do not hide a match", () => {
  const o = { status: 200, body: '{"id":"p","owner":"b","updated_at":"2026-11-07T10:00:00Z","name":"roadmap for tenant b"}' };
  const a = { status: 200, body: '{"id":"p","owner":"b","updated_at":"2026-11-07T10:00:09Z","name":"roadmap for tenant b"}' };
  assert.equal(authzOracle({ attacker: a, owner: o, control: { status: 404, body: "" }, ownerMarkers: [] }).verdict, "leak");
});

test("oracle: a route that answers a non-existent id the same way is not a leak (negative control)", () => {
  const generic = { status: 200, body: '{"ok":true}' };
  assert.equal(authzOracle({ attacker: generic, owner: generic, control: generic, ownerMarkers: ["ok"] }).verdict, "lead");
});

test("oracle: denied stays denied", () => {
  for (const s of [401, 403, 404, 500]) assert.equal(authzOracle({ attacker: { status: s, body: "" }, control: { status: 404, body: "" }, ownerMarkers: [] }).verdict, "denied");
});

function env(base: string, opts: Record<string, unknown>, active = true): ValidatorEnv {
  return {
    scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active, stagingUrl: base }),
    projectDir: tmpdir(), options: { "authz-matrix": opts }, stagingUrl: base, checks: [],
  };
}
const authzOpts = (o: Record<string, unknown> = {}) => ({
  resources: [{ name: "project", path: "/api/projects/:id" }, { name: "render", path: "/api/renders/:id" }],
  accounts: { a: { token: DEMO_TOKENS.a }, b: { token: DEMO_TOKENS.b, marker: "acct_b", owns: { project: ["proj_b_1"], render: ["rnd_b_1"] } } },
  ...o,
});
const claim = (resource: string, id: string, actor = "a"): Claim => ({ id: `c:${resource}:${id}:${actor}`, class: "authz.cross-tenant", source: "agent", detail: { resource, id, actor } });

test("authz validator: proves a real cross-tenant read with owner baseline and negative control", async () => {
  const t = await startDemoTarget();
  try {
    const v = await validateClaim(claim("project", "proj_b_1"), env(t.url, authzOpts()));
    assert.equal(v.state, "proven", v.reason);
    assert.ok(v.evidence?.control?.includes("crenel-nonexistent-"));
    assert.ok(!v.evidence?.request.includes(DEMO_TOKENS.a), "the token is redacted");
    assert.ok(t.seen.every((r) => r.method === "GET"));
    // owner baseline + attacker + control
    assert.equal(t.seen.length, 3);
  } finally { await t.close(); }
});

test("authz validator: a correctly isolated route is not proven", async () => {
  const t = await startDemoTarget();
  try {
    assert.equal((await validateClaim(claim("render", "rnd_b_1"), env(t.url, authzOpts()))).state, "unproven");
  } finally { await t.close(); }
});

test("authz validator: a route answering every id the same way is only a lead", async () => {
  const t = await startDemoTarget({ genericOk: true });
  try {
    const v = await validateClaim(claim("project", "proj_b_1"), env(t.url, authzOpts({ accounts: { a: { token: DEMO_TOKENS.a }, b: { token: DEMO_TOKENS.b, marker: "ok", owns: { project: ["proj_b_1"] } } } })));
    assert.equal(v.state, "unproven");
    assert.match(v.reason, /non-existent/);
  } finally { await t.close(); }
});

test("authz validator: refuses ids not declared as B's, public-by-design routes, and active testing off", async () => {
  const t = await startDemoTarget();
  try {
    assert.equal((await validateClaim(claim("project", "proj_a_1"), env(t.url, authzOpts()))).state, "unproven");
    assert.equal((await validateClaim(claim("project", "proj_b_1"), env(t.url, authzOpts({ publicByDesign: ["/api/projects/:id"] })))).state, "unproven");
    assert.equal((await validateClaim(claim("project", "proj_b_1"), env(t.url, authzOpts(), false))).state, "unproven");
    assert.equal(t.seen.length, 0, "nothing was sent for refused claims");
  } finally { await t.close(); }
});

test("a claim with no validator for its class stays unproven, labelled", async () => {
  const v = await validateClaim({ id: "x", class: "xss.reflected", source: "llm", detail: {} }, env("http://127.0.0.1:1", {}));
  assert.equal(v.state, "unproven");
  assert.equal(v.validator, null);
});

test("check.replay re-runs the check itself; a finding that does not reproduce is not proven", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-val-"));
  try {
    writeFileSync(join(dir, "app.js"), 'const k = "sk_live_ABCDEFGHIJKLMNOP1234";\n');
    const ctx = { scope: new Scope({ allowedHosts: [] }), projectDir: dir, options: {}, log: () => {} };
    const [f] = await exposedSecrets.run(ctx);
    const e: ValidatorEnv = { scope: ctx.scope, projectDir: dir, options: {}, checks: [exposedSecrets] };
    assert.equal((await validateClaim(claimFor(f!), e)).state, "proven");
    writeFileSync(join(dir, "app.js"), "// fixed\n");
    assert.equal((await validateClaim(claimFor(f!), e)).state, "unproven");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("check.replay hands the staging URL to the check, so a live proof can reproduce", async () => {
  const { validateClaim } = await import("./validators.js");
  const { Scope } = await import("../core/scope.js");
  const seen: (string | undefined)[] = [];
  const check = { name: "live-thing", title: "t", readOnly: true, run: async (c: { stagingUrl?: string }) => {
    seen.push(c.stagingUrl);
    return [{ id: "live-thing:x", check: "live-thing", title: "x", severity: "high" as const, state: "proven" as const, location: "https://s/x", description: "", remediation: "", proof: { method: "m", replay: "r" } }];
  } };
  const v = await validateClaim({ id: "c", source: "check", class: "check.replay", detail: { check: "live-thing", findingId: "live-thing:x" } },
    { scope: new Scope({ allowedHosts: ["s"] }), projectDir: ".", stagingUrl: "https://s/", options: {}, checks: [check] } as never);
  assert.equal(v.state, "proven");
  assert.deepEqual(seen, ["https://s/"]);
});
