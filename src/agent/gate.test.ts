import { test } from "node:test";
import assert from "node:assert/strict";
import { authorize, gateDeterministic, type GateContext, type Mode } from "./gate.js";
import { Scope } from "../core/scope.js";

const scope = (o: Partial<ConstructorParameters<typeof Scope>[0]> = {}) =>
  new Scope({ allowedHosts: ["staging.acme.test"], allowActiveTesting: true, ...o });
const ctx = (mode: Mode, o: Partial<GateContext> = {}): GateContext => ({ scope: scope(), mode, grants: new Set(), userRequest: "scan", ...o });
const get = (url: string) => ({ method: "GET", url });

test("offline tools are allowed in every mode, and cannot carry requests", () => {
  for (const m of ["ask", "readonly", "bypass"] as Mode[]) assert.equal(gateDeterministic({ tool: "scan.secrets" }, ctx(m)).verdict, "allow");
  assert.equal(gateDeterministic({ tool: "scan.secrets", requests: [get("https://staging.acme.test/")] }, ctx("bypass")).verdict, "deny");
});

test("unknown tools are denied", () => {
  assert.equal(gateDeterministic({ tool: "shell.exec" }, ctx("bypass")).verdict, "deny");
});

test("ask mode asks before a network request to a declared host; a session grant skips the question", () => {
  assert.equal(gateDeterministic({ tool: "scan.web", requests: [get("https://staging.acme.test/")] }, ctx("ask")).verdict, "ask");
  const d = gateDeterministic({ tool: "scan.web", requests: [get("https://staging.acme.test/")] }, ctx("ask", { grants: new Set(["staging.acme.test"]) }));
  assert.equal(d.verdict, "allow");
  assert.equal(d.unattended, true, "a probe sent on a standing grant is logged as unattended");
});

test("readonly mode never lets a request out", () => {
  const d = gateDeterministic({ tool: "scan.web", requests: [get("https://staging.acme.test/")] }, ctx("readonly", { grants: new Set(["staging.acme.test"]) }));
  assert.equal(d.verdict, "deny");
});

test("bypass removes the question, not the perimeter", () => {
  const c = ctx("bypass");
  const ok = gateDeterministic({ tool: "authz.matrix", requests: [get("https://staging.acme.test/api/projects/1")] }, c);
  assert.equal(ok.verdict, "allow");
  assert.equal(ok.unattended, true);
  // Out of scope host.
  assert.equal(gateDeterministic({ tool: "scan.web", requests: [get("https://evil.example/")] }, c).verdict, "deny");
  // Mutating method, even on a declared host.
  for (const m of ["POST", "PUT", "PATCH", "DELETE"]) {
    assert.equal(gateDeterministic({ tool: "authz.matrix", requests: [{ method: m, url: "https://staging.acme.test/api/projects/1" }] }, c).verdict, "deny", m);
  }
  // A GET that looks like a side effect.
  assert.equal(gateDeterministic({ tool: "scan.web", requests: [get("https://staging.acme.test/account/delete")] }, c).verdict, "deny");
  // Active probe with allowActiveTesting off in the config.
  assert.equal(gateDeterministic({ tool: "authz.matrix", requests: [get("https://staging.acme.test/x")] }, { ...c, scope: scope({ allowActiveTesting: false }) }).verdict, "deny");
  // Private IP literal, declared, but allowPrivate off.
  const priv = { ...c, scope: new Scope({ allowedHosts: ["169.254.169.254", "10.0.0.5"], allowActiveTesting: true }) };
  assert.equal(gateDeterministic({ tool: "scan.web", requests: [get("http://169.254.169.254/latest/meta-data")] }, priv).verdict, "deny");
  assert.equal(gateDeterministic({ tool: "scan.web", requests: [get("http://10.0.0.5/")] }, priv).verdict, "deny");
  // Non-http scheme.
  assert.equal(gateDeterministic({ tool: "scan.web", requests: [get("file:///etc/passwd")] }, c).verdict, "deny");
});

test("one bad request in a batch denies the whole call", () => {
  const d = gateDeterministic({ tool: "scan.web", requests: [get("https://staging.acme.test/"), get("https://other.example/")] }, ctx("bypass"));
  assert.equal(d.verdict, "deny");
  assert.ok(d.reasons.some((r) => r.includes("other.example")));
});

test("a judge can harden (allow -> ask, ask -> deny) but never loosen a deny", async () => {
  const call = { tool: "scan.web", requests: [get("https://staging.acme.test/")] };
  assert.equal((await authorize(call, ctx("bypass"), async () => "ask")).verdict, "ask");
  assert.equal((await authorize(call, ctx("ask"), async () => "deny")).verdict, "deny");
  const bad = { tool: "scan.web", requests: [get("https://evil.example/")] };
  let called = false;
  assert.equal((await authorize(bad, ctx("bypass"), async () => { called = true; return "pass"; })).verdict, "deny");
  assert.equal(called, false, "the judge never sees what stage 1 denied");
  assert.equal((await authorize(call, ctx("bypass"), async () => { throw new Error("down"); })).verdict, "ask", "a failing judge escalates");
});
