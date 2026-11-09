import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startServer } from "./http.js";
import { uidOf } from "../agent/state.js";

// Console routes that only keep bookkeeping (archive, feedback, ignore) and
// the SARIF export of the console's findings.
async function boot() {
  const dir = mkdtempSync(join(tmpdir(), "crenel-console-"));
  const cfg = join(dir, "crenel.config.yaml");
  writeFileSync(cfg, `project: t\nprojectDir: .\nscope:\n  allowedHosts: [127.0.0.1]\nchecks: []\n`);
  const state = join(dir, ".crenel");
  mkdirSync(state, { recursive: true });
  const id = "exposed-secrets:stripe:dist/app.js:5";
  writeFileSync(join(state, "findings.json"), JSON.stringify({ checksRun: ["exposed-secrets"], items: [{
    id, uid: uidOf(id), check: "exposed-secrets", title: "Stripe secret key in the client bundle", severity: "critical", state: "proven",
    location: "dist/app.js:5", firstSeen: "2026-11-01T00:00:00Z", lastSeen: "2026-11-01T00:00:00Z", run: "r-x", notes: [],
  }] }));
  const srv = await startServer({ configPath: cfg, port: 0, token: "tk", webDir: null, llm: "off", claudeAvailable: false, checks: [] });
  const H = { authorization: "Bearer tk", "content-type": "application/json" };
  return {
    srv, uid: uidOf(id),
    post: (p: string, body: unknown) => fetch(`${srv.url}${p}`, { method: "POST", headers: H, body: JSON.stringify(body) }),
    get: (p: string) => fetch(`${srv.url}${p}`, { headers: H }),
    close: async () => { await srv.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

test("ignoring a finding marks it in /api/state with its reason, and it can be undone", async () => {
  const c = await boot();
  try {
    assert.equal((await c.post(`/api/findings/${c.uid}/ignore`, { ignored: true, reason: "clé de test révoquée" })).status, 200);
    let st = await (await c.get("/api/state")).json() as { findings: { uid: string; ignored?: { reason: string } }[] };
    assert.equal(st.findings[0]?.ignored?.reason, "clé de test révoquée");
    assert.equal((await c.post(`/api/findings/${c.uid}/ignore`, { ignored: false })).status, 200);
    st = await (await c.get("/api/state")).json() as typeof st;
    assert.equal(st.findings[0]?.ignored, undefined);
    assert.equal((await c.post(`/api/findings/f-nope/ignore`, { ignored: true })).status, 404);
    const audit = await (await c.get("/api/audit")).json() as { kind: string }[];
    assert.deepEqual(audit.filter((e) => e.kind.startsWith("finding-")).map((e) => e.kind), ["finding-ignored", "finding-unignored"]);
  } finally { await c.close(); }
});

test("GET /api/sarif is the scan's SARIF for the console's findings", async () => {
  const c = await boot();
  try {
    const res = await c.get("/api/sarif");
    assert.equal(res.status, 200);
    const sarif = await res.json() as { version: string; runs: { results: { ruleId: string }[] }[] };
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0]?.results.length, 1);
    assert.match(sarif.runs[0]!.results[0]!.ruleId, /exposed-secrets/);
  } finally { await c.close(); }
});

test("a run can be archived and rated; the rating goes to the audit log", async () => {
  const c = await boot();
  try {
    const { id } = await (await c.post("/api/runs", { prompt: "bonjour", mode: "readonly" })).json() as { id: string };
    assert.equal((await c.post(`/api/runs/${id}/archive`, { archived: true })).status, 200);
    let st = await (await c.get("/api/state")).json() as { runs: { id: string; archived: boolean }[] };
    assert.equal(st.runs.find((r) => r.id === id)?.archived, true);
    await c.post(`/api/runs/${id}/archive`, { archived: false });
    st = await (await c.get("/api/state")).json() as typeof st;
    assert.equal(st.runs.find((r) => r.id === id)?.archived, false);
    assert.equal((await c.post(`/api/runs/${id}/feedback`, { useful: "yes" })).status, 400);
    assert.equal((await c.post(`/api/runs/${id}/feedback`, { useful: true })).status, 200);
    const audit = await (await c.get("/api/audit")).json() as { kind: string; run?: string; useful?: boolean }[];
    assert.deepEqual(audit.filter((e) => e.kind === "run-feedback").map((e) => [e.run, e.useful]), [[id, true]]);
    assert.equal((await c.post(`/api/runs/r-nope/archive`, { archived: true })).status, 404);
  } finally { await c.close(); }
});
