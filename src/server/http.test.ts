import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";
import { startServer, type CrenelServer } from "./http.js";
import { startDemoTarget, DEMO_TOKENS, type DemoTarget } from "../testing/demo-target.js";
import { exposedSecrets } from "../checks/exposed-secrets.js";
import { exposedFiles } from "../checks/exposed-files.js";
import type { Check } from "../core/types.js";
import { headers } from "../checks/headers.js";
import { readJournal, verifyJournal } from "../agent/journal.js";

// fetch() drops a custom Host header, so the rebinding test goes through node:http.
function rawStatus(base: string, path: string, headers: Record<string, string>): Promise<number> {
  const u = new URL(base);
  return new Promise((ok, ko) => {
    const req = request({ host: u.hostname, port: u.port, path, headers }, (res) => { res.resume(); ok(res.statusCode ?? 0); });
    req.on("error", ko);
    req.end();
  });
}

interface Ctx { dir: string; srv: CrenelServer; target: DemoTarget; cfgPath: string }

function configYaml(target: string, o: { active?: boolean } = {}) {
  return `project: test app
projectDir: ./dist
scope:
  allowedHosts: [127.0.0.1]
  allowActiveTesting: ${o.active ?? true}
  allowPrivate: true
  stagingUrl: ${target}/
checks: []
options:
  authz-matrix:
    resources:
      - { name: project, path: /api/projects/:id, methods: [GET, DELETE] }
      - { name: render, path: /api/renders/:id }
    accounts:
      a: { token: ${DEMO_TOKENS.a} }
      b: { token: ${DEMO_TOKENS.b}, marker: acct_b, owns: { project: [proj_b_1], render: [rnd_b_1] } }
`;
}

async function setup(o: { active?: boolean; servesEnv?: boolean; checks?: Check[] } = {}): Promise<Ctx> {
  const dir = mkdtempSync(join(tmpdir(), "crenel-srv-"));
  const target = await startDemoTarget({ servesEnv: o.servesEnv });
  mkdirSync(join(dir, "dist"));
  writeFileSync(join(dir, "dist", "app.js"), 'const k = "sk_live_ABCDEFGHIJKLMNOP1234";\n');
  const cfgPath = join(dir, "crenel.config.yaml");
  writeFileSync(cfgPath, configYaml(target.url, o));
  const srv = await startServer({ configPath: cfgPath, port: 0, token: "test-token", webDir: null, llm: "off", checks: o.checks ?? [exposedSecrets, headers] });
  return { dir, srv, target, cfgPath };
}
async function teardown(c: Ctx) {
  await c.srv.close();
  await c.target.close();
  rmSync(c.dir, { recursive: true, force: true });
}

const H = { authorization: "Bearer test-token", "content-type": "application/json" };
const api = (c: Ctx, path: string, init: RequestInit = {}) => fetch(c.srv.url + path, { ...init, headers: { ...H, ...(init.headers as Record<string, string> | undefined) } });
const post = (c: Ctx, path: string, body: unknown) => api(c, path, { method: "POST", body: JSON.stringify(body) });

/** Follow a run's SSE stream until eof; call onEvent for each journal entry. */
async function follow(c: Ctx, id: string, onEvent: (type: string, data: any) => Promise<void> | void = () => {}, timeoutMs = 20_000) {
  const res = await api(c, `/api/runs/${id}/events`, { signal: AbortSignal.timeout(timeoutMs) });
  const reader = res.body!.getReader();
  const types: string[] = [];
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += new TextDecoder().decode(value);
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, i);
      buf = buf.slice(i + 2);
      const type = chunk.match(/^event: (.*)$/m)?.[1];
      const data = chunk.match(/^data: (.*)$/m)?.[1];
      if (!type) continue;
      types.push(type);
      if (type === "eof") return types;
      await onEvent(type, JSON.parse(data!).data);
    }
  }
  return types;
}

test("the API is locked: token, Host header, JSON writes, same-origin writes", async () => {
  const c = await setup();
  try {
    assert.equal((await fetch(c.srv.url + "/api/state")).status, 401);
    assert.equal((await fetch(c.srv.url + "/api/state", { headers: { authorization: "Bearer wrong" } })).status, 401);
    assert.equal(await rawStatus(c.srv.url, "/api/state", { host: "evil.example", authorization: "Bearer test-token" }), 421, "DNS rebinding");
    assert.equal((await api(c, "/api/runs", { method: "POST", body: "prompt=x", headers: { "content-type": "text/plain" } })).status, 415);
    assert.equal((await api(c, "/api/runs", { method: "POST", body: "{}", headers: { origin: "http://evil.example" } })).status, 403);
    // The printed link trades the token for an HttpOnly, SameSite=Strict cookie.
    const link = await fetch(c.srv.url + "/?token=test-token", { redirect: "manual" });
    assert.equal(link.status, 302);
    const set = link.headers.get("set-cookie") ?? "";
    assert.match(set, /HttpOnly/);
    assert.match(set, /SameSite=Strict/);
    assert.equal((await fetch(c.srv.url + "/api/state", { headers: { cookie: set.split(";")[0]! } })).status, 200);
  } finally { await teardown(c); }
});

test("ask mode: a probe waits for approval; Deny sends nothing to the target", async () => {
  const c = await setup();
  try {
    const { id } = await (await post(c, "/api/runs", { prompt: "/authz", mode: "ask" })).json() as { id: string };
    let asked = 0;
    await follow(c, id, async (type, d) => {
      if (type === "ui" && d.ev.kind === "permission") {
        asked++;
        assert.ok(d.ev.requests.every((r: string) => r.startsWith("GET")), "the DELETE method is never even proposed");
        await post(c, `/api/runs/${id}/decision`, { id: d.ev.id, decision: "deny" });
      }
    });
    assert.equal(asked, 1);
    assert.equal(c.target.seen.length, 0, "nothing reached the target");
    const entries = readJournal(join(c.dir, ".crenel", "runs", `${id}.jsonl`));
    assert.equal(verifyJournal(entries).ok, true);
    assert.ok(entries.some((e) => e.type === "decision" && (e.data as { decision: string }).decision === "deny"));
  } finally { await teardown(c); }
});

test("ask mode: Allow once runs the matrix and the validator proves the cross-tenant read", async () => {
  const c = await setup();
  try {
    const { id } = await (await post(c, "/api/runs", { prompt: "Prouve que le compte A ne lit pas les données du compte B", mode: "ask" })).json() as { id: string };
    await follow(c, id, async (type, d) => {
      if (type === "ui" && d.ev.kind === "permission") await post(c, `/api/runs/${id}/decision`, { id: d.ev.id, decision: "once" });
    });
    const state = await (await api(c, "/api/state")).json() as any;
    const authz = state.findings.filter((f: any) => f.check === "authz-matrix");
    assert.ok(authz.some((f: any) => f.state === "proven" && f.title.includes("project")), JSON.stringify(authz.map((f: any) => [f.title, f.state, f.verdict])));
    assert.ok(!authz.some((f: any) => f.state === "proven" && f.title.includes("render")), "isolated route not reported");
    assert.equal(state.authz.actors.find((a: any) => a.id === "a").cells.project, 200);
    assert.ok(c.target.seen.every((r) => r.method === "GET"), "only GET ever sent");
    assert.equal(state.audit.filter((a: any) => a.kind === "probe-unattended").length, 0, "approved probes are not 'unattended'");
  } finally { await teardown(c); }
});

test("the stop button really stops: a waiting run ends stopped and nothing is sent", async () => {
  const c = await setup();
  try {
    const { id } = await (await post(c, "/api/runs", { prompt: "/authz", mode: "ask" })).json() as { id: string };
    const types = await follow(c, id, async (type, d) => {
      if (type === "ui" && d.ev.kind === "permission") await post(c, `/api/runs/${id}/stop`, {});
    });
    assert.ok(types.includes("stop"));
    const run = await (await api(c, `/api/runs/${id}`)).json() as any;
    assert.equal(run.status, "stopped");
    assert.equal(c.target.seen.length, 0);
  } finally { await teardown(c); }
});

test("bypass: no question, every probe in the audit log, and the perimeter still blocks", async () => {
  const c = await setup();
  try {
    const { id } = await (await post(c, "/api/runs", { prompt: "/scan", mode: "bypass" })).json() as { id: string };
    const types = await follow(c, id);
    assert.ok(!types.includes("decision"));
    const state = await (await api(c, "/api/state")).json() as any;
    const unattended = state.audit.filter((a: any) => a.kind === "probe-unattended");
    assert.equal(unattended.length, c.target.seen.length, "one audit line per request sent");
    assert.ok(c.target.seen.length > 0);
    assert.ok(c.target.seen.every((r) => r.method === "GET"), "DELETE declared in the config was never sent");
  } finally { await teardown(c); }

  // Same bypass run, active testing off in the config: the matrix is refused before sending.
  const off = await setup({ active: false });
  try {
    const { id } = await (await post(off, "/api/runs", { prompt: "/authz", mode: "bypass" })).json() as { id: string };
    await follow(off, id);
    assert.equal(off.target.seen.filter((r) => r.url.startsWith("/api/")).length, 0);
  } finally { await teardown(off); }
});

test("goals: a goal that needs a code fix stalls; a stopped goal stops", async () => {
  const c = await setup();
  try {
    const { id } = await (await post(c, "/api/goals", { text: "prouver l'isolation entre comptes sur toutes les ressources", mode: "bypass", budget: { maxIterations: 4 } })).json() as { id: string };
    const goal: string[] = [];
    await follow(c, id, (type, d) => { if (type.startsWith("goal.")) goal.push(type === "goal.end" ? `end:${d.outcome}` : type); });
    assert.equal(goal[0], "goal.start");
    assert.equal(goal.at(-1), "end:stalled", goal.join(","));
    const list = await (await api(c, "/api/goals")).json() as any[];
    assert.equal(list[0].goal.status, "stalled");

    const g2 = await (await post(c, "/api/goals", { text: "aucun finding critique prouvé", mode: "ask" })).json() as { id: string };
    const ends: string[] = [];
    await follow(c, g2.id, async (type, d) => {
      if (type === "ui" && d.ev.kind === "permission") await post(c, `/api/goals/${g2.id}/stop`, {});
      if (type === "goal.end") ends.push(d.outcome);
    });
    assert.deepEqual(ends, ["stopped"]);
  } finally { await teardown(c); }
});

test("config and targets: invalid YAML is refused, adding a host needs the owner declaration", async () => {
  const c = await setup();
  try {
    const before = readFileSync(c.cfgPath, "utf8");
    assert.equal((await api(c, "/api/config", { method: "PUT", body: JSON.stringify({ text: "scope:\n  allowedHosts: ['']\n" }) })).status, 422);
    assert.equal(readFileSync(c.cfgPath, "utf8"), before);
    assert.equal((await post(c, "/api/targets", { host: "staging.example.com" })).status, 400);
    const ok = await (await post(c, "/api/targets", { host: "https://staging.example.com/app", owner: true })).json() as any;
    assert.deepEqual(ok.scope.allowedHosts, ["127.0.0.1", "staging.example.com"]);
    assert.match(readFileSync(c.cfgPath, "utf8"), /staging\.example\.com/);
    const del = await (await api(c, "/api/targets/staging.example.com", { method: "DELETE" })).json() as any;
    assert.deepEqual(del.scope.allowedHosts, ["127.0.0.1"]);
  } finally { await teardown(c); }
});

test("a full scan runs the live-site checks under the gate, and the replay validator proves a served .env", async () => {
  const c = await setup({ servesEnv: true, checks: [exposedSecrets, headers, exposedFiles] });
  try {
    const { id } = await (await post(c, "/api/runs", { prompt: "/scan", mode: "bypass" })).json() as { id: string };
    await follow(c, id);
    const state = await (await api(c, "/api/state")).json() as any;
    const env = (state.findings?.items ?? state.findings ?? []).find((f: any) => f.id === "exposed-files:/.env");
    assert.ok(env, "the served .env is a finding");
    assert.equal(env.state, "proven", "replayed through the staging URL, it stays proven");
    assert.ok(c.target.seen.every((r) => r.method === "GET"));
  } finally { await teardown(c); }
});

test("toolbox backend: PUT /api/toolbox switches docker <-> wsl in the YAML, validated; GET reports the WSL status", async () => {
  const c = await setup();
  const prev = process.env.CRENEL_WSL;
  process.env.CRENEL_WSL = join(c.dir, "no-wsl-here");
  try {
    const put = (body: unknown) => api(c, "/api/toolbox", { method: "PUT", body: JSON.stringify(body) });
    assert.equal((await put({ backend: "podman" })).status, 400);
    const before = readFileSync(c.cfgPath, "utf8");
    assert.equal((await put({ backend: "wsl", distro: "kali; rm -rf /" })).status, 422);
    assert.equal(readFileSync(c.cfgPath, "utf8"), before, "an invalid distro never reaches the file");
    const ok = await (await put({ backend: "wsl" })).json() as any;
    assert.equal(ok.options.backend, "wsl");
    assert.match(readFileSync(c.cfgPath, "utf8"), /toolbox:\n\s+backend: wsl/);
    const st = await (await api(c, "/api/toolbox")).json() as any;
    assert.equal(st.backend, "wsl");
    assert.equal(st.ready, false);
    assert.match(st.reason, /WSL is not installed/);
    assert.equal((await (await put({ backend: "docker" })).json() as any).options.backend, "docker");
  } finally {
    if (prev === undefined) delete process.env.CRENEL_WSL; else process.env.CRENEL_WSL = prev;
    await teardown(c);
  }
});
