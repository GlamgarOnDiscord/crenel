import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigSchema } from "../core/config.js";
import { AgentRun } from "./run.js";
import { StateStore } from "./state.js";
import { authzWrite } from "../checks/authz-write.js";

// One vulnerable PATCH route: any signed-in user changes any project.
function api() {
  const db: Record<string, { tenant: string; name: string }> = { p_a: { tenant: "t_a", name: "Alpha" }, p_b: { tenant: "t_b", name: "Bravo" } };
  const writes: string[] = [];
  const srv = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      const t = { "Bearer tok-a": "t_a", "Bearer tok-b": "t_b" }[req.headers.authorization ?? ""];
      const id = req.url!.split("/").pop()!;
      const p = db[id];
      res.setHeader("content-type", "application/json");
      if (!t || !p) { res.statusCode = t ? 404 : 401; return res.end("{}"); }
      if (req.method === "GET") { res.statusCode = p.tenant === t ? 200 : 404; return res.end(JSON.stringify(p.tenant === t ? p : {})); }
      writes.push(`${req.method} ${req.url}`);
      Object.assign(p, JSON.parse(raw || "{}"));
      res.end(JSON.stringify(p));
    });
  });
  return { srv, db, writes };
}

async function setup(mode: "ask" | "bypass", grants: string[] = []) {
  const s = api();
  await new Promise<void>((r) => s.srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(s.srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-active-"));
  const config = ConfigSchema.parse({
    project: "t", projectDir: dir,
    scope: { allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true, stagingUrl: base },
    options: {
      "authz-matrix": { accounts: { a: { token: "tok-a" }, b: { token: "tok-b" } } },
      "authz-write": { enabled: true, targets: [{ name: "project", path: "/api/projects/:id", method: "PATCH", field: "name", victimId: "p_b", ownId: "p_a" }] },
    },
  });
  const store = new StateStore(join(dir, ".crenel"));
  const run = new AgentRun({ config, configPath: join(dir, "crenel.config.yaml"), store, grants: new Set(grants), llm: null, checks: [authzWrite] }, { prompt: "/authz", mode });
  return { s, dir, store, run, close: () => { s.srv.close(); rmSync(dir, { recursive: true, force: true }); } };
}

const permissions = (run: AgentRun) => run.journal.since(0).filter((e) => e.type === "ui" && (e.data as { ev: { kind: string } }).ev.kind === "permission").map((e) => (e.data as { ev: { id: string; tool: string; requests: string[] } }).ev);

test("agent: active writes ask in ask mode even with a standing grant; a deny sends no write", async () => {
  const t = await setup("ask", ["127.0.0.1"]);
  try {
    const done = t.run.start();
    for (let i = 0; i < 200 && permissions(t.run).length === 0; i++) await new Promise((r) => setTimeout(r, 10));
    const p = permissions(t.run)[0]!;
    assert.equal(p.tool, "active.writes");
    assert.ok(p.requests.some((r) => r.startsWith("PATCH") && r.includes("/api/projects/p_b")), "the user sees the write on B's object");
    t.run.decide(p.id, "deny");
    await done;
    assert.deepEqual(t.s.writes, []);
  } finally { t.close(); }
});

test("agent: in bypass the write is sent, proven by the check's own observation, restored and stored", async () => {
  const t = await setup("bypass");
  try {
    await t.run.start();
    assert.equal(t.run.status, "done");
    const items = t.store.findings().items;
    const p = items.find((f) => f.check === "authz-write" && f.state === "proven")!;
    assert.ok(p, "proven finding stored");
    assert.equal(p.validator, "in-check-observation:authz-write");
    assert.ok(items.some((f) => f.id === "authz-write:writes"), "the receipt of writes is stored");
    assert.equal(t.s.db.p_b!.name, "Bravo", "B's object restored");
  } finally { t.close(); }
});
