import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { authzWrite, plannedWrites } from "./authz-write.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";
import { generateRegressionFile } from "../generate/tests.js";
import { run } from "../core/runner.js";
import { ConfigSchema } from "../core/config.js";

const USERS: Record<string, string> = { "tok-a": "t_a", "tok-b": "t_b" };

// A projects API. checkOwner: the server scopes writes to the caller's tenant.
// anonWrites: writes do not even require a token.
function api({ checkOwner = false, anonWrites = false } = {}) {
  const db: Record<string, { id: string; tenant: string; name: string; meta: { color: string } }> = {
    p_a: { id: "p_a", tenant: "t_a", name: "Alpha", meta: { color: "red" } },
    p_b: { id: "p_b", tenant: "t_b", name: "Bravo", meta: { color: "blue" } },
    d_a: { id: "d_a", tenant: "t_a", name: "tmp", meta: { color: "x" } },
    d_b: { id: "d_b", tenant: "t_b", name: "tmp", meta: { color: "x" } },
  };
  const seen: { method: string; url: string; auth?: string }[] = [];
  const srv = createServer((req: IncomingMessage, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      seen.push({ method: req.method!, url: req.url!, auth: req.headers.authorization });
      const tenant = USERS[(req.headers.authorization ?? "").replace("Bearer ", "")];
      const m = /^\/api\/projects\/([^/]+)$/.exec(req.url!);
      const send = (s: number, b: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
      if (!m) return send(404, {});
      const p = db[m[1]!];
      if (req.method === "GET") return !tenant ? send(401, {}) : p && p.tenant === tenant ? send(200, p) : send(404, {});
      if (!tenant && !anonWrites) return send(401, {});
      if (!p || (checkOwner && p.tenant !== tenant)) return send(404, {});
      if (req.method === "DELETE") { delete db[m[1]!]; return send(204, {}); }
      const body = JSON.parse(raw || "{}");
      if (req.method === "PUT") db[m[1]!] = { ...body, id: p.id, tenant: p.tenant };
      else Object.assign(p, body, { meta: { ...p.meta, ...(body.meta ?? {}) } });
      return send(200, db[m[1]!]);
    });
  });
  return { srv, db, seen };
}

async function listen(s: ReturnType<typeof api>) {
  await new Promise<void>((r) => s.srv.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(s.srv.address() as AddressInfo).port}`;
}

const ctx = (base: string, opts: Record<string, unknown>, active = true): CheckContext => ({
  scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active }),
  projectDir: ".", stagingUrl: base, log: () => {},
  options: { "authz-write": { enabled: true, accounts: { a: { token: "tok-a" }, b: { token: "tok-b" } }, ...opts } },
});
const patch = { name: "project", path: "/api/projects/:id", method: "PATCH", field: "name", victimId: "p_b", ownId: "p_a" };

test("authz-write: A changing B's object is proven by B's own read, and B's value is restored", async () => {
  const s = api(); const base = await listen(s);
  try {
    const f = await authzWrite.run(ctx(base, { targets: [patch] }));
    const proven = f.filter((x) => x.state === "proven");
    assert.deepEqual(proven.map((x) => x.id), ["authz-write:project:PATCH:p_b"]);
    assert.equal(proven[0]!.severity, "critical");
    assert.match(proven[0]!.description, /restored by B/);
    assert.equal(s.db.p_b!.name, "Bravo", "B's object is back to its old value");
    assert.equal(s.db.p_a!.name, "Alpha", "A's control object is back too");
    const receipt = f.find((x) => x.id === "authz-write:writes")!;
    assert.equal(receipt.severity, "info");
    assert.match(receipt.title, /every change restored or refused/);
    assert.match(receipt.proof!.evidence!, /PATCH .*\/api\/projects\/p_b as A/);
  } finally { s.srv.close(); }
});

test("authz-write: anonymous writes are proven separately", async () => {
  const s = api({ anonWrites: true }); const base = await listen(s);
  try {
    const ids = (await authzWrite.run(ctx(base, { targets: [patch] }))).filter((x) => x.state === "proven").map((x) => x.id);
    assert.deepEqual(ids.sort(), ["authz-write:project:PATCH:p_b", "authz-write:project:PATCH:p_b:anon"]);
    assert.equal(s.db.p_b!.name, "Bravo");
  } finally { s.srv.close(); }
});

test("authz-write: an owner-scoped API is clean, and the control proves the route works", async () => {
  const s = api({ checkOwner: true }); const base = await listen(s);
  try {
    const f = await authzWrite.run(ctx(base, { targets: [patch, { ...patch, name: "nested", field: "meta.color" }] }));
    assert.equal(f.filter((x) => x.state === "proven").length, 0);
    assert.ok(s.seen.some((r) => r.method === "PATCH" && r.url === "/api/projects/p_a"), "the control wrote A's own object");
    assert.equal(s.db.p_a!.meta.color, "red", "nested canary restored");
  } finally { s.srv.close(); }
});

test("authz-write: PUT sends the owner's object with the field changed, and nested fields work", async () => {
  const s = api(); const base = await listen(s);
  try {
    const f = await authzWrite.run(ctx(base, { targets: [{ ...patch, method: "PUT", field: "meta.color" }] }));
    assert.deepEqual(f.filter((x) => x.state === "proven").map((x) => x.id), ["authz-write:project:PUT:p_b"]);
    assert.equal(s.db.p_b!.meta.color, "blue");
    assert.equal(s.db.p_b!.name, "Bravo", "PUT kept the rest of the object");
  } finally { s.srv.close(); }
});

test("authz-write: a failing control means B's object is never touched", async () => {
  const s = api(); const base = await listen(s);
  try {
    const f = await authzWrite.run(ctx(base, { targets: [{ ...patch, field: "doesnotexist" }] }));
    assert.equal(f.filter((x) => x.state === "proven").length, 0);
    assert.ok(!s.seen.some((r) => r.method !== "GET" && r.url.endsWith("/p_b")), "no write on B's object");
  } finally { s.srv.close(); }
});

test("authz-write: DELETE only on disposable ids, proven and reported as not restored", async () => {
  const s = api(); const base = await listen(s);
  try {
    const del = { name: "scratch", path: "/api/projects/:id", method: "DELETE", victimId: "d_b", ownId: "d_a" };
    const none = await authzWrite.run(ctx(base, { targets: [del] }));
    assert.equal(none.filter((x) => x.state === "proven").length, 0);
    assert.ok(!s.seen.some((r) => r.method === "DELETE"), "not disposable: no DELETE sent");
    const f = await authzWrite.run(ctx(base, { targets: [{ ...del, disposable: true }] }));
    const p = f.find((x) => x.state === "proven")!;
    assert.equal(p.id, "authz-write:scratch:DELETE:d_b");
    assert.match(p.description, /NOT restored/);
    assert.match(f.find((x) => x.id === "authz-write:writes")!.title, /NOT restored/);
    assert.ok(s.db.p_b, "a non-disposable object is never deleted");
  } finally { s.srv.close(); }
});

test("authz-write: off unless enabled; enabled without allowActiveTesting is refused before any request", async () => {
  const s = api(); const base = await listen(s);
  try {
    const off = ctx(base, { targets: [patch] });
    (off.options["authz-write"] as Record<string, unknown>).enabled = false;
    assert.deepEqual(await authzWrite.run(off), []);
    await assert.rejects(() => authzWrite.run(ctx(base, { targets: [patch] }, false)), /allowActiveTesting is off/);
    assert.equal(s.seen.length, 0);
  } finally { s.srv.close(); }
});

test("authz-write: same identity for A and B sends nothing", async () => {
  const s = api(); const base = await listen(s);
  try {
    const c = ctx(base, { targets: [patch], accounts: { a: { token: "tok-b" }, b: { token: "tok-b" } } });
    const f = await authzWrite.run(c);
    assert.equal(f[0]!.id, "authz-write:same-identity");
    assert.equal(s.seen.length, 0);
  } finally { s.srv.close(); }
});

test("authz-write: the request budget stops the run", async () => {
  const s = api(); const base = await listen(s);
  try {
    const f = await authzWrite.run(ctx(base, { targets: [patch], maxRequests: 3 }));
    assert.equal(f.filter((x) => x.state === "proven").length, 0);
    assert.equal(s.seen.length, 0, "the budget cannot cover a write and its restore: nothing is sent");
    assert.match(f.find((x) => x.id === "authz-write:writes")!.description, /budget/);
  } finally { s.srv.close(); }
});

test("authz-write: the runner refuses it without allowActiveTesting, and default runs include it only when enabled", async () => {
  const cfg = ConfigSchema.parse({ scope: { allowedHosts: [] }, options: { "authz-write": { enabled: true } } });
  const r = await run(cfg, "x.yaml", {}, [authzWrite]);
  assert.match(r.errors[0]!.message, /not read-only and allowActiveTesting is off/);
  const { resolveChecks } = await import("../core/registry.js");
  assert.ok(resolveChecks([], cfg.options).some((c) => c.name === "authz-write"));
  assert.ok(!resolveChecks([], {}).some((c) => c.name === "authz-write"));
});

test("authz-write: the generated regression test targets the proven object; planned writes list the declared ids only", async () => {
  const s = api(); const base = await listen(s);
  try {
    const f = await authzWrite.run(ctx(base, { targets: [patch] }));
    const out = generateRegressionFile(f);
    assert.equal((out.match(/\btest\(/g) ?? []).length, 1, "the receipt gets no test");
    assert.match(out, /\/api\/projects\/p_b/);
    assert.match(out, /TOKEN_B/);
    const planned = plannedWrites({ "authz-write": { enabled: true, targets: [patch] } }, "https://staging.acme.test");
    assert.deepEqual(planned.map((p) => `${p.method} ${p.url}`), ["PATCH https://staging.acme.test/api/projects/p_a", "PATCH https://staging.acme.test/api/projects/p_b", "GET https://staging.acme.test/api/projects/p_b"]);
  } finally { s.srv.close(); }
});
