import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { supabaseRpc, extractRpcCalls, readRpcAnswer } from "./supabase-rpc.js";
import { Scope } from "../core/scope.js";

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const ANON = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64({ iss: "supabase", ref: "rpcbench", role: "anon", iat: 1, exp: 9999999999 })}.c2lnbmF0dXJlX2Zha2U`;

test("extractRpcCalls: names and whether arguments are passed", () => {
  const c = extractRpcCalls(`a.rpc("search_users")\nb.rpc('get_stats', { day: 1 })\nc.rpc(name)`, "x.js");
  assert.deepEqual(c.map((x) => [x.name, x.withArgs, x.line]), [["search_users", false, 1], ["get_stats", true, 2]]);
});

test("readRpcAnswer: rows, scalars, empty, refused, 405 write, missing args", () => {
  assert.deepEqual(readRpcAnswer(200, '[{"id":1,"email":"x"}]', false), { kind: "data", rows: 1, columns: ["id", "email"], scalar: false });
  assert.deepEqual(readRpcAnswer(200, "42", false), { kind: "data", rows: 1, columns: [], scalar: true });
  assert.equal(readRpcAnswer(200, "[]", false).kind, "empty");
  assert.equal(readRpcAnswer(200, "null", false).kind, "empty");
  assert.equal(readRpcAnswer(401, "", false).kind, "refused");
  assert.equal(readRpcAnswer(405, '{"code":"25006"}', false).kind, "writes");
  assert.equal(readRpcAnswer(404, '{"code":"PGRST202"}', false).kind, "needs-args");
});

async function setup(fn: (base: string, dir: string, seen: string[]) => Promise<void>) {
  const seen: string[] = [];
  const srv = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    const j = (s: number, b: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
    if (req.headers.apikey !== ANON) return j(401, { message: "No API key found in request" });
    const name = req.url!.replace("/rest/v1/rpc/", "");
    if (name === "search_users") return j(200, [{ id: 1, email: "b@example.com" }]);
    if (name === "my_orders") return j(200, []);
    if (name === "log_visit") return j(405, { code: "25006", message: "cannot execute INSERT in a read-only transaction" });
    j(404, { code: "PGRST202" });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-rpc-"));
  writeFileSync(join(dir, "app.js"), `const s = createClient("${base}", "${ANON}");\ns.rpc("search_users");\ns.rpc("my_orders");\ns.rpc("log_visit");\ns.rpc("needs_args", { id });\ns.rpc("send_invite");\n`);
  try { await fn(base, dir, seen); } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("supabase-rpc: an open function is proven (with the no-key control), a write is undetermined, an empty answer is nothing; GET only", () =>
  setup(async (_base, dir, seen) => {
    const f = await supabaseRpc.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true }), projectDir: dir, options: {}, log: () => {} });
    const byId = Object.fromEntries(f.map((x) => [x.id.split(":").pop(), x]));
    assert.deepEqual(Object.keys(byId).sort(), ["log_visit", "search_users"]);
    assert.equal(byId.search_users!.state, "proven");
    assert.equal(byId.search_users!.severity, "critical");
    assert.equal(byId.log_visit!.state, "unproven");
    assert.ok(seen.every((s) => s.startsWith("GET ")));
    assert.ok(!seen.some((s) => s.includes("send_invite")), "side-effect names are never called");
    assert.ok(!f.some((x) => /b@example\.com/.test(JSON.stringify(x))), "the row is never kept");
  }));

test("supabase-rpc: without active testing, one lead and no request", () =>
  setup(async (_base, dir, seen) => {
    const f = await supabaseRpc.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: dir, options: {}, log: () => {} });
    assert.equal(f.length, 1);
    assert.equal(f[0]!.state, "unproven");
    assert.equal(seen.length, 0);
  }));
