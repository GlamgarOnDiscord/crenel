import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { devServer } from "./dev-server.js";
import { aiInfra } from "./ai-infra.js";
import { vercelPreview } from "./vercel-preview.js";
import { cacheDeception } from "./cache-deception.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

async function serve(h: (req: IncomingMessage, res: ServerResponse) => void) {
  const srv = createServer(h);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return { srv, base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` };
}
const ctx = (stagingUrl: string, over: Partial<CheckContext> = {}, active = false): CheckContext =>
  ({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active }), projectDir: ".", stagingUrl, options: {}, log: () => {}, ...over });

test("dev-server: the Vite client runtime is proven; an SPA fallback is not", async () => {
  const a = await serve((req, res) => { res.writeHead(req.url === "/@vite/client" ? 200 : 404); res.end(req.url === "/@vite/client" ? "import { createHotContext } from '/@vite/env'" : ""); });
  const b = await serve((_q, res) => { res.writeHead(200); res.end("<!doctype html><div id=app>"); });
  try {
    assert.deepEqual((await devServer.run(ctx(a.base))).map((f) => f.id), ["dev-server:/@vite/client"]);
    assert.equal((await devServer.run(ctx(b.base))).length, 0);
  } finally { a.srv.close(); b.srv.close(); }
});

test("ai-infra: an open Ollama and Qdrant are proven by their inventory; a 401 is not", async () => {
  const { srv, base } = await serve((req, res) => {
    const j = (b: unknown) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
    if (req.url === "/api/tags") return j({ models: [{ name: "llama3" }] });
    if (req.url === "/collections") return j({ result: { collections: [{ name: "docs" }] }, status: "ok" });
    if (req.url === "/v1/models") { res.writeHead(401); return res.end(); }
    res.writeHead(404); res.end();
  });
  try {
    const ids = (await aiInfra.run(ctx(base))).map((f) => f.id.replace(base, ""));
    assert.deepEqual(ids.sort(), ["ai-infra:/api/tags", "ai-infra:/collections"]);
  } finally { srv.close(); }
});

test("vercel-preview: an undeclared preview host found in the code is a lead, never requested", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-vercel-"));
  writeFileSync(join(dir, "README.md"), "Preview: https://acme-git-feature-x-acme-team.vercel.app\n");
  try {
    const found = await vercelPreview.run({ scope: new Scope({ allowedHosts: [] }), projectDir: dir, options: {}, log: () => {} });
    assert.equal(found.length, 1);
    assert.equal(found[0]!.state, "unproven");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("cache-deception: a cache keyed by extension serves B's object to anyone; needs active testing", async () => {
  const cache = new Map<string, string>();
  const { srv, base } = await serve((req, res) => {
    const u = req.url ?? "";
    if (/\.css(\?|$)/.test(u) && cache.has(u)) { res.writeHead(200, { "x-cache": "HIT" }); return res.end(cache.get(u)); }
    const m = /^\/api\/projects\/(proj_b_1)/.exec(u);
    if (!m) { res.writeHead(404); return res.end(); }
    if (req.headers.authorization !== "Bearer tok-b") { res.writeHead(401); return res.end(); }
    const body = JSON.stringify({ id: "proj_b_1", owner: "org_b" });
    if (/\.css(\?|$)/.test(u)) cache.set(u, body); // the CDN stores it
    res.writeHead(200); res.end(body);
  });
  const options = { "authz-matrix": { resources: [{ name: "project", path: "/api/projects/:id" }], accounts: { b: { token: "tok-b", marker: "org_b", owns: { project: ["proj_b_1"] } } } } };
  try {
    assert.equal((await cacheDeception.run(ctx(base, { options }, false))).length, 0, "off without active testing");
    const found = await cacheDeception.run(ctx(base, { options }, true));
    assert.equal(found.length, 1);
    assert.equal(found[0]!.severity, "critical");
  } finally { srv.close(); }
});
