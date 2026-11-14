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
import { installSafeFetchTestTransport } from "../core/net.js";
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

test("ai-infra: an MCP server handing out an SSE session without auth is proven, without waiting for the stream to end", async () => {
  const { srv, base } = await serve((req, res) => {
    if (req.url === "/sse") { res.writeHead(200, { "content-type": "text/event-stream" }); res.write("event: endpoint\ndata: /messages?sessionId=abc123def456\n\n"); return; } // never ends
    res.writeHead(404); res.end();
  });
  try {
    const t0 = Date.now();
    const found = await aiInfra.run(ctx(base));
    assert.deepEqual(found.map((f) => f.id.replace(base, "")), ["ai-infra:/sse"]);
    assert.ok(Date.now() - t0 < 5000);
  } finally { srv.closeAllConnections(); srv.close(); }
});

test("auth-config: Better Auth's OpenAPI reference published is a low finding", async () => {
  const { authConfig } = await import("./auth-config.js");
  const { srv, base } = await serve((req, res) => { if (req.url === "/api/auth/reference") { res.writeHead(200); return res.end('<script id="api-reference" data-url="/api/auth/open-api/generate-schema"></script><!-- scalar -->'); } res.writeHead(404); res.end(); });
  try { assert.deepEqual((await authConfig.run(ctx(base))).map((f) => f.id), ["auth-config:better-auth-openapi:/api/auth/reference"]); }
  finally { srv.close(); }
});

test("auth-variants: /dashboard redirects, /dashboard.rsc is served; an app that refuses every spelling is clean", async () => {
  const { authVariants } = await import("./auth-variants.js");
  const page = "<html>" + "Revenue for every customer. ".repeat(5) + "</html>";
  const leaky = await serve((req, res) => {
    if (req.url === "/dashboard") { res.writeHead(307, { location: "/login" }); return res.end(); }
    if (req.url === "/dashboard.rsc") { res.writeHead(200); return res.end(page); }
    res.writeHead(404); res.end();
  });
  const strict = await serve((req, res) => { if (req.url?.toLowerCase().includes("dashboard")) { res.writeHead(401); return res.end(); } res.writeHead(404); res.end(); });
  try {
    assert.deepEqual((await authVariants.run(ctx(leaky.base))).map((f) => f.id), ["auth-variants:/dashboard:trailing .rsc"]);
    assert.equal((await authVariants.run(ctx(strict.base))).length, 0);
  } finally { leaky.srv.close(); strict.srv.close(); }
});

test("auth-variants: a trailing-slash normalization redirect is not a bypass", async () => {
  const { authVariants } = await import("./auth-variants.js");
  const { srv, base } = await serve((req, res) => {
    if (req.url === "/dashboard") { res.writeHead(308, { location: "/dashboard/" }); return res.end(); }
    if (req.url === "/dashboard/") { res.writeHead(200); return res.end("<html>" + "public landing ".repeat(10) + "</html>"); }
    res.writeHead(404); res.end();
  });
  try { assert.equal((await authVariants.run(ctx(base))).length, 0); } finally { srv.close(); }
});

test("ai-infra: an MCP server over Streamable HTTP that answers an anonymous initialize is proven; one that asks for a token is not", async () => {
  const seen: string[] = [];
  const { srv, base } = await serve((req, res) => {
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      if (req.method === "POST") seen.push(`${req.url} ${JSON.parse(b).method}`);
      if (req.url === "/api/mcp") { res.writeHead(401); return res.end(); }
      if (req.url !== "/mcp" || req.method !== "POST") { res.writeHead(404); return res.end(); }
      const m = JSON.parse(b).method;
      if (m === "initialize") { res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "s1" }); return res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-06-18", serverInfo: { name: "x" }, capabilities: {} } })); }
      if (m === "tools/list" && req.headers["mcp-session-id"] === "s1") { res.writeHead(200, { "content-type": "text/event-stream" }); return res.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: 2, result: { tools: [{ name: "run_sql" }, { name: "send_email" }] } })}\n\n`); }
      res.writeHead(400); res.end();
    });
  });
  try {
    const found = (await aiInfra.run(ctx(base))).filter((f) => f.id.endsWith("mcp"));
    assert.deepEqual(found.map((f) => f.id.replace(base, "")), ["ai-infra:/mcp"]);
    assert.match(found[0]!.description, /2 tool\(s\) listed/);
    assert.ok(seen.every((s) => /initialize|tools\/list/.test(s)), seen.join(", "));
  } finally { srv.close(); }
});

test("ai-infra: a Langflow version is checked against OSV (PyPI) when osv is on; a bare {version} JSON is never taken for Flowise", async () => {
  const { aiInfra, serviceVersions } = await import("./ai-infra.js");
  const real = globalThis.fetch;
  const osvBodies: string[] = [];
  let flowisePing = true;
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const j = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
    if (url === "https://api.osv.dev/v1/querybatch") { osvBodies.push(String(init?.body)); return j({ results: [{ vulns: [{ id: "GHSA-test-lf01" }] }] }); }
    if (url.startsWith("https://api.osv.dev/v1/vulns/")) return j({ summary: "Unauthenticated code execution", aliases: ["CVE-0000-0001"], database_specific: { severity: "CRITICAL" } });
    if (url === "https://lf.acme.test/api/v1/version") return j({ version: "1.8.0", main_version: "1.8.0", package: "Langflow" });
    if (url === "https://fw.acme.test/api/v1/version") return j({ version: "3.0.4" });
    if (url === "https://fw.acme.test/api/v1/ping") return new Response(flowisePing ? "pong" : "<html>", { status: 200 });
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  try {
    const scope = new Scope({ allowedHosts: ["lf.acme.test", "fw.acme.test", "api.osv.dev"], allowPrivate: true });
    installSafeFetchTestTransport(scope, { resolver: async () => [{ address: "127.0.0.1", family: 4 }], fetch: globalThis.fetch });
    const c = (u: string) => ({ scope, projectDir: ".", stagingUrl: u, options: { "dependency-risk": { osv: true } }, log: () => {} });
    const f = (await aiInfra.run(c("https://lf.acme.test"))).filter((x) => x.id.startsWith("ai-infra:advisory:"));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.state, "unproven");
    assert.equal(f[0]!.severity, "critical");
    assert.match(f[0]!.title, /^Langflow at lf\.acme\.test: langflow@1\.8\.0 is affected by GHSA-test-lf01/);
    assert.match(osvBodies[0]!, /"ecosystem":"PyPI"/);
    assert.deepEqual((await serviceVersions("https://fw.acme.test", c("https://fw.acme.test"))).map((s) => `${s.service}@${s.version}`), ["Flowise@3.0.4"]);
    flowisePing = false;
    assert.deepEqual(await serviceVersions("https://fw.acme.test", c("https://fw.acme.test")), []);
    const off = await aiInfra.run({ ...c("https://lf.acme.test"), options: {} });
    assert.equal(off.filter((x) => x.id.includes("advisory")).length, 0, "no OSV, no version probe");
  } finally { globalThis.fetch = real; }
});
