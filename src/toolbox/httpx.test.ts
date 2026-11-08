import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Scope } from "../core/scope.js";
import { REGISTRY } from "../core/registry.js";
import { validateClaim } from "../agent/validators.js";
import { gateDeterministic } from "../agent/gate.js";
import { parseHttpx } from "./adapters.js";
import { httpxArgv, httpxTargets, ToolboxOptions } from "./run.js";
import { dockerBackend } from "./backend.js";
import { dockerStatus } from "./docker.js";

const row = (o: Record<string, unknown>) => JSON.stringify(o);

test("httpx results: off-scope and failed rows dropped, plain HTTP on a non-staging declared host is a lead with a claim, a versioned Server header is info", () => {
  const scope = new Scope({ allowedHosts: ["app.example.test", "old.example.test", "staging.example.test"] });
  const out = [
    row({ url: "http://old.example.test", status_code: 200, title: "Old\u0007 admin", webserver: "nginx/1.18.0", tech: ["Nginx:1.18.0", "PHP"] }),
    row({ url: "https://app.example.test", status_code: 200, webserver: "cloudflare", tech: ["Cloudflare"] }),
    row({ url: "http://app.example.test", status_code: 301, location: "https://app.example.test/" }),
    row({ url: "http://staging.example.test", status_code: 200 }),
    row({ url: "http://evil.example/", status_code: 200, webserver: "Apache/2.4.1" }),
    row({ url: "https://old.example.test", failed: true }),
    "not json",
  ].join("\n");
  const r = parseHttpx(out, scope, "https://staging.example.test/");
  assert.equal(r.hosts.length, 4);
  assert.equal(r.skipped, 3);
  const plain = r.findings.filter((f) => f.id.includes("plain-http"));
  assert.deepEqual(plain.map((f) => f.location), ["http://old.example.test/"], "the staging host is transport's job, a redirect is fine");
  assert.equal(r.claims[0]!.class, "http.plain-served");
  const ver = r.findings.filter((f) => f.id.includes("server-version"));
  assert.equal(ver.length, 1);
  assert.equal(ver[0]!.severity, "info");
  assert.ok(r.findings.every((f) => f.state === "unproven"));
  assert.ok(!JSON.stringify(r.hosts).includes("\u0007"), "control characters stripped");
  assert.ok(!JSON.stringify([r.hosts, r.findings, r.claims]).includes("evil.example"), "nothing about an undeclared host (only in the fenced raw output)");
});

test("httpx argv: declared host names only, both schemes, through the proxy, no third-party lookups, no redirects, no path probing", () => {
  assert.deepEqual(httpxTargets(["App.Example.test", "*.example.test", "10.0.0.5", "bad host", "app.example.test"]), ["app.example.test", "10.0.0.5"]);
  const a = httpxArgv(["a.test", "b.test"], "http://crenel:t@crenel-proxy:3128", ToolboxOptions.parse({}));
  assert.equal(a[0], "httpx");
  assert.equal(a[a.indexOf("-u") + 1], "a.test,b.test");
  assert.equal(a[a.indexOf("-http-proxy") + 1], "http://crenel:t@crenel-proxy:3128");
  for (const f of ["-nf", "-duc", "-json"]) assert.ok(a.includes(f), f);
  for (const f of ["-asn", "-cdn", "-fr", "-follow-redirects", "-favicon", "-ss", "-screenshot", "-path", "-x", "-pa", "-probe-all-ips"]) assert.ok(!a.includes(f), f);
});

test("plain-http-reread: proven on a 200 over http://, not on a redirect, never off the scope", async () => {
  const srv = createServer((q, s) => {
    if (q.url === "/" && q.headers.host?.startsWith("localhost")) { s.writeHead(301, { location: "https://localhost/" }); return s.end(); }
    s.writeHead(200, { "content-type": "text/html" }); s.end("plain");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1", "localhost"], allowPrivate: true });
    const env = { scope, projectDir: ".", options: {}, checks: REGISTRY };
    const v = await validateClaim({ id: "c1", class: "http.plain-served", source: "agent", detail: { url: `http://127.0.0.1:${port}/` } }, env);
    assert.equal(v.state, "proven", v.reason);
    assert.equal(v.validator, "plain-http-reread");
    const red = await validateClaim({ id: "c2", class: "http.plain-served", source: "agent", detail: { url: `http://localhost:${port}/` } }, env);
    assert.equal(red.state, "unproven");
    assert.match(red.reason, /301/);
    const off = await validateClaim({ id: "c3", class: "http.plain-served", source: "agent", detail: { url: "http://example.com/" } }, env);
    assert.equal(off.state, "unproven");
    const https = await validateClaim({ id: "c4", class: "http.plain-served", source: "agent", detail: { url: `https://127.0.0.1:${port}/` } }, env);
    assert.equal(https.state, "unproven");
  } finally { srv.close(); }
});

test("gate: tools.httpx is a read-only network tool, undeclared hosts denied", () => {
  const scope = new Scope({ allowedHosts: ["app.example.test"] });
  const ctx = { scope, mode: "bypass" as const, grants: new Set<string>(), userRequest: "" };
  assert.equal(gateDeterministic({ tool: "tools.httpx", requests: [{ method: "GET", url: "http://app.example.test/" }] }, ctx).verdict, "allow");
  assert.equal(gateDeterministic({ tool: "tools.httpx", requests: [{ method: "GET", url: "http://other.example.test/" }] }, ctx).verdict, "deny");
});

// Real container, skipped when Docker or an image with httpx is missing.
test("httpx in the toolbox container: no DNS inside, the proxy resolves; the declared host answers, a lead proven by the re-read", async (t) => {
  const st = await dockerStatus();
  if (!st.available || !st.imagePresent || !(st.tools ?? []).includes("httpx")) { t.skip(`no image with httpx: ${st.reason ?? "rebuild with crenel tools build"}`); return; }
  const srv = createServer((_q, s) => { s.writeHead(200, { "content-type": "text/html", server: "nginx/1.18.0" }); s.end("<title>Own box</title>"); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as AddressInfo).port;
  try {
    // Declared hosts carry no port, so the backend is driven directly with the test server's host:port.
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    const o = ToolboxOptions.parse({});
    const events: { target: string; refused?: string; status?: number }[] = [];
    const r = await dockerBackend(o.image).run({
      tool: "httpx", network: true, scope, limits: { timeoutMs: 120_000, memory: "512m" }, proxy: { ratePerSec: 10, maxRequests: 50 },
      onEvent: (e) => events.push(e), build: (p) => httpxArgv([`127.0.0.1:${port}`], p.proxy, o),
    }, await dockerBackend(o.image).status());
    assert.equal(r.network, "internal+proxy");
    assert.ok(events.some((e) => e.status === 200 && e.target.includes(`:${port}`)), JSON.stringify(events).slice(0, 600) + r.stderr.slice(-400));
    const p = parseHttpx(r.stdout, scope);
    assert.ok(p.hosts.some((h) => h.status === 200 && h.server === "nginx/1.18.0" && h.title === "Own box"), r.stdout.slice(0, 600) + r.stderr.slice(-400));
  } finally { srv.close(); }
});
