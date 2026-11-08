import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { IncomingMessage, ServerResponse } from "node:http";
import { accessFinding, detectAccessGate, redact, redactFindings, registerSecret, resolveAccess } from "./access.js";
import { safeFetch } from "./net.js";
import { AccessGateError, Scope } from "./scope.js";
import { ConfigSchema } from "./config.js";
import { run } from "./runner.js";
import { headers as headersCheck } from "../checks/headers.js";
import { openRedirect } from "../checks/open-redirect.js";
import { Journal } from "../agent/journal.js";
import type { Check } from "./types.js";

// The exact shape staging.scenivia.com answered with on 2026-11-08 (meta JWT shortened).
const ACCESS_302 = new Headers({
  location: "https://team.cloudflareaccess.com/cdn-cgi/access/login/staging.example.com?kid=ae09&meta=eyJ0.e30.sig&redirect_url=%2F",
  "www-authenticate": 'Cloudflare-Access resource_metadata="https://staging.example.com/.well-known/cloudflare-access-protected-resource/"',
  "set-cookie": "CF_AppSession=f9c6e42fa2386160; Path=/; Secure; HttpOnly",
});

test("detectAccessGate: each signal Access sets is recognised", () => {
  assert.match(detectAccessGate(302, ACCESS_302, "https://staging.example.com/")!, /Cloudflare-Access/);
  assert.match(detectAccessGate(302, new Headers({ location: "https://team.cloudflareaccess.com/cdn-cgi/access/login/x" }), "https://a.example.com/")!, /cloudflareaccess\.com/);
  assert.match(detectAccessGate(302, new Headers({ location: "/cdn-cgi/access/login/a.example.com?redirect_url=%2F" }), "https://a.example.com/")!, /cdn-cgi\/access\/login/);
  assert.match(detectAccessGate(302, new Headers({ "set-cookie": "CF_AppSession=abc; Path=/" }), "https://a.example.com/")!, /CF_AppSession/);
  assert.match(detectAccessGate(403, new Headers(), "https://a.example.com/", "<html>Forbidden. Cloudflare Access</html>")!, /Access page/);
  assert.match(detectAccessGate(200, new Headers(), "https://a.example.com/cdn-cgi/access/login/a.example.com")!, /login path/);
});

test("detectAccessGate: an app that talks about Access, or redirects to its own login, is not a gate", () => {
  assert.equal(detectAccessGate(200, new Headers(), "https://a.example.com/docs", "We put staging behind Cloudflare Access (cloudflareaccess.com)."), null);
  assert.equal(detectAccessGate(302, new Headers({ location: "/login?next=%2F" }), "https://a.example.com/"), null);
  assert.equal(detectAccessGate(302, new Headers({ location: "https://evil.example/cloudflareaccess.com/x" }), "https://a.example.com/"), null);
  assert.equal(detectAccessGate(403, new Headers(), "https://a.example.com/", "Forbidden"), null);
  assert.equal(detectAccessGate(200, new Headers({ "set-cookie": "CF_AppSession=x" }), "https://a.example.com/"), null);
  assert.equal(detectAccessGate(401, new Headers({ "www-authenticate": 'Bearer realm="api"' }), "https://a.example.com/"), null);
});

test("config: scope.access takes env var names only, for declared hosts only", () => {
  const ok = ConfigSchema.safeParse({ scope: { allowedHosts: ["staging.example.com"], access: { "staging.example.com": { clientIdEnv: "CF_ID", clientSecretEnv: "CF_SECRET" } } } });
  assert.equal(ok.success, true);
  const pasted = ConfigSchema.safeParse({ scope: { allowedHosts: ["staging.example.com"], access: { "staging.example.com": { clientIdEnv: "0123456789abcdef0123456789abcdef.access", clientSecretEnv: "CF_SECRET" } } } });
  assert.equal(pasted.success, false, "a Client ID pasted in place of a variable name is refused");
  const value = ConfigSchema.safeParse({ scope: { allowedHosts: ["staging.example.com"], access: { "staging.example.com": { clientIdEnv: "CF_ID", clientSecretEnv: "CF_SECRET", clientSecret: "x" } } } });
  assert.equal(value.success, false, "no field can carry a value");
  const other = ConfigSchema.safeParse({ scope: { allowedHosts: ["staging.example.com"], access: { "prod.example.com": { clientIdEnv: "CF_ID", clientSecretEnv: "CF_SECRET" } } } });
  assert.equal(other.success, false, "a host outside allowedHosts is refused");
});

test("resolveAccess: values come from the environment; an unset variable is reported, never guessed", () => {
  const r = resolveAccess({ "A.example.com": { clientIdEnv: "X_ID", clientSecretEnv: "X_SECRET" }, "b.example.com": { clientIdEnv: "Y_ID", clientSecretEnv: "Y_SECRET" } }, { X_ID: "id-aaaa.access", X_SECRET: "secret-aaaa-1234" });
  assert.deepEqual(r.headers["a.example.com"], { "CF-Access-Client-Id": "id-aaaa.access", "CF-Access-Client-Secret": "secret-aaaa-1234" });
  assert.equal(r.headers["b.example.com"], undefined);
  assert.match(r.missing["b.example.com"]!, /Y_ID and Y_SECRET not set/);
  assert.equal(redact("got secret-aaaa-1234 back"), "got secr…[redacted] back");
});

test("a finding says what to do and never claims the app was tested", () => {
  const f = accessFinding({ host: "staging.example.com", url: "https://staging.example.com/", status: 302, reason: "x", tokenSent: false });
  assert.equal(f.severity, "info");
  assert.equal(f.state, "unproven");
  assert.match(f.title, /protected by Cloudflare Access: live checks see only the login page; provide a service token/);
  const g = accessFinding({ host: "staging.example.com", url: "https://staging.example.com/", status: 302, reason: "x", tokenSent: true });
  assert.match(g.title, /service token rejected/);
});

/* ---------- live, against mocked servers ---------- */

type Handler = (q: IncomingMessage, s: ServerResponse) => void;

async function httpServer(h: Handler) {
  const http = await import("node:http");
  const server = http.createServer(h);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { port: (server.address() as AddressInfo).port, close: () => new Promise<void>((r) => server.close(() => r())) };
}

const gate: Handler = (q, s) => {
  s.writeHead(302, {
    location: `https://team.cloudflareaccess.com/cdn-cgi/access/login/${q.headers.host}?redirect_url=${encodeURIComponent(q.url ?? "/")}`,
    "www-authenticate": "Cloudflare-Access",
    "set-cookie": "CF_AppSession=abc; Path=/; Secure; HttpOnly",
    "access-control-allow-credentials": "true",
  });
  s.end("<html><head><title>302 Found</title></head></html>");
};

test("safeFetch: an Access login is 'not reached', recorded once, and the host is not hit again", async () => {
  let hits = 0;
  const srv = await httpServer((q, s) => { hits++; gate(q, s); });
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    await assert.rejects(safeFetch(`http://127.0.0.1:${srv.port}/`, scope), (e) => e instanceof AccessGateError && /Cloudflare Access/.test(e.message));
    await assert.rejects(safeFetch(`http://127.0.0.1:${srv.port}/login`, scope, { followRedirects: false }), AccessGateError);
    assert.equal(hits, 1, "the second request was not sent: the root is gated");
    assert.equal(scope.accessGates.size, 1);
  } finally { await srv.close(); }
});

test("a gate seen only on a sub-path leaves the rest of the host reachable", async () => {
  const srv = await httpServer((q, s) => { if (q.url?.startsWith("/admin")) return gate(q, s); s.writeHead(200); s.end("app"); });
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    await assert.rejects(safeFetch(`http://127.0.0.1:${srv.port}/admin`, scope), AccessGateError);
    assert.equal((await safeFetch(`http://127.0.0.1:${srv.port}/`, scope)).body, "app");
  } finally { await srv.close(); }
});

test("runner: a gated host gives ONE info lead and no header or redirect finding about Cloudflare's page", async () => {
  const srv = await httpServer(gate);
  try {
    const base = `http://127.0.0.1:${srv.port}/`;
    const config = ConfigSchema.parse({ project: "t", scope: { allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base } });
    const r = await run(config, join(tmpdir(), "crenel.config.yaml"), {}, [headersCheck, openRedirect]);
    assert.deepEqual(r.findings.map((f) => f.check), ["cloudflare-access"]);
    assert.equal(r.findings[0]!.severity, "info");
    assert.equal(r.findings[0]!.id, "cloudflare-access:127.0.0.1");
  } finally { await srv.close(); }
});

test("pacing and budget: maxRequests refuses past the cap, ratePerSec spaces requests", async () => {
  const srv = await httpServer((_q, s) => { s.writeHead(200); s.end("ok"); });
  try {
    const events: string[] = [];
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, maxRequests: 3, ratePerSec: 20, onRequest: (e) => events.push(e.refused ? "refused" : "sent") });
    const t0 = Date.now();
    for (let i = 0; i < 3; i++) await safeFetch(`http://127.0.0.1:${srv.port}/${i}`, scope);
    assert.ok(Date.now() - t0 >= 90, "three requests at 20/s take at least 100 ms");
    await assert.rejects(safeFetch(`http://127.0.0.1:${srv.port}/4`, scope), /budget exhausted/);
    assert.deepEqual(events, ["sent", "sent", "sent", "refused"]);
  } finally { await srv.close(); }
});

/* ---------- service token over https ---------- */

let tlsDir = "";
let tls: { key: Buffer; cert: Buffer } | null = null;
const prevTls = process.env["NODE_TLS_REJECT_UNAUTHORIZED"];

before(() => {
  try {
    tlsDir = mkdtempSync(join(tmpdir(), "crenel-access-"));
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", join(tlsDir, "k.pem"), "-out", join(tlsDir, "c.pem")], { stdio: "ignore" });
    tls = { key: readFileSync(join(tlsDir, "k.pem")), cert: readFileSync(join(tlsDir, "c.pem")) };
    // Test-only, this process only: the mocked https servers use a throwaway self-signed certificate.
    process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
  } catch { tls = null; }
});
after(() => {
  if (prevTls === undefined) delete process.env["NODE_TLS_REJECT_UNAUTHORIZED"]; else process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = prevTls;
  if (tlsDir) rmSync(tlsDir, { recursive: true, force: true });
});

async function httpsServer(h: Handler) {
  const https = await import("node:https");
  const server = https.createServer({ key: tls!.key, cert: tls!.cert }, h);
  // Every interface (dual stack): reached as 127.0.0.1 and as localhost, two different hosts for the scope.
  await new Promise<void>((r) => server.listen(0, r));
  return { port: (server.address() as AddressInfo).port, close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }) };
}

const ID = "0123456789abcdef0123456789abcdef.access";
const SECRET = "f".repeat(60) + "c0de";
const ENV = { CRENEL_CF_ID: ID, CRENEL_CF_SECRET: SECRET };

test("service token: sent over https to its exact host only, never on a redirect to another host, never over http", async (t) => {
  if (!tls) return t.skip("openssl not available");
  const seen: { host: string; path: string; id?: string; secret?: string }[] = [];
  const srv = await httpsServer((q, s) => {
    seen.push({ host: String(q.headers.host).replace(/:\d+$/, ""), path: q.url ?? "", id: q.headers["cf-access-client-id"] as string | undefined, secret: q.headers["cf-access-client-secret"] as string | undefined });
    if (q.url === "/hop") { s.writeHead(302, { location: `https://localhost:${(srv as { port: number }).port}/landed` }); return s.end(); }
    s.writeHead(200); s.end("app");
  });
  const plain = await httpServer((q, s) => { seen.push({ host: "plain", path: q.url ?? "", id: q.headers["cf-access-client-id"] as string | undefined }); s.writeHead(200); s.end("plain"); });
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1", "localhost"], allowPrivate: true, access: { "127.0.0.1": { clientIdEnv: "CRENEL_CF_ID", clientSecretEnv: "CRENEL_CF_SECRET" } }, env: ENV });
    await safeFetch(`https://127.0.0.1:${srv.port}/`, scope);
    await safeFetch(`https://127.0.0.1:${srv.port}/hop`, scope);
    await safeFetch(`http://127.0.0.1:${plain.port}/`, scope);
    assert.deepEqual(seen[0], { host: "127.0.0.1", path: "/", id: ID, secret: SECRET });
    assert.equal(seen[1]!.id, ID, "the first hop is the declared host");
    assert.deepEqual([seen[2]!.host, seen[2]!.id, seen[2]!.secret], ["localhost", undefined, undefined], "the redirect to another host carries no token");
    assert.deepEqual([seen[3]!.host, seen[3]!.id], ["plain", undefined], "plain http never carries the token");
  } finally { await srv.close(); await plain.close(); }
});

test("service token rejected: the lead says so; an echoed secret is redacted in findings and the journal", async (t) => {
  if (!tls) return t.skip("openssl not available");
  const srv = await httpsServer((q, s) => {
    if (q.url === "/echo") { s.writeHead(200); return s.end(`you sent ${q.headers["cf-access-client-secret"]}`); }
    gate(q, s);
  });
  const dir = mkdtempSync(join(tmpdir(), "crenel-journal-"));
  try {
    const base = `https://127.0.0.1:${srv.port}`;
    const echo: Check = {
      name: "echo", title: "echo", readOnly: true,
      async run(ctx) {
        const r = await safeFetch(`${base}/echo`, ctx.scope);
        return [{ id: "echo", check: "echo", title: r.body, severity: "low", state: "unproven", location: base, description: r.body, remediation: "", proof: { method: "m", replay: "r", evidence: r.body } }];
      },
    };
    const gated: Check = { name: "gated", title: "gated", readOnly: true, async run(ctx) { try { await safeFetch(`${base}/`, ctx.scope); } catch { /* not reached */ } return []; } };
    process.env["CRENEL_TEST_CF_ID"] = ID;
    process.env["CRENEL_TEST_CF_SECRET"] = SECRET;
    const config = ConfigSchema.parse({ project: "t", scope: { allowedHosts: ["127.0.0.1"], allowPrivate: true, access: { "127.0.0.1": { clientIdEnv: "CRENEL_TEST_CF_ID", clientSecretEnv: "CRENEL_TEST_CF_SECRET" } } } });
    const r = await run(config, join(dir, "crenel.config.yaml"), {}, [echo, gated]);
    const text = JSON.stringify(r);
    assert.ok(!text.includes(SECRET), "the secret never appears in the result");
    assert.match(text, /ffff…\[redacted\]/);
    const lead = r.findings.find((f) => f.check === "cloudflare-access")!;
    assert.match(lead.title, /service token rejected/);

    registerSecret(SECRET);
    const j = new Journal(join(dir, "run.jsonl"), "r-test");
    j.append("net", { body: `echo ${SECRET}` });
    assert.ok(!readFileSync(join(dir, "run.jsonl"), "utf8").includes(SECRET));
    assert.equal(redactFindings([{ id: "x", check: "x", title: SECRET, severity: "low", state: "unproven", location: "", description: "", remediation: "" }])[0]!.title, "ffff…[redacted]");
  } finally {
    delete process.env["CRENEL_TEST_CF_ID"]; delete process.env["CRENEL_TEST_CF_SECRET"];
    await srv.close(); rmSync(dir, { recursive: true, force: true });
  }
});
