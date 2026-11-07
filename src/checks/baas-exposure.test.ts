import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { baasExposure, extractBaas } from "./baas-exposure.js";
import { exposedSecrets } from "./exposed-secrets.js";
import { generateRegressionFile } from "../generate/tests.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (payload: object) => `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64(payload)}.c2lnbmF0dXJlX2Zha2U`;
const ANON = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon", iat: 1, exp: 9999999999 });
const SERVICE = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role", iat: 1, exp: 9999999999 });

function ctx(projectDir: string, scope = new Scope({ allowedHosts: [] })): CheckContext {
  return { scope, projectDir, options: {}, log: () => {} };
}

function withDir(files: Record<string, string>, fn: (dir: string) => Promise<void>) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), "crenel-baas-"));
    try {
      for (const [n, c] of Object.entries(files)) writeFileSync(join(dir, n), c);
      await fn(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

// A fake PostgREST: `profiles` has no RLS (returns a row), `notes` has RLS
// (returns []), and every request must carry the anon key. Records every
// request so the test can assert we never wrote and never asked for more than
// one row.
function fakePostgrest(): Promise<{ server: Server; url: string; seen: { method: string; url: string }[] }> {
  const seen: { method: string; url: string }[] = [];
  const server = createServer((req, res) => {
    seen.push({ method: req.method!, url: req.url! });
    if (req.headers.apikey !== ANON) { res.writeHead(401).end("{}"); return; }
    const u = new URL(req.url!, "http://x");
    if (u.pathname === "/rest/v1/") {
      res.writeHead(200, { "content-type": "application/openapi+json" }).end(JSON.stringify({
        paths: { "/": {}, "/profiles": {}, "/notes": {}, "/rpc/do_thing": {} },
        definitions: { profiles: { properties: { id: {}, email: {}, full_name: {} } }, notes: { properties: { id: {}, body: {} } } },
      }));
      return;
    }
    if (u.pathname === "/rest/v1/profiles") {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify([{ id: 1, email: "victim@example.com", full_name: "V" }]));
      return;
    }
    if (u.pathname === "/rest/v1/notes") { res.writeHead(200, { "content-type": "application/json" }).end("[]"); return; }
    res.writeHead(404).end("{}");
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => {
    const port = (server.address() as { port: number }).port;
    resolve({ server, url: `http://127.0.0.1:${port}`, seen });
  }));
}

test("extracts a hosted Supabase URL with its anon key, matched by the ref claim", () => {
  const hits = extractBaas(`const s = createBrowserClient("https://abcdefghijklmnopqrst.supabase.co", "${ANON}")`, "app.js");
  const s = hits.find((h) => h.kind === "supabase");
  assert.ok(s && s.kind === "supabase");
  assert.equal(s.url, "https://abcdefghijklmnopqrst.supabase.co");
  assert.equal(s.keyKind, "anon-jwt");
});

test("a publishable key and a Firebase config are found; a service_role JWT is not an anon pair", () => {
  const hits = extractBaas([
    'const a = "https://qwertyuiopasdfghjklz.supabase.co"; const k = "sb_publishable_ABCDEFGHIJKLMNOPQRSTUV";',
    `const fb = { apiKey: "AIza${"x".repeat(35)}", authDomain: "demo.firebaseapp.com", projectId: "demo-app", databaseURL: "https://demo-app-default-rtdb.firebaseio.com" };`,
    `const admin = "${SERVICE}";`,
  ].join("\n"), "app.js");
  assert.ok(hits.some((h) => h.kind === "supabase" && h.keyKind === "publishable"));
  const fb = hits.find((h) => h.kind === "firebase");
  assert.ok(fb && fb.kind === "firebase" && fb.projectId === "demo-app" && fb.databaseURL?.includes("firebaseio.com"));
  assert.ok(!hits.some((h) => h.kind === "supabase" && h.key === SERVICE));
});

test("offline: a Supabase pair is a medium lead that says to check RLS, nothing proven", withDir(
  { "app.js": `createClient("https://abcdefghijklmnopqrst.supabase.co", "${ANON}")` },
  async (dir) => {
    const found = await baasExposure.run(ctx(dir));
    assert.equal(found.length, 1);
    assert.equal(found[0]!.state, "unproven");
    assert.equal(found[0]!.severity, "medium");
    assert.match(found[0]!.title, /RLS/);
    assert.ok(!found[0]!.description.includes(ANON), "the key is redacted");
  },
));

test("exposed-secrets: service_role JWT and sb_secret_ are critical and proven; anon JWT and Firebase apiKey are not secrets", withDir(
  { "app.js": [`const a="${ANON}";`, `const s="${SERVICE}";`, 'const t="sb_secret_ABCDEFGHIJKLMNOPQRSTUVWX";',
    `const fb={apiKey:"AIza${"y".repeat(35)}",authDomain:"demo.firebaseapp.com",projectId:"demo-app"};`].join("\n") },
  async (dir) => {
    const found = await exposedSecrets.run(ctx(dir));
    const ids = found.map((f) => f.id.split(":")[1]);
    assert.ok(ids.includes("supabase-service-role"));
    assert.ok(ids.includes("supabase-secret-key"));
    assert.equal(found.filter((f) => f.id.includes("supabase-service-role")).length, 1, "the anon JWT is not flagged");
    assert.ok(!ids.includes("google-api-key"), "a Firebase web apiKey is public by design");
    for (const f of found.filter((x) => x.id.includes("supabase"))) { assert.equal(f.state, "proven"); assert.equal(f.severity, "critical"); }
  },
));

test("live: needs allowActiveTesting; without it no request is sent", async () => {
  const pg = await fakePostgrest();
  const dir = mkdtempSync(join(tmpdir(), "crenel-baas-"));
  try {
    writeFileSync(join(dir, "app.js"), `createClient("${pg.url}", "${ANON}")`);
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    const found = await baasExposure.run(ctx(dir, scope));
    assert.equal(pg.seen.length, 0);
    assert.equal(found[0]!.state, "unproven");
  } finally {
    pg.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("live: a table without RLS is proven, one with RLS is not, reads are GET limit=1, content never kept", async () => {
  const pg = await fakePostgrest();
  const dir = mkdtempSync(join(tmpdir(), "crenel-baas-"));
  try {
    writeFileSync(join(dir, "app.js"), `createClient("${pg.url}", "${ANON}")`);
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true });
    const found = await baasExposure.run(ctx(dir, scope));
    const proven = found.filter((f) => f.state === "proven");
    assert.equal(proven.length, 1);
    assert.match(proven[0]!.title, /profiles/);
    assert.equal(proven[0]!.severity, "critical", "an email column makes it critical");
    assert.ok(pg.seen.every((r) => r.method === "GET"), "never writes");
    assert.ok(pg.seen.filter((r) => r.url.includes("/rest/v1/") && r.url !== "/rest/v1/").every((r) => r.url.includes("limit=1")));
    assert.ok(!pg.seen.some((r) => r.url.includes("rpc")), "never calls RPC functions");
    const text = JSON.stringify(found);
    assert.ok(!text.includes("victim@example.com"), "row content is never stored");
    const file = generateRegressionFile(found);
    assert.match(file, /the table profiles is not readable with the anon key/);
  } finally {
    pg.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Firestore collection names are read from the client code", async () => {
  const { firestoreCollections } = await import("./baas-exposure.js");
  const dir = mkdtempSync(join(tmpdir(), "crenel-fs-"));
  writeFileSync(join(dir, "app.js"), 'getDocs(collection(db, "invoices"));getDoc(doc(db, "users", uid));firebase.firestore().collection("orders").get();');
  try { assert.deepEqual(firestoreCollections(dir).sort(), ["invoices", "orders", "users"]); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});

test("Firebase: a listable Storage bucket and the default RTDB instance are proven by GET; a protected bucket is not", async () => {
  const { storageBuckets, rtdbUrls } = await import("./baas-exposure.js");
  assert.deepEqual(storageBuckets({ projectId: "demo-app" }), ["demo-app.appspot.com", "demo-app.firebasestorage.app"]);
  assert.deepEqual(rtdbUrls({ projectId: "demo-app" }), ["https://demo-app-default-rtdb.firebaseio.com"]);
  const dir = mkdtempSync(join(tmpdir(), "crenel-fbs-"));
  writeFileSync(join(dir, "app.js"), `const fb={apiKey:"AIza${"z".repeat(35)}",authDomain:"demo.firebaseapp.com",projectId:"demo-app",storageBucket:"demo-app.firebasestorage.app"};`);
  const seen: string[] = [];
  const real = globalThis.fetch;
  let open = true;
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    seen.push(`${init?.method ?? "GET"} ${url}`);
    if (url.startsWith("https://firebasestorage.googleapis.com/v0/b/demo-app.firebasestorage.app/o?maxResults=1"))
      return new Response(open ? JSON.stringify({ items: [{ name: "avatars/u1.png", bucket: "x" }] }) : JSON.stringify({ error: { code: 403 } }), { status: open ? 200 : 403 });
    if (url === "https://demo-app-default-rtdb.firebaseio.com/.json?shallow=true") return new Response(open ? '{"users":true}' : '{"error":"Permission denied"}', { status: open ? 200 : 401 });
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
  try {
    const scope = new Scope({ allowedHosts: ["firebasestorage.googleapis.com", "demo-app-default-rtdb.firebaseio.com"], allowPrivate: true, allowActiveTesting: true });
    const found = await baasExposure.run(ctx(dir, scope));
    const ids = found.filter((f) => f.state === "proven").map((f) => f.id).sort();
    assert.deepEqual(ids, ["baas-exposure:firebase-rtdb:https://demo-app-default-rtdb.firebaseio.com", "baas-exposure:firebase-storage:demo-app.firebasestorage.app"]);
    assert.ok(!JSON.stringify(found).includes("avatars/u1.png"), "object names are never kept");
    assert.ok(seen.every((s) => s.startsWith("GET ")));
    open = false;
    const closed = await baasExposure.run(ctx(dir, scope));
    assert.equal(closed.filter((f) => f.state === "proven").length, 0);
  } finally { globalThis.fetch = real; rmSync(dir, { recursive: true, force: true }); }
});
