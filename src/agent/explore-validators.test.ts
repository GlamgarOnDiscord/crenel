import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Scope } from "../core/scope.js";
import { controlUrl, validateClaim, type Claim, type ValidatorEnv } from "./validators.js";
import { freeArgsProblem, freeArgv } from "../toolbox/free-args.js";

// Key-shaped strings are assembled at run time, so the test file itself holds no secret a scanner would flag.
const LIVE = ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc8a1b2c3d"].join("_");
const PUBLISHABLE = ["pk", "live", "51HqLyjWDarjtT1zdp7dc8a1b2c3d"].join("_");

function target() {
  const sent: string[] = [];
  const srv = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const who = { "Bearer tok-a": "a", "Bearer tok-b": "b" }[req.headers.authorization ?? ""];
    sent.push(`${who ?? "anon"} ${u.pathname}${u.search}`);
    const json = (s: number, b: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
    // A leak on an unusual shape: /v2/w/<slug>/export.json, no owner check.
    let m = u.pathname.match(/^\/v2\/w\/([^/]+)\/export\.json$/);
    if (m) {
      if (!who) return json(401, {});
      return m[1] === "ws-b" ? json(200, { ws: "ws-b", owner: "acct_b_mk", rows: 3 }) : json(404, {});
    }
    // Public by nature: everyone, signed in or not, gets the same catalog.
    if (u.pathname.startsWith("/v2/catalog/")) return json(200, { plans: ["free", "pro"], owner: "acct_b_mk" });
    // A catch-all that echoes the path.
    if (u.pathname.startsWith("/echo/")) return json(200, { path: u.pathname, owner: "acct_b_mk" });
    m = u.pathname.match(/^\/__ops\/(dump|build)$/);
    if (m) return json(200, m[1] === "dump" ? { STRIPE_KEY: LIVE } : { stripe: PUBLISHABLE, placeholder: ["sk", "live", "xxxxxxxxxxxxxxxxxxxxxxxx"].join("_") });
    json(404, {});
  });
  return { srv, sent };
}

async function withEnv(fn: (env: ValidatorEnv, sent: string[], dir: string) => Promise<void>) {
  const t = target();
  await new Promise<void>((r) => t.srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(t.srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-gv-"));
  try {
    const env: ValidatorEnv = {
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }), projectDir: dir, stagingUrl: base, checks: [],
      options: { "authz-matrix": { accounts: { a: { token: "tok-a", marker: "acct_a_mk" }, b: { token: "tok-b", marker: "acct_b_mk" } } } },
    };
    await fn(env, t.sent, dir);
  } finally {
    t.srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

const claim = (cls: string, detail: Record<string, unknown>): Claim => ({ id: "c1", class: cls, source: "llm", detail });

test("cross-actor: A reading B's export on an undeclared route shape is proven, with controls", async () => {
  await withEnv(async (env, sent) => {
    const v = await validateClaim(claim("explore.cross-actor", { url: "/v2/w/ws-b/export.json", attacker: "a", id: "ws-b" }), env);
    assert.equal(v.state, "proven", v.reason);
    assert.equal(v.ceiling, "critical");
    assert.ok(sent.some((s) => s.startsWith("b ")), "owner baseline");
    assert.ok(sent.some((s) => s.startsWith("anon ")), "anonymous control");
    assert.ok(sent.some((s) => s.includes("crenel-nonexistent")), "control id");
  });
});

test("cross-actor: content everyone gets is public, not a leak", async () => {
  await withEnv(async (env) => {
    const v = await validateClaim(claim("explore.cross-actor", { url: "/v2/catalog/plans", attacker: "a" }), env);
    assert.equal(v.state, "unproven");
  });
});

test("cross-actor: two tokens of the same identity are refused", async () => {
  await withEnv(async (env) => {
    const opts = { "authz-matrix": { accounts: { a: { token: "same" }, b: { token: "same" } } } };
    const v = await validateClaim(claim("explore.cross-actor", { url: "/v2/w/ws-b/export.json", attacker: "a" }), { ...env, options: opts });
    assert.match(v.reason, /identical/);
  });
});

test("replay: proven only with another account's marker and controls that do not return it", async () => {
  await withEnv(async (env) => {
    const ok = await validateClaim(claim("explore.replay", { request: { url: "/v2/w/ws-b/export.json", as: "a" }, expect: { status: 200, bodyIncludes: ["acct_b_mk"] } }), env);
    assert.equal(ok.state, "proven", ok.reason);
    // Own data: replayed, but no oracle says it is a flaw.
    const own = await validateClaim(claim("explore.replay", { request: { url: "/v2/w/ws-b/export.json", as: "b" }, expect: { bodyIncludes: ["acct_b_mk"] } }), env);
    assert.equal(own.state, "unproven");
    // A catch-all answers the control path the same way.
    const echo = await validateClaim(claim("explore.replay", { request: { url: "/echo/anything", as: "a" }, expect: { bodyIncludes: ["acct_b_mk"] } }), env);
    assert.equal(echo.state, "unproven");
    assert.match(echo.reason, /control/);
    // Text the request carries is an echo.
    const refl = await validateClaim(claim("explore.replay", { request: { url: "/echo/acct_b_mk", as: "a" }, expect: { bodyIncludes: ["acct_b_mk"] } }), env);
    assert.match(refl.reason, /echo/);
    // A write is never replayed.
    const w = await validateClaim(claim("explore.replay", { request: { method: "DELETE", url: "/v2/w/ws-b/export.json", as: "a" }, expect: { bodyIncludes: ["acct_b_mk"] } }), env);
    assert.match(w.reason, /write/);
    // A status alone proves nothing.
    const st = await validateClaim(claim("explore.replay", { request: { url: "/v2/w/ws-b/export.json", as: "a" }, expect: { status: 200 } }), env);
    assert.match(st.reason, /status alone/);
  });
});

test("secret-in-response: a live secret key is proven and masked; a publishable key or a placeholder is not", async () => {
  await withEnv(async (env) => {
    const v = await validateClaim(claim("explore.secret", { request: { url: "/__ops/dump" } }), env);
    assert.equal(v.state, "proven", v.reason);
    assert.equal(v.ceiling, "critical");
    assert.ok(!JSON.stringify(v).includes(LIVE), "the key never appears whole in the verdict");
    const d = await validateClaim(claim("explore.secret", { request: { url: "/__ops/build" } }), env);
    assert.equal(d.state, "unproven");
  });
});

test("file-match: a quote in a project file is found; paths outside the project are not read", async () => {
  await withEnv(async (env, _sent, dir) => {
    writeFileSync(join(dir, "server.ts"), 'app.get("/__ops/dump", (req, res) => res.json(process.env));\n');
    mkdirSync(join(dir, "sub"));
    symlinkSync("/etc/hostname", join(dir, "sub", "link"));
    const ok = await validateClaim(claim("explore.file-match", { file: "server.ts", text: "res.json(process.env)", line: 1 }), env);
    assert.equal(ok.state, "proven");
    assert.equal(ok.ceiling, "medium");
    for (const file of ["../../etc/passwd", "/etc/passwd", "sub/link"]) {
      const v = await validateClaim(claim("explore.file-match", { file, text: "root:x:0:0:root" }), env);
      assert.equal(v.state, "unproven", file);
    }
  });
});

test("controlUrl replaces the id in the path or the query, else the last segment", () => {
  assert.match(controlUrl("http://h/v2/w/ws-b/export.json", "ws-b"), /\/v2\/w\/crenel-nonexistent-[0-9a-f]+\/export\.json$/);
  assert.match(controlUrl("http://h/rpc/x?statement=stm_b_19", "stm_b_19"), /statement=crenel-nonexistent-/);
  assert.match(controlUrl("http://h/__ops/dump"), /\/__ops\/crenel-nonexistent-/);
});

test("free toolbox arguments: proxy, output, local code, off-scope URLs and paths are refused; Crenel's flags come last", () => {
  const scope = new Scope({ allowedHosts: ["staging.acme.test"] });
  for (const bad of [["-proxy", "http://x:1"], ["-p", "http://x:1"], ["-o", "/tmp/x"], ["--output=/etc/x"], ["-code"], ["-lfa"], ["-itags", "dos"], ["-etags", ""], ["-tags", "intrusive"],
    ["-u", "https://evil.example/"], ["-t", "/etc/passwd"], ["-H", "x: ../../etc"], ["-rl", "9999"], ["-headless"], ["-u", "file:///etc/passwd"]]) {
    assert.ok(freeArgsProblem("nuclei", bad, scope), `nuclei ${bad.join(" ")} should be refused`);
  }
  assert.equal(freeArgsProblem("nuclei", ["-tags", "exposure,panel", "-severity", "high", "-u", "https://staging.acme.test/"], scope), null);
  assert.equal(freeArgsProblem("katana", ["-d", "3", "-H", "X-Test: 1"], scope), null);
  assert.ok(freeArgsProblem("trufflehog", ["--only-verified"], scope));
  const argv = freeArgv("nuclei", ["-tags", "exposure"], { proxy: "http://px:1", projectRoot: "/project", templatesDir: "/opt/t" }, { ratePerSec: 3, target: "https://staging.acme.test/" });
  assert.equal(argv[argv.indexOf("-proxy") + 1], "http://px:1");
  assert.ok(argv.includes("-etags"));
  assert.ok(argv.indexOf("-proxy") > argv.indexOf("-tags"));
});

// --- explore.injection: a server with a real boolean-SQLi param and a reflected-XSS param ---
test("explore.injection proves boolean SQLi and reflected XSS, denies a static param", async () => {
  const srv = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const q = u.searchParams.get("q") ?? "";
    const name = u.searchParams.get("name") ?? "";
    const send = (b: string) => { res.writeHead(200, { "content-type": "text/html" }); res.end(b); };
    if (u.pathname === "/search") {
      // boolean-SQLi mock: a truthy tautology returns the full list (like no filter), a falsy one returns none.
      if (/OR '1'='1/.test(q)) return send("<ul><li>alice</li><li>bob</li><li>carol</li></ul>");
      if (/AND '1'='2/.test(q)) return send("<ul></ul>");
      return send("<ul><li>alice</li><li>bob</li><li>carol</li></ul>"); // baseline (q=1) returns all
    }
    if (u.pathname === "/greet") return send(`<h1>Hello ${name}</h1>`); // reflects unescaped -> XSS
    if (u.pathname === "/static") return send("<h1>Welcome</h1>"); // ignores params
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-inj-"));
  try {
    const env: ValidatorEnv = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }), projectDir: dir, stagingUrl: base, checks: [], options: {} };
    const mk = (detail: Record<string, unknown>): Claim => ({ id: "c", class: "explore.injection", source: "llm", detail });

    const sqli = await validateClaim(mk({ url: "/search", param: "q", value: "1" }), env);
    assert.equal(sqli.state, "proven", sqli.reason);
    assert.match(sqli.reason, /SQL injection/);

    const xss = await validateClaim(mk({ url: "/greet", param: "name", value: "bob" }), env);
    assert.equal(xss.state, "proven", xss.reason);
    assert.match(xss.reason, /XSS/);

    const stat = await validateClaim(mk({ url: "/static", param: "q", value: "1" }), env);
    assert.equal(stat.state, "unproven", "a param the server ignores must never be proven");
  } finally {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- explore.injection over GraphQL: a field arg that reflects unescaped (XSS) ---
test("explore.injection proves injection through a GraphQL argument", async () => {
  const srv = createServer((req, res) => {
    if (req.method !== "POST") { res.writeHead(404); res.end(); return; }
    let body = ""; req.on("data", (c) => (body += c)); req.on("end", () => {
      let q = ""; try { q = JSON.parse(body).query ?? ""; } catch {}
      // naive backend: echoes the greet() argument straight into HTML (reflected XSS).
      const m = q.match(/greet\(name:\s*"([^"]*)"\)/);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: { greet: `<p>Hi ${m ? m[1] : "?"}</p>` } }));
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-gql-"));
  try {
    const env: ValidatorEnv = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }), projectDir: dir, stagingUrl: base, checks: [], options: {} };
    const claim: Claim = { id: "g", class: "explore.injection", source: "llm", detail: { url: "/graphql", gql: '{ greet(name: "__INJECT__") }' } };
    const v = await validateClaim(claim, env);
    assert.equal(v.state, "proven", v.reason);
    assert.match(v.reason, /XSS/);
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});

// --- explore.injection: OS command injection (server runs the shell arithmetic) ---
test("explore.injection proves OS command injection via a shell-evaluated arithmetic", async () => {
  const srv = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const host = u.searchParams.get("host") ?? "";
    // vulnerable: concatenates host into a shell command; emulate the shell evaluating $((7*7)).
    // Do NOT reflect raw input (avoid an incidental XSS match); only the shell path yields output.
    let out = "PING: host is up";
    const m = host.match(/echo (cr[0-9a-f]+)\$\(\(7\*7\)\)/);
    if (m) out = `PING\n${m[1]}49\n`; // the shell computed the arithmetic
    res.writeHead(200, { "content-type": "text/plain" }); res.end(out);
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-cmd-"));
  try {
    const env: ValidatorEnv = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }), projectDir: dir, stagingUrl: base, checks: [], options: {} };
    const claim: Claim = { id: "cmd", class: "explore.injection", source: "llm", detail: { url: "/ping", param: "host", value: "127.0.0.1" } };
    const v = await validateClaim(claim, env);
    assert.equal(v.state, "proven", v.reason);
    assert.match(v.reason, /command injection/i);
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});

// --- explore.ssrf: out-of-band proof via a server that fetches the injected URL ---
test("explore.ssrf proves SSRF out-of-band and denies a param the server does not fetch", async () => {
  const srv = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const target = u.searchParams.get("url");
    if (u.pathname === "/fetch" && target) {
      // vulnerable: server-side fetch of the attacker-supplied URL
      fetch(target).then(() => { res.writeHead(200); res.end("fetched"); }).catch(() => { res.writeHead(200); res.end("err"); });
      return;
    }
    res.writeHead(200); res.end("ignored"); // /safe ignores the param
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-ssrf-"));
  try {
    const env: ValidatorEnv = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }), projectDir: dir, stagingUrl: base, checks: [], options: { explore: { ssrfCallbackHost: "127.0.0.1" } } };
    const mk = (path: string): Claim => ({ id: "s", class: "explore.ssrf", source: "llm", detail: { url: path, param: "url", callbackHost: "127.0.0.1" } });

    const vuln = await validateClaim(mk("/fetch"), env);
    assert.equal(vuln.state, "proven", vuln.reason);
    assert.match(vuln.reason, /SSRF/);

    const safe = await validateClaim(mk("/safe"), env);
    assert.equal(safe.state, "unproven", "a param the server never fetches must not be proven");
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});

// --- explore.stored-xss: stored then served unescaped ---
test("explore.stored-xss proves stored XSS and denies an escaped sink", async () => {
  let stored = "";
  const srv = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    if (req.method === "POST" && u.pathname === "/comment") { let b=""; req.on("data",c=>b+=c); req.on("end",()=>{ const p=new URLSearchParams(b); stored=p.get("text")??""; res.writeHead(200); res.end("saved"); }); return; }
    if (u.pathname === "/wall") { res.writeHead(200,{"content-type":"text/html"}); res.end(`<div>${stored}</div>`); return; }       // unescaped
    if (u.pathname === "/wall-safe") { res.writeHead(200,{"content-type":"text/html"}); res.end(`<div>${stored.replace(/</g,"&lt;")}</div>`); return; } // escaped
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-sx-"));
  try {
    const env: ValidatorEnv = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true, stagingUrl: base }), projectDir: dir, stagingUrl: base, checks: [], options: {} };
    const mk = (ret: string): Claim => ({ id: "x", class: "explore.stored-xss", source: "llm", detail: { storeUrl: "/comment", storeParam: "text", storeWhere: "body", retrieveUrl: ret } });
    const proven = await validateClaim(mk("/wall"), env);
    assert.equal(proven.state, "proven", proven.reason);
    assert.match(proven.reason, /Stored XSS/);
    const safe = await validateClaim(mk("/wall-safe"), env);
    assert.equal(safe.state, "unproven", "escaped sink must not be proven");
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});

// --- explore.lfi: path traversal returns /etc/passwd content ---
test("explore.lfi proves path traversal and denies a param that ignores it", async () => {
  const { readFileSync } = await import("node:fs");
  const srv = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const f = u.searchParams.get("file") ?? "";
    if (u.pathname === "/download") {
      // vulnerable: strips nothing, reads the path (simulate /etc/passwd)
      if (/etc\/passwd/.test(f.replace(/%2f/gi,"/").replace(/\.\.\//g,"../"))) { res.writeHead(200); res.end("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"); return; }
      res.writeHead(200); res.end("not found"); return;
    }
    res.writeHead(200); res.end("static"); // /safe ignores file
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-lfi-"));
  try {
    const env: ValidatorEnv = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }), projectDir: dir, stagingUrl: base, checks: [], options: {} };
    const mk = (p: string): Claim => ({ id: "l", class: "explore.lfi", source: "llm", detail: { url: p, param: "file" } });
    const vuln = await validateClaim(mk("/download"), env);
    assert.equal(vuln.state, "proven", vuln.reason);
    assert.match(vuln.reason, /traversal/i);
    const safe = await validateClaim(mk("/safe"), env);
    assert.equal(safe.state, "unproven", "a param the server ignores must not be proven");
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});

// --- explore.jwt-none: server accepts an unsigned alg:none token ---
test("explore.jwt-none proves broken JWT verification, denies a server that rejects none", async () => {
  const b64=(o:unknown)=>Buffer.from(JSON.stringify(o)).toString("base64url");
  const validJwt=`${b64({alg:"HS256",typ:"JWT"})}.${b64({sub:"u1",role:"user"})}.sig`;
  const mkSrv=(acceptNone:boolean)=>createServer((req,res)=>{
    const auth=(req.headers.authorization??"").replace("Bearer ","");
    const parts=auth.split(".");
    if(parts.length<2){res.writeHead(401);res.end("no token");return;}
    let alg="";try{alg=JSON.parse(Buffer.from(parts[0]!,"base64url").toString()).alg;}catch{}
    if(alg==="none"&&!acceptNone){res.writeHead(401);res.end("none rejected");return;}
    res.writeHead(200);res.end("welcome "+(()=>{try{return JSON.parse(Buffer.from(parts[1]!,"base64url").toString()).sub;}catch{return"?";}})());
  });
  for(const [accept,expect] of [[true,"proven"],[false,"unproven"]] as const){
    const srv=mkSrv(accept); await new Promise<void>(r=>srv.listen(0,"127.0.0.1",r));
    const base=`http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    const dir=mkdtempSync(join(tmpdir(),"crenel-jwt-"));
    try{
      const env:ValidatorEnv={scope:new Scope({allowedHosts:["127.0.0.1"],allowPrivate:true,stagingUrl:base}),projectDir:dir,stagingUrl:base,checks:[],options:{}};
      const v=await validateClaim({id:"j",class:"explore.jwt-none",source:"llm",detail:{url:"/me",token:validJwt}},env);
      assert.equal(v.state,expect,`accept=${accept}: ${v.reason}`);
    } finally { srv.close(); rmSync(dir,{recursive:true,force:true}); }
  }
});

test("mass-assignment: a vulnerable update binds the privileged field (proven), a safe one stays a lead", async () => {
  for (const vulnerable of [true, false]) {
    // Per-actor state; GET reads it, PUT binds body fields (all when vulnerable, only `name` when safe).
    const state: Record<string, unknown> = { name: "a", role: "user" };
    const srv = createServer((req, res) => {
      const who = req.headers.authorization === "Bearer tok-a" ? "a" : null;
      const u = new URL(req.url!, "http://x");
      const json = (s: number, b: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
      if (!who) return json(401, {});
      if (u.pathname !== "/profile") return json(404, {});
      if (req.method === "GET") return json(200, state);
      let chunks = ""; req.on("data", (c) => (chunks += c)); req.on("end", () => {
        let body: Record<string, unknown> = {}; try { body = JSON.parse(chunks || "{}"); } catch { /* ignore */ }
        if (vulnerable) Object.assign(state, body);
        else if (typeof body.name === "string") state.name = body.name; // whitelist: role is never bound
        json(200, state);
      });
      return undefined;
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    const dir = mkdtempSync(join(tmpdir(), "crenel-ma-"));
    try {
      const env: ValidatorEnv = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base, allowActiveTesting: true }),
        projectDir: dir, stagingUrl: base, checks: [],
        options: { "authz-matrix": { accounts: { a: { token: "tok-a" } } } },
      };
      const v = await validateClaim(claim("explore.mass-assignment", { url: "/profile", field: "role", value: "admin", update: { name: "a2" }, as: "a" }), env);
      if (vulnerable) { assert.equal(v.state, "proven", v.reason); assert.equal(v.ceiling, "medium"); assert.equal(state.role, "admin"); }
      else { assert.equal(v.state, "unproven", v.reason); assert.equal(state.role, "user"); }
    } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
  }
});

test("mass-assignment: without active mode it refuses", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-ma2-"));
  try {
    const env: ValidatorEnv = {
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: "http://127.0.0.1:1" }),
      projectDir: dir, stagingUrl: "http://127.0.0.1:1", checks: [],
      options: { "authz-matrix": { accounts: { a: { token: "tok-a" } } } },
    };
    const v = await validateClaim(claim("explore.mass-assignment", { url: "/profile", field: "role", value: "admin", as: "a" }), env);
    assert.equal(v.state, "unproven");
    assert.match(v.reason, /active/i);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("cors: a server reflecting any origin with credentials is proven; a fixed allowlist is not", async () => {
  for (const vulnerable of [true, false]) {
    const srv = createServer((req, res) => {
      const origin = req.headers.origin as string | undefined;
      const h: Record<string, string> = { "content-type": "application/json" };
      if (origin) {
        h["access-control-allow-origin"] = vulnerable ? origin : "https://trusted.app"; // reflect vs fixed
        h["access-control-allow-credentials"] = "true";
      }
      res.writeHead(200, h); res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    const dir = mkdtempSync(join(tmpdir(), "crenel-cors-"));
    try {
      const env: ValidatorEnv = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }),
        projectDir: dir, stagingUrl: base, checks: [], options: {},
      };
      const v = await validateClaim(claim("explore.cors", { url: "/api" }), env);
      if (vulnerable) { assert.equal(v.state, "proven", v.reason); assert.equal(v.ceiling, "high"); }
      else assert.equal(v.state, "unproven", v.reason);
    } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
  }
});

test("cross-actor: an endpoint public to anon that carries the owner's marker escalates to a proven anonymous leak", async () => {
  // /obj/:id returns B's object (with B's marker) to EVERYONE incl. anon; a non-existent id -> 404.
  // Claimed as attacker A, the validator must escalate to a proven broken-authentication leak (anon).
  const srv = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const json = (s: number, b: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
    const m = u.pathname.match(/^\/obj\/([^/]+)$/);
    if (!m) return json(404, {});
    return m[1] === "6" ? json(200, { id: 6, owner: "acct_b_mk", item: "seat" }) : json(404, {});
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-anon-"));
  try {
    const env: ValidatorEnv = {
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }),
      projectDir: dir, stagingUrl: base, checks: [],
      options: { "authz-matrix": { accounts: { a: { token: "tok-a", marker: "acct_a_mk" }, b: { token: "tok-b", marker: "acct_b_mk" } } } },
    };
    const v = await validateClaim(claim("explore.cross-actor", { url: "/obj/6", attacker: "a", owner: "b", id: "6" }), env);
    assert.equal(v.state, "proven", v.reason);
    assert.equal(v.ceiling, "critical");
    assert.match(v.reason, /no token at all/i);
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});
