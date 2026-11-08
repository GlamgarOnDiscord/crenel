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
