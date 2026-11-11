import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { extractSession, isJwt } from "./session.js";
import { authzMatrix } from "./authz-matrix.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub, exp: Math.floor(Date.now() / 1000) + 60 })}.c2lnbmF0dXJlLXg`;
const answer = (status: number, body: string, setCookie: string[] = []) => {
  const headers = new Headers({ "content-type": "application/json" });
  for (const c of setCookie) headers.append("set-cookie", c);
  return { status, headers, body };
};

test("isJwt: three base64url parts whose header is JSON with alg", () => {
  assert.ok(isJwt(jwt("u1")));
  assert.ok(!isJwt("aaaaaaaaaa.bbbbbbbbbb.cccc"), "a dotted string whose header is not JSON");
  assert.ok(!isJwt("not a token"));
});

test("extractSession: a JWT anywhere in the JSON, a conventional key, a declared path, the cookies set", () => {
  const t = jwt("u1");
  assert.deepEqual(extractSession(answer(200, JSON.stringify({ message: "ok", auth_token: t }))), { token: t });
  assert.deepEqual(extractSession(answer(200, JSON.stringify({ data: { session: { value: t } } }))), { token: t }, "nested, any key");
  assert.deepEqual(extractSession(answer(200, JSON.stringify({ access_token: "opaque-0123456789abcdef" }))), { token: "opaque-0123456789abcdef" });
  assert.deepEqual(extractSession(answer(200, JSON.stringify({ r: { k: "opaque-0123456789abcdef" } }), []), "r.k"), { token: "opaque-0123456789abcdef" });
  assert.deepEqual(extractSession(answer(302, "", ["sid=abc123; Path=/; HttpOnly", "old=; Max-Age=0", "x=gone; Expires=Thu, 01 Jan 1970 00:00:00 GMT"])), { cookie: "sid=abc123" });
});

test("extractSession: a failed login, or an answer with no token and no cookie, is no session", () => {
  assert.equal(extractSession(answer(401, JSON.stringify({ token: jwt("u1") }))), null, "a 401 carries no session even with a token-shaped field");
  assert.equal(extractSession(answer(200, JSON.stringify({ message: "Successfully logged in.", status: "success" }))), null);
  assert.equal(extractSession(answer(200, JSON.stringify({ token: "short" }))), null, "a short value is not a token");
  assert.equal(extractSession(answer(200, "<html>welcome</html>")), null);
});

// A login-gated API: JWTs from POST /login (or a cookie session from /login-form), notes owned per user.
// `safe` checks ownership; otherwise any logged-in user reads any note (BOLA). Anonymous is always refused.
function app(safe: boolean): Promise<{ base: string; srv: Server }> {
  const users: Record<string, string> = { alice: "pw-alice", bob: "pw-bob" };
  const notes: Record<string, { owner: string; text: string }> = { "note_a_1": { owner: "alice", text: "alice-private" }, "note_b_1": { owner: "bob", text: "bob-secret-canary" } };
  const sessions: Record<string, string> = {};
  const srv = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      const send = (s: number, o: unknown, h: Record<string, string> = {}) => { res.writeHead(s, { "content-type": "application/json", ...h }); res.end(JSON.stringify(o)); };
      const u = new URL(req.url!, "http://x");
      if (req.method === "POST" && (u.pathname === "/login" || u.pathname === "/login-form")) {
        const body = u.pathname === "/login" ? JSON.parse(raw || "{}") : Object.fromEntries(new URLSearchParams(raw));
        if (users[body.username] !== body.password) return send(401, { error: "bad credentials" });
        if (u.pathname === "/login") return send(200, { message: "ok", auth_token: jwt(body.username) });
        const sid = `s-${body.username}-${Math.random().toString(36).slice(2)}`;
        sessions[sid] = body.username;
        return send(302, {}, { location: "/", "set-cookie": `sid=${sid}; Path=/; HttpOnly` });
      }
      const m = /^\/api\/notes\/([^/]+)$/.exec(u.pathname);
      if (req.method === "GET" && m) {
        const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
        const sid = /(?:^|; )sid=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
        const who = bearer ? JSON.parse(Buffer.from(bearer.split(".")[1]!, "base64url").toString()).sub : sid ? sessions[sid] : undefined;
        if (!who) return send(401, { error: "login required" });
        const n = notes[decodeURIComponent(m[1]!)];
        if (!n || (safe && n.owner !== who)) return send(404, { error: "not found" });
        return send(200, { id: m[1], owner: n.owner, text: n.text });
      }
      send(404, { error: "not found" });
    });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, srv })));
}

const env = { CRENEL_TEST_PW_A: "pw-alice", CRENEL_TEST_PW_B: "pw-bob", CRENEL_TEST_PW_BAD: "wrong" };
function options(loginPath: string, format: "json" | "form", pwA = "CRENEL_TEST_PW_A") {
  return {
    "authz-matrix": {
      resources: [{ name: "note", path: "/api/notes/:id" }],
      accounts: {
        a: { label: "A", login: { url: loginPath, username: "alice", passwordEnv: pwA, format } },
        b: { label: "B", login: { url: loginPath, username: "bob", passwordEnv: "CRENEL_TEST_PW_B", format }, owns: { note: ["note_b_1"] }, marker: "bob-secret-canary" },
      },
    },
  };
}
async function run(base: string, opts: Record<string, unknown>): Promise<{ id: string; state: string }[]> {
  const logs: string[] = [];
  const ctx: CheckContext = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true }), projectDir: "/tmp/x", stagingUrl: base, options: opts, log: (m) => logs.push(m) };
  Object.assign(process.env, env);
  try { return await authzMatrix.run(ctx); } finally { for (const k of Object.keys(env)) delete process.env[k]; }
}
const proven = (f: { state: string }[]) => f.filter((x) => x.state === "proven");

test("authz-matrix behind a login: a fresh JWT session per account proves the BOLA", async () => {
  const { base, srv } = await app(false);
  try { assert.equal(proven(await run(base, options("/login", "json"))).length, 1); } finally { srv.close(); }
});

test("authz-matrix behind a login: a cookie session (302 + Set-Cookie, form post) proves the BOLA", async () => {
  const { base, srv } = await app(false);
  try { assert.equal(proven(await run(base, options("/login-form", "form"))).length, 1); } finally { srv.close(); }
});

test("authz-matrix behind a login: an app that checks ownership proves nothing (negative control)", async () => {
  const { base, srv } = await app(true);
  try { assert.equal(proven(await run(base, options("/login", "json"))).length, 0); } finally { srv.close(); }
});

test("authz-matrix behind a login: a failed login of A sends no probe as A and proves nothing", async () => {
  const { base, srv } = await app(false);
  try { assert.equal(proven(await run(base, options("/login", "json", "CRENEL_TEST_PW_BAD"))).length, 0); } finally { srv.close(); }
});

test("authz-matrix: a declared login needs active testing (it is a POST)", async () => {
  const ctx: CheckContext = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: "/tmp/x", stagingUrl: "http://127.0.0.1:9", options: options("/login", "json"), log: () => {} };
  await assert.rejects(authzMatrix.run(ctx), /allowActiveTesting is off/);
});
