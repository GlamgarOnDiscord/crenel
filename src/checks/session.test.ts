import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { extractSession, isJwt, jwtSub, listedIds, mentions } from "./session.js";
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
  const users: Record<string, string> = { alice: "pw-alice", bobbie: "pw-bob" };
  const notes: Record<string, { owner: string; text: string }> = { "note_a_1": { owner: "alice", text: "alice-private" }, "note_b_1": { owner: "bobbie", text: "bob-secret-canary" },
    "note_c_1": { owner: "bobbie2", text: "another tenant" }, "note_a_2": { owner: "alice", text: "shared with bobbie" } };
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
      const authed = /^Bearer /.test(req.headers.authorization ?? "") || /sid=/.test(req.headers.cookie ?? "");
      // A global listing (every tenant's ids): being listed says nothing about ownership.
      if (req.method === "GET" && u.pathname === "/api/notes") return authed ? send(200, { notes: Object.keys(notes).map((id) => ({ id, title: "note" })) }) : send(401, {});
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
        b: { label: "B", login: { url: loginPath, username: "bobbie", passwordEnv: "CRENEL_TEST_PW_B", format }, owns: { note: ["note_b_1"] }, marker: "bob-secret-canary" },
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
const proven = <F extends { state: string }>(f: F[]) => f.filter((x) => x.state === "proven");

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

test("listedIds, jwtSub, mentions: the pieces of listing discovery", () => {
  assert.deepEqual(listedIds(JSON.stringify({ Books: [{ book_title: "t1" }, { book_title: "t2", nested: { book_title: 3 } }, { book_title: "t1" }] }), "book_title"), ["t1", "t2", "3"]);
  assert.deepEqual(listedIds("not json", "id"), []);
  assert.equal(jwtSub(jwt("bobbie")), "bobbie");
  assert.equal(jwtSub("opaque-token"), undefined);
  assert.ok(mentions('{"owner":"bobbie"}', "bobbie"));
  assert.ok(!mentions('{"owner":"bobbie2"}', "bobbie"), "a longer name is not the account");
  assert.ok(!mentions('{"email":"x.bobbie@y"}', "bobbie"));
});

// B's objects are found from the listing B reads, with no declared owns and no marker: the identity is B's JWT sub.
function listOptions() {
  return {
    "authz-matrix": {
      resources: [{ name: "note", path: "/api/notes/:id", list: "/api/notes", idField: "id" }],
      accounts: {
        a: { label: "A", login: { url: "/login", username: "alice", passwordEnv: "CRENEL_TEST_PW_A" } },
        b: { label: "B", login: { url: "/login", username: "bobbie", passwordEnv: "CRENEL_TEST_PW_B" } },
      },
    },
  };
}

test("authz-matrix: B's objects discovered from a global listing prove the BOLA on B's object only", async () => {
  const { base, srv } = await app(false);
  try {
    const p = proven(await run(base, listOptions()));
    assert.deepEqual(p.map((f) => f.id), ["authz-matrix:note:GET:note_b_1"], "not bobbie2's note, not A's note that mentions B");
  } finally { srv.close(); }
});

test("authz-matrix: listing discovery on an app that checks ownership proves nothing (negative control)", async () => {
  const { base, srv } = await app(true);
  try { assert.equal(proven(await run(base, listOptions())).length, 0); } finally { srv.close(); }
});

// The other account-based checks log in too: each one's requests carry the session the login returned.
test("nested-authz, authz-write, mass-assignment and data-exposure send the session of a declared login", async () => {
  const { nestedAuthz } = await import("./nested-authz.js");
  const { authzWrite } = await import("./authz-write.js");
  const { massAssignment } = await import("./mass-assignment.js");
  const { dataExposure } = await import("./data-exposure.js");
  const subs: string[] = [];
  const srv = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      res.writeHead(req.url === "/login" || req.method === "GET" ? 200 : 404, { "content-type": "application/json" });
      if (req.url === "/login") { const b = JSON.parse(raw || "{}"); return res.end(JSON.stringify({ token: b.password === `pw-${b.username}` ? jwt(b.username) : "" })); }
      const t = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
      if (t) subs.push(JSON.parse(Buffer.from(t.split(".")[1]!, "base64url").toString()).sub);
      res.end(JSON.stringify({ id: "x", name: "n" }));
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const login = (u: string) => ({ url: "/login", username: u, passwordEnv: `CRENEL_TEST_PW_${u.toUpperCase()}` });
  Object.assign(process.env, { CRENEL_TEST_PW_ALICE: "pw-alice", CRENEL_TEST_PW_BOBBIE: "pw-bobbie" });
  const ctx = (options: Record<string, unknown>): CheckContext => ({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true }), projectDir: "/tmp/x", stagingUrl: base, options, log: () => {} });
  try {
    const cases: [string, { run(c: CheckContext): Promise<unknown> }, Record<string, unknown>][] = [
      ["nested-authz", nestedAuthz, { "nested-authz": { accounts: { a: { login: login("alice") }, b: { login: login("bobbie"), marker: "bobbie-marker" } }, resources: [{ name: "p", path: "/orgs/:org/projects/:id", segments: { org: { b: "org-b" }, id: { b: "proj-b" } } }] } }],
      ["authz-write", authzWrite, { "authz-write": { enabled: true, accounts: { a: { login: login("alice") }, b: { login: login("bobbie") } }, targets: [{ name: "project", path: "/api/projects/:id", method: "PATCH", field: "name", victimId: "p_b", ownId: "p_a" }] } }],
      ["mass-assignment", massAssignment, { "mass-assignment": { enabled: true, accounts: { a: { login: login("alice") } }, targets: [{ name: "profile", path: "/api/me", method: "PATCH", fields: { role: "admin" } }] } }],
      ["data-exposure", dataExposure, { "data-exposure": { endpoints: ["/_debug"], as: "a" }, "authz-matrix": { accounts: { a: { login: login("alice") } } } }],
    ];
    for (const [name, check, options] of cases) {
      subs.length = 0;
      await check.run(ctx(options));
      assert.ok(subs.includes("alice"), `${name}: a request carried A's fresh session (saw ${JSON.stringify(subs)})`);
    }
  } finally { delete process.env.CRENEL_TEST_PW_ALICE; delete process.env.CRENEL_TEST_PW_BOBBIE; srv.close(); }
});
