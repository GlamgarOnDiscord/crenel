import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { passwordBody, passwordTakeover, plannedTakeover } from "./password-takeover.js";
import { ActiveClient, redactWriteBody } from "./active-common.js";
import { Scope } from "../core/scope.js";
import type { CheckContext, Finding } from "../core/types.js";

const TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2In0.sig_aaaaaa";
const opts = {
  "password-takeover": {
    enabled: true,
    accounts: { a: { token: "A" }, b: { token: "B" } },
    targets: [{ name: "password", changePath: "/users/:id/password", victimId: "victim", body: '{"password":"{{PW}}"}', login: { path: "/login", userField: "user", victimUser: "victim" }, restorePasswordEnv: "CRENEL_TEST_RESTORE_PASSWORD" }],
  },
};

test("active receipts redact nested passwords, tokens, cookies and secrets", () => {
  assert.deepEqual(redactWriteBody({ password: "p", nested: { apiKey: "k", cookie: "c", privateKey: "pk", credentials: "creds", otp: "123", safe: "shown" }, token: "t" }), {
    password: "<redacted>", nested: { apiKey: "<redacted>", cookie: "<redacted>", privateKey: "<redacted>", credentials: "<redacted>", otp: "<redacted>", safe: "shown" }, token: "<redacted>",
  });
  let deep: unknown = { password: "never-visible" };
  for (let i = 0; i < 10_000; i++) deep = { next: deep };
  assert.doesNotMatch(JSON.stringify(redactWriteBody(deep)), /never-visible/);
  const cyclic: { safe: string; nested?: unknown; password: string } = { safe: "shown", password: "never-visible" };
  cyclic.nested = cyclic;
  assert.deepEqual(redactWriteBody(cyclic), { safe: "shown", password: "<redacted>", nested: "<redacted circular value>" });
  const shared = { safe: "copied twice" };
  assert.deepEqual(redactWriteBody({ first: shared, second: shared }), { first: { safe: "copied twice" }, second: { safe: "copied twice" } }, "a repeated reference is not a cycle");
  const sparse: unknown[] = [];
  sparse[2] = { password: "never-visible" };
  assert.deepEqual(redactWriteBody({ sparse }), { sparse: [undefined, undefined, { password: "<redacted>" }] });
  const wide: Record<string, unknown> = {};
  for (let i = 0; i < 20_000; i++) wide[`safe${i}`] = i;
  wide.password = "never-visible";
  const bounded = JSON.stringify(redactWriteBody(wide));
  assert.doesNotMatch(bounded, /never-visible/);
  assert.ok(bounded.length < 250_000, "wide receipt redaction stops at its global property budget");
});

test("password templates preserve JSON-special and replacement-token characters", () => {
  assert.deepEqual(passwordBody('{"password":"{{PW}}"}', 'quote" slash\\ $& $`'), { password: 'quote" slash\\ $& $`' });
  assert.equal(plannedTakeover(opts, "https://staging.example").length, 5);
});

test("active receipts suppress scalar and array payloads", async () => {
  const server = createServer((_req, res) => { res.writeHead(200); res.end("{}"); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  const context: CheckContext = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true }), projectDir: "/tmp", options: {}, log: () => {} };
  const client = new ActiveClient(context, "test");
  try {
    await client.send("POST", `http://127.0.0.1:${port}/`, undefined, "secret scalar");
    await client.send("POST", `http://127.0.0.1:${port}/`, undefined, ["secret array"]);
    assert.deepEqual(client.writes.map((w) => w.body), ["<redacted non-object payload>", "<redacted non-object payload>"]);
  } finally { server.close(); }
});

function run(server: Server, options: Record<string, unknown>): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const ctx: CheckContext = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }),
        projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {},
      };
      const previous = process.env.CRENEL_TEST_RESTORE_PASSWORD;
      process.env.CRENEL_TEST_RESTORE_PASSWORD = "orig";
      try { resolve(await passwordTakeover.run(ctx)); } catch (e) { reject(e); } finally {
        if (previous === undefined) delete process.env.CRENEL_TEST_RESTORE_PASSWORD; else process.env.CRENEL_TEST_RESTORE_PASSWORD = previous;
        server.close();
      }
    });
  });
}

function body(req: import("node:http").IncomingMessage): Promise<string> {
  return new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
}

// Any authenticated caller changes any user's password (BOLA); login checks the password.
function vulnerable(): Server {
  const pw: Record<string, string> = { victim: "orig" };
  return createServer(async (req, res) => {
    const m = /^\/users\/([^/]+)\/password$/.exec(req.url ?? "");
    if (m && req.method === "PUT") {
      if (!req.headers.authorization) { res.writeHead(401); return res.end(); }
      if (!(m[1]! in pw)) { res.writeHead(404); return res.end('{"error":"no such user"}'); } // control: non-existent rejected
      try { pw[m[1]!] = JSON.parse(await body(req)).password; } catch { /* */ }
      res.writeHead(200); return res.end('{"status":"ok"}');
    }
    if (req.url === "/login" && req.method === "POST") {
      let o: Record<string, string> = {}; try { o = JSON.parse(await body(req)); } catch { /* */ }
      if (pw[o.user!] === o.password) { res.writeHead(200); return res.end(`{"auth_token":"${TOKEN}"}`); }
      res.writeHead(200); return res.end('{"status":"fail"}');
    }
    res.writeHead(404); res.end();
  });
}

test("password-takeover: A changing B's password, confirmed by login as B, is proven", async () => {
  const found = await run(vulnerable(), opts);
  const proven = found.filter((f) => f.state === "proven");
  assert.equal(proven.length, 1, "the account takeover is the one proof");
  assert.match(proven[0]!.title, /Account takeover/i);
  assert.equal(proven[0]!.severity, "critical");
  const serialized = JSON.stringify(found);
  assert.doesNotMatch(serialized, /orig|Crenel-[a-f0-9]+-Aa1!/, "probe and restore passwords are redacted from the receipt");
});

test("password-takeover: a properly-gated endpoint (A gets 403 on B) proves nothing", async () => {
  const pw: Record<string, string> = { victim: "orig" };
  const server = createServer(async (req, res) => {
    const m = /^\/users\/([^/]+)\/password$/.exec(req.url ?? "");
    if (m && req.method === "PUT") { res.writeHead(req.headers.authorization === "Bearer B" ? 200 : 403); if (req.headers.authorization === "Bearer B") { try { pw[m[1]!] = JSON.parse(await body(req)).password; } catch { /* */ } } return res.end("{}"); }
    if (req.url === "/login") { let o: Record<string, string> = {}; try { o = JSON.parse(await body(req)); } catch { /* */ } res.writeHead(200); return res.end(pw[o.user!] === o.password ? `{"auth_token":"${TOKEN}"}` : '{"status":"fail"}'); }
    res.writeHead(404); res.end();
  });
  const found = await run(server, opts);
  assert.ok(!found.some((f) => f.state === "proven"), "a gated password change is not a takeover");
});

test("password-takeover: an accept-all endpoint (control for a non-existent victim accepted) proves nothing", async () => {
  const server = createServer(async (req, res) => {
    if (/\/password$/.test(req.url ?? "") && req.method === "PUT") { res.writeHead(200); return res.end("{}"); } // accepts everything, incl. the control
    if (req.url === "/login") { res.writeHead(200); return res.end('{"status":"fail"}'); }
    res.writeHead(404); res.end();
  });
  const found = await run(server, opts);
  assert.ok(!found.some((f) => f.state === "proven"), "accept-all is not a takeover proof");
});

test("password-takeover: restoration still runs when the confirmation login connection fails", async () => {
  let loginCalls = 0, restored = false;
  const server = createServer(async (req, res) => {
    const m = /^\/users\/([^/]+)\/password$/.exec(req.url ?? "");
    if (m && req.method === "PUT") {
      if (m[1] !== "victim") { res.writeHead(404); return res.end(); }
      const value = JSON.parse(await body(req)).password;
      if (req.headers.authorization === "Bearer B" && value === "orig") restored = true;
      res.writeHead(200); return res.end("{}");
    }
    if (req.url === "/login") {
      loginCalls++;
      await body(req);
      if (loginCalls === 2) return req.socket.destroy();
      res.writeHead(200); return res.end('{"status":"fail"}');
    }
    res.writeHead(404); res.end();
  });
  const found = await run(server, opts);
  assert.equal(restored, true);
  assert.equal(loginCalls, 2, "the second login is the failing confirmation path");
  assert.ok(!found.some((f) => f.state === "proven"));
  assert.ok(found.some((f) => f.id === "password-takeover:writes" && /every change restored/i.test(f.title)));
});

test("password-takeover: restoration runs when the mutation applies then the socket drops", async () => {
  let restored = false, currentPassword = "orig";
  const server = createServer(async (req, res) => {
    const m = /^\/users\/([^/]+)\/password$/.exec(req.url ?? "");
    if (m && req.method === "PUT") {
      if (m[1] !== "victim") { res.writeHead(404); return res.end(); }
      const value = JSON.parse(await body(req)).password;
      currentPassword = value;
      if (req.headers.authorization === "Bearer A") return req.socket.destroy();
      if (req.headers.authorization === "Bearer B" && value === "orig") restored = true;
      res.writeHead(200); return res.end("{}");
    }
    if (req.url === "/login") { await body(req); res.writeHead(200); return res.end('{"status":"fail"}'); }
    res.writeHead(404); res.end();
  });
  const found = await run(server, opts);
  assert.equal(restored, true);
  assert.equal(currentPassword, "orig", "the victim restore replaces the attacker's applied password after the dropped response");
  assert.ok(!found.some((f) => f.state === "proven"));
  assert.ok(found.some((f) => f.id === "password-takeover:writes" && /every change restored/i.test(f.title)));
});

test("password-takeover: a malformed non-string body is skipped without aborting the check", async () => {
  const malformed = { "password-takeover": { ...opts["password-takeover"], targets: [{ ...opts["password-takeover"].targets[0], body: { password: "{{PW}}" } }] } } as unknown as Record<string, unknown>;
  const found = await run(createServer((_req, res) => { res.writeHead(500); res.end(); }), malformed);
  assert.ok(found.some((f) => f.id === "password-takeover:writes" && /skipped/i.test(f.description)));
});

test("password-takeover: off unless active testing is enabled (scope gate holds)", async () => {
  const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: false });
  await assert.rejects(() => passwordTakeover.run({ scope, projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: opts, log: () => {} }), /active/i);
});

test("password-takeover: disabled yields nothing", async () => {
  const found = await passwordTakeover.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});
