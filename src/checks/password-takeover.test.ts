import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { passwordTakeover } from "./password-takeover.js";
import { Scope } from "../core/scope.js";
import type { CheckContext, Finding } from "../core/types.js";

const TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2In0.sig_aaaaaa";
const opts = {
  "password-takeover": {
    enabled: true,
    accounts: { a: { token: "A" }, b: { token: "B" } },
    targets: [{ name: "password", changePath: "/users/:id/password", victimId: "victim", body: '{"password":"{{PW}}"}', login: { path: "/login", userField: "user", victimUser: "victim" }, restorePassword: "orig" }],
  },
};

function run(server: Server, options: Record<string, unknown>): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const ctx: CheckContext = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }),
        projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {},
      };
      try { resolve(await passwordTakeover.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
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

test("password-takeover: off unless active testing is enabled (scope gate holds)", async () => {
  const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: false });
  await assert.rejects(() => passwordTakeover.run({ scope, projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: opts, log: () => {} }), /active/i);
});

test("password-takeover: disabled yields nothing", async () => {
  const found = await passwordTakeover.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});
