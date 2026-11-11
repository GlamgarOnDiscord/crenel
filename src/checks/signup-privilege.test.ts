import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { signupPrivilege } from "./signup-privilege.js";
import { Scope } from "../core/scope.js";
import type { CheckContext, Finding } from "../core/types.js";

function run(server: Server, options: Record<string, unknown>): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const ctx: CheckContext = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }),
        projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {},
      };
      try { resolve(await signupPrivilege.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

const opts = { "signup-privilege": { enabled: true, targets: [{ name: "register", path: "/register", body: { username: "x", password: "p" }, privileged: { admin: true }, readPath: "/_debug", listField: "users" }] } };

// A registration that binds the whole body to the user (accepts admin), and a public
// _debug listing. The vulnerable case; a control signup without admin stays admin:false.
function vulnerable(): Server {
  const users: Record<string, unknown>[] = [];
  return createServer((req, res) => {
    if (req.url === "/_debug") { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ users })); }
    if (req.method === "POST" && req.url === "/register") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { let o: Record<string, unknown> = {}; try { o = JSON.parse(b); } catch { /* */ } users.push({ username: o.username, admin: o.admin === true }); res.writeHead(200); res.end('{"status":"success"}'); });
      return;
    }
    res.writeHead(404); res.end();
  });
}

test("signup-privilege: a registration that accepts admin:true is proven (control stays default)", async () => {
  const found = await run(vulnerable(), opts);
  const proven = found.filter((f) => f.state === "proven");
  assert.equal(proven.length, 1, "the privileged signup is the one proof");
  assert.match(proven[0]!.title, /Registration accepts a privileged field/i);
  assert.equal(proven[0]!.severity, "critical");
});

test("signup-privilege: a registration that IGNORES admin is not proven (no false positive)", async () => {
  const users: Record<string, unknown>[] = [];
  const server = createServer((req, res) => {
    if (req.url === "/_debug") { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ users })); }
    if (req.method === "POST") { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { let o: Record<string, unknown> = {}; try { o = JSON.parse(b); } catch { /* */ } users.push({ username: o.username, admin: false }); res.writeHead(200); res.end("{}"); }); return; }
    res.writeHead(404); res.end();
  });
  const found = await run(server, opts);
  assert.ok(!found.some((f) => f.state === "proven"), "a server that ignores the field is correct, not a finding");
});

test("signup-privilege: off unless active testing is enabled (scope gate holds)", async () => {
  const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: false });
  await assert.rejects(
    () => signupPrivilege.run({ scope, projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: opts, log: () => {} }),
    /active/i,
  );
});

test("signup-privilege: disabled yields nothing and sends no request", async () => {
  const found = await signupPrivilege.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});
