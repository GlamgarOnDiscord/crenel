import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { functionAuthz } from "./function-authz.js";
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
      try { resolve(await functionAuthz.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

const USERS = '{"data":[{"id":1,"email":"admin@x"},{"id":2,"email":"u@x"}]}';
const auth = (req: { headers: Record<string, unknown> }) => String(req.headers["authorization"] ?? "");
const opts = (over: Record<string, unknown> = {}) => ({
  "function-authz": { accounts: { privileged: { token: "ADMIN" }, normal: { token: "NORMAL" }, ...(over.accounts as object ?? {}) }, functions: over.functions ?? [{ name: "user-list", path: "/api/Users" }] },
});

// A server where /api/Users is an admin function that ALSO answers any authenticated
// caller (BFLA): admin and normal both get the full list; anon is refused; a nonsense
// sub-path 404s.
function bfla(): Server {
  return createServer((req, res) => {
    if ((req.url ?? "").startsWith("/api/Users/crenel-")) { res.writeHead(404); return res.end("{}"); }
    if (req.url === "/api/Users") {
      if (!auth(req as never)) { res.writeHead(401); return res.end('{"error":"auth"}'); }
      res.writeHead(200, { "content-type": "application/json" }); return res.end(USERS);
    }
    res.writeHead(404); res.end("{}");
  });
}

test("function-authz: a normal account reaching an admin function is proven (anon refused, control refused)", async () => {
  const found = await run(bfla(), opts());
  const proven = found.filter((f) => f.state === "proven");
  assert.equal(proven.length, 1, "the function-level break is the one proof");
  assert.match(proven[0]!.title, /function-level authorization/i);
  assert.match(proven[0]!.description ?? "", /privilege escalation/i);
});

test("function-authz: a properly gated admin function (normal gets 403) proves nothing", async () => {
  const server = createServer((req, res) => {
    if (req.url === "/api/Users") {
      const a = auth(req as never);
      if (a === "Bearer ADMIN") { res.writeHead(200, { "content-type": "application/json" }); return res.end(USERS); }
      res.writeHead(a ? 403 : 401); return res.end("{}");
    }
    res.writeHead(404); res.end("{}");
  });
  const found = await run(server, opts());
  assert.ok(!found.some((f) => f.state === "proven"), "a gated function is not a BFLA");
});

test("function-authz: a public function (anon also reaches it) is not a proven BFLA", async () => {
  const server = createServer((req, res) => {
    if (req.url === "/api/Users") { res.writeHead(200, { "content-type": "application/json" }); return res.end(USERS); }
    res.writeHead(404); res.end("{}");
  });
  const found = await run(server, opts());
  assert.ok(!found.some((f) => f.state === "proven"), "a public endpoint is not privilege-gated");
});

test("function-authz: an accept-all endpoint (control also 2xx) is not proven", async () => {
  const server = createServer((req, res) => {
    if (!auth(req as never)) { res.writeHead(401); return res.end("{}"); }
    res.writeHead(200, { "content-type": "application/json" }); res.end(USERS); // every path, incl. the control
  });
  const found = await run(server, opts());
  assert.ok(!found.some((f) => f.state === "proven"), "a non-discriminating endpoint is a lead, not a proof");
});

test("function-authz: privileged and normal being the same token yields no finding", async () => {
  const found = await run(bfla(), opts({ accounts: { privileged: { token: "SAME" }, normal: { token: "SAME" } } }));
  assert.equal(found.length, 0);
});

test("function-authz: no functions declared yields no findings", async () => {
  const found = await functionAuthz.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});
