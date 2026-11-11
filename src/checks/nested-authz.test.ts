import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { nestedAuthz } from "./nested-authz.js";
import { Scope } from "../core/scope.js";
import type { CheckContext, Finding } from "../core/types.js";

const MARKER = "owner-b@example.com";
const PROJECT = "/orgs/org-b/projects/proj-b";

function run(server: Server, options: Record<string, unknown>): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const ctx: CheckContext = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }),
        projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {},
      };
      try { resolve(await nestedAuthz.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

const opts = (over: Record<string, unknown> = {}) => ({
  "nested-authz": {
    accounts: { a: { token: "A" }, b: { token: "B", marker: MARKER }, ...(over.accounts as object ?? {}) },
    resources: over.resources ?? [{ name: "project", path: "/orgs/:org/projects/:id", segments: { org: { b: "org-b" }, id: { b: "proj-b" } } }],
  },
});

const auth = (req: { headers: Record<string, unknown> }) => String(req.headers["authorization"] ?? "");

// Server that authorizes the PARENT (org) but trusts the leaf: any authenticated
// caller who walks B's path reads B's project. A non-existent leaf 404s; anon 401.
function vulnerable(): Server {
  return createServer((req, res) => {
    const a = auth(req as never);
    if (!a) { res.writeHead(401); return res.end('{"error":"auth required"}'); }
    if (req.url === PROJECT) { res.writeHead(200, { "content-type": "application/json" }); return res.end(`{"id":"proj-b","owner":"${MARKER}"}`); }
    res.writeHead(404); res.end('{"error":"not found"}');
  });
}

test("nested-authz: a server that trusts the leaf id leaks B's nested project to A (proven)", async () => {
  const found = await run(vulnerable(), opts());
  const proven = found.filter((f) => f.state === "proven");
  assert.equal(proven.length, 1, "the cross-tenant nested read is the one proof");
  assert.match(proven[0]!.title, /nested project/i);
  assert.equal(proven[0]!.severity, "high");
  assert.match(proven[0]!.proof?.evidence ?? "", /anonymous HTTP 401/);
});

test("nested-authz: a server that authorizes the leaf (A gets 403) proves nothing", async () => {
  const server = createServer((req, res) => {
    const a = auth(req as never);
    if (!a) { res.writeHead(401); return res.end("{}"); }
    if (req.url === PROJECT && a === "Bearer B") { res.writeHead(200, { "content-type": "application/json" }); return res.end(`{"id":"proj-b","owner":"${MARKER}"}`); }
    if (req.url === PROJECT) { res.writeHead(403); return res.end('{"error":"forbidden"}'); }
    res.writeHead(404); res.end("{}");
  });
  const found = await run(server, opts());
  assert.ok(!found.some((f) => f.state === "proven"), "a scoped leaf is not a BOLA");
});

test("nested-authz: an accept-all route (bogus leaf returns the same body) is a lead, no false positive", async () => {
  // Every path, including the non-existent-leaf control, returns the same generic body.
  const server = createServer((req, res) => {
    if (!auth(req as never)) { res.writeHead(401); return res.end("{}"); }
    res.writeHead(200, { "content-type": "application/json" }); res.end('{"page":"generic"}');
  });
  const found = await run(server, opts());
  assert.ok(!found.some((f) => f.state === "proven"), "accept-all is not a nested-BOLA proof");
});

test("nested-authz: a public nested route (anonymous also reads it) is not a proven BOLA", async () => {
  const server = createServer((req, res) => {
    if (req.url === PROJECT) { res.writeHead(200, { "content-type": "application/json" }); return res.end(`{"id":"proj-b","owner":"${MARKER}"}`); }
    res.writeHead(404); res.end("{}");
  });
  const found = await run(server, opts());
  assert.ok(!found.some((f) => f.state === "proven"), "a route anyone can read is not a cross-tenant break");
});

test("nested-authz: A and B being the same token yields no finding (same-identity guard)", async () => {
  const found = await run(vulnerable(), opts({ accounts: { a: { token: "SAME" }, b: { token: "SAME", marker: MARKER } } }));
  assert.equal(found.length, 0);
});

test("nested-authz: a non-nested path (single segment) is skipped", async () => {
  const found = await run(vulnerable(), opts({ resources: [{ name: "project", path: "/projects/:id", segments: { id: { b: "proj-b" } } }] }));
  assert.ok(!found.some((f) => f.state === "proven"));
});

test("nested-authz: no resources declared yields no findings", async () => {
  const found = await nestedAuthz.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});
