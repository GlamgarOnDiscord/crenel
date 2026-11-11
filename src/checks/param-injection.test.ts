import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { paramInjection } from "./param-injection.js";
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
      try { resolve(await paramInjection.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

// Boolean SQLi in a path segment (like VAmPI /users/v1/:username): the raw value and
// an always-TRUE condition return the object; an always-FALSE condition returns none.
function pathSqli(): Server {
  return createServer((req, res) => {
    const u = decodeURIComponent((req.url ?? "").replace("/users/", ""));
    const trueCond = /OR\s+'?1'?\s*=\s*'?1|OR\s+1=1/i.test(u);
    const falseCond = /AND\s+'?1'?\s*=\s*'?2|AND\s+1=2/i.test(u);
    if (falseCond) { res.writeHead(404, { "content-type": "application/json" }); return res.end('{"status":"fail","message":"User not found"}'); }
    if (u === "name1" || trueCond) { res.writeHead(200, { "content-type": "application/json" }); return res.end('{"username":"name1","email":"mail1@mail.com"}'); }
    res.writeHead(404); res.end('{"status":"fail"}');
  });
}

test("param-injection: boolean SQLi in a path segment is proven (TRUE like baseline, FALSE diverges)", async () => {
  const opts = { "param-injection": { endpoints: [{ url: "/users/:u", param: "u", baseline: "name1" }] } };
  const found = await run(pathSqli(), opts);
  const proven = found.filter((f) => f.state === "proven");
  assert.equal(proven.length, 1, "the injectable path segment is the one proof");
  assert.match(proven[0]!.title, /SQL injection in the u URL parameter/);
  assert.equal(proven[0]!.severity, "critical");
});

test("param-injection: boolean SQLi in a query parameter is proven", async () => {
  const server = createServer((req, res) => {
    const q = new URL(req.url ?? "/", "http://x").searchParams.get("q") ?? "";
    if (/AND\s+'?1'?\s*=\s*'?2/i.test(q)) { res.writeHead(404); return res.end('{"error":"none"}'); }
    if (q === "name1" || /OR\s+'?1'?\s*=\s*'?1/i.test(q)) { res.writeHead(200, { "content-type": "application/json" }); return res.end('{"username":"name1"}'); }
    res.writeHead(404); res.end("{}");
  });
  const found = await run(server, { "param-injection": { endpoints: [{ url: "/search", param: "q", baseline: "name1" }] } });
  assert.equal(found.filter((f) => f.state === "proven").length, 1);
});

test("param-injection: a parameter that is NOT injectable proves nothing (no false positive)", async () => {
  // Returns the same object for every value, injection or not: no differential.
  const server = createServer((_req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end('{"username":"name1"}'); });
  const found = await run(server, { "param-injection": { endpoints: [{ url: "/users/:u", param: "u", baseline: "name1" }] } });
  assert.ok(!found.some((f) => f.state === "proven"), "an endpoint that ignores the payload is not injectable");
});

test("param-injection: off unless active testing is enabled (scope gate holds)", async () => {
  const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: false });
  await assert.rejects(
    () => paramInjection.run({ scope, projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: { "param-injection": { endpoints: [{ url: "/users/:u", param: "u", baseline: "x" }] } }, log: () => {} }),
    /active/i,
  );
});

test("param-injection: no endpoints yields no findings", async () => {
  const found = await paramInjection.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});
