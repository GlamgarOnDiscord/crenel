import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { apiDocs, parseSpec } from "./api-docs.js";
import { Scope } from "../core/scope.js";

async function serve(handler: (url: string) => [number, string]) {
  const srv = createServer((req, res) => { const [s, b] = handler(req.url ?? "/"); res.writeHead(s); res.end(b); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return { srv, base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` };
}
const run = (base: string) => apiDocs.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });
const spec = JSON.stringify({ openapi: "3.0.3", paths: { "/projects/{id}": { get: {} }, "/admin/users": { get: {}, delete: {} } } });

test("api-docs: a served OpenAPI document with admin routes is proven, medium, once per host", async () => {
  const { srv, base } = await serve((u) => (u === "/openapi.json" || u === "/v3/api-docs" ? [200, spec] : [404, ""]));
  try {
    const f = await run(base);
    assert.equal(f.length, 1);
    assert.equal(f[0]!.state, "proven");
    assert.equal(f[0]!.severity, "medium");
    assert.match(f[0]!.title, /3 operations, 1 admin/);
    assert.match(f[0]!.description, /1 GET route\(s\) take one object id/);
  } finally { srv.close(); }
});

test("api-docs: a YAML Swagger 2 spec counts, low without admin routes", async () => {
  const { srv, base } = await serve((u) => (u === "/swagger.yaml" ? [200, "swagger: '2.0'\npaths:\n  /me:\n    get: {}\n"] : [404, ""]));
  try { const f = await run(base); assert.equal(f.length, 1); assert.equal(f[0]!.severity, "low"); } finally { srv.close(); }
});

test("api-docs: an SPA shell, a JSON that is not a spec, and a 401 are nothing", async () => {
  const { srv, base } = await serve((u) => (u.startsWith("/v3") ? [401, spec] : u.endsWith(".json") ? [200, '{"openapi":"soon"}'] : [200, "<!doctype html><div id=root>"]));
  try { assert.equal((await run(base)).length, 0); } finally { srv.close(); }
  assert.equal(parseSpec('{"swagger":"2.0"}'), null);
  assert.equal(parseSpec("openapi: 3.1.0\npaths: []\n"), null);
});
