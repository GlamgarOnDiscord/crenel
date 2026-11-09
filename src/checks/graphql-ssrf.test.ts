import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { graphqlSsrf } from "./graphql-ssrf.js";
import { Scope } from "../core/scope.js";

const SCHEMA = { data: { __schema: { queryType: { fields: [
  { name: "fetchUrl", args: [{ name: "url", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "SCALAR", name: "String", ofType: null } },
  { name: "echo", args: [{ name: "text", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "SCALAR", name: "String", ofType: null } },
] }, mutationType: { fields: [] } } } };

function target(ssrf: boolean) {
  const read = (req: import("node:http").IncomingMessage) => new Promise<string>((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
  return createServer(async (req, res) => {
    let q = ""; try { q = JSON.parse(await read(req)).query ?? ""; } catch { /* */ }
    const send = (o: unknown) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
    if (/__schema/.test(q)) return send(SCHEMA);
    const m = /fetchUrl\(\s*url:\s*"((?:[^"\\]|\\.)*)"/.exec(q);
    if (m && ssrf) { try { await fetch(m[1]!.replace(/\\"/g, '"')); } catch { /* */ } return send({ data: { fetchUrl: "ok" } }); }
    return send({ data: {} });
  });
}
async function run(ssrf: boolean) {
  const srv = target(ssrf);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try { return await graphqlSsrf.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true }), projectDir: ".", stagingUrl: base, options: { "graphql-ssrf": { enabled: true, endpoint: "/", callbackHost: "127.0.0.1" } }, log: () => {} }); }
  finally { srv.close(); }
}
test("graphql-ssrf: a schema field that fetches our callback is proven", async () => {
  const f = await run(true);
  assert.ok(f.some((x) => x.state === "proven" && /fetchUrl/.test(x.title!)));
});
test("graphql-ssrf: a field that makes no outbound request is not flagged", async () => {
  assert.equal((await run(false)).filter((x) => x.state === "proven").length, 0);
});
