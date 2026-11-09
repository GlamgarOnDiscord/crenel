import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { graphqlInjection } from "./graphql-injection.js";
import { Scope } from "../core/scope.js";

const SCHEMA = { data: { __schema: { queryType: { fields: [
  { name: "vulnSearch", args: [{ name: "q", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "LIST", name: null, ofType: { kind: "OBJECT", name: "Row", ofType: null } } },
  { name: "runCmd", args: [{ name: "c", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "SCALAR", name: "String", ofType: null } },
  { name: "safeSearch", args: [{ name: "q", type: { kind: "SCALAR", name: "String", ofType: null } }], type: { kind: "LIST", name: null, ofType: { kind: "OBJECT", name: "Row", ofType: null } } },
] }, mutationType: { fields: [] } } } };
const ROW = { data: { __type: { fields: [{ name: "id", type: { kind: "SCALAR", name: "ID", ofType: null } }] } } };

function target() {
  const read = (req: import("node:http").IncomingMessage) => new Promise<string>((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
  return createServer(async (req, res) => {
    let q = ""; try { q = JSON.parse(await read(req)).query ?? ""; } catch { /* */ }
    const send = (o: unknown) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
    if (/__schema/.test(q)) return send(SCHEMA);
    if (/__type\(name:\s*"Row"\)/.test(q)) return send(ROW);
    const call = /(\w+)\(\s*\w+:\s*"((?:[^"\\]|\\.)*)"/.exec(q);
    if (!call) return send({ data: {} });
    const field = call[1]!, arg = call[2]!.replace(/\\"/g, '"');
    if (field === "runCmd") { const m = arg.match(/echo\s+(\S*?)\$\(\(7\*7\)\)/); return send({ data: { runCmd: m ? m[1] + "49" : "" } }); }
    if (field === "vulnSearch") return send({ data: { vulnSearch: /'\s*OR\s*'1'='1/i.test(arg) ? [{ id: "1" }, { id: "2" }] : [] } });
    return send({ data: { safeSearch: [] } });
  });
}
async function run() {
  const srv = target();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try { return await graphqlInjection.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true }), projectDir: ".", stagingUrl: base, options: { "graphql-injection": { enabled: true, endpoint: "/" } }, log: () => {} }); }
  finally { srv.close(); }
}
test("graphql-injection: proves schema-discovered SQL (boolean) and OS command injection, not the safe field", async () => {
  const f = await run();
  const proven = f.filter((x) => x.state === "proven");
  assert.ok(proven.some((x) => /vulnSearch/.test(x.title!)), "boolean SQLi proven");
  assert.ok(proven.some((x) => /runCmd/.test(x.title!)), "command injection proven");
  assert.ok(!proven.some((x) => /safeSearch/.test(x.title!)), "safe field not flagged");
});
