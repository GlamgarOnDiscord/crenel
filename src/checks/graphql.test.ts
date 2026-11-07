import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { graphql } from "./graphql.js";
import { Scope } from "../core/scope.js";

test("an introspection answered over GET is proven; a server that refuses it is not", async () => {
  const schema = { data: { __schema: { queryType: { name: "Query" }, mutationType: { name: "Mutation" }, types: [{ name: "Query", kind: "OBJECT" }, { name: "AdminUser", kind: "OBJECT" }, { name: "__Type", kind: "OBJECT" }] } } };
  const srv = createServer((req, res) => {
    if (req.url?.startsWith("/graphql?query=")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(schema)); }
    if (req.url?.startsWith("/api/graphql")) { res.writeHead(200); return res.end(JSON.stringify({ errors: [{ message: "introspection disabled" }] })); }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const found = await graphql.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });
    assert.equal(found.length, 1);
    assert.equal(found[0]!.id, "graphql:introspection:/graphql");
    assert.match(found[0]!.title, /2 object types, mutations included/);
    assert.match(found[0]!.description, /AdminUser/);
  } finally { srv.close(); }
});
