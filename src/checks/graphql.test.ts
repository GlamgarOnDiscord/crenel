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

test("a server that takes GraphQL over POST only is tested with a POST that carries a query", async () => {
  const schema = { data: { __schema: { queryType: { name: "Query" }, mutationType: null, types: [{ name: "Query", kind: "OBJECT" }] } } };
  const bodies: string[] = [];
  const srv = createServer((req, res) => {
    if (req.method !== "POST" || !req.url?.startsWith("/graphql")) { res.writeHead(405); return res.end(); }
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { bodies.push(b); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(schema)); });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const found = await graphql.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: { graphql: { paths: ["/graphql"] } }, log: () => {} });
    assert.equal(found.length, 1);
    assert.match(found[0]!.proof!.method, /POST/);
    assert.deepEqual(JSON.parse(bodies[0]!), { query: "query{__schema{queryType{name}mutationType{name}types{name kind}}}" });
  } finally { srv.close(); }
});

test("field suggestions are proven even when introspection is off", async () => {
  const srv = createServer((req, res) => {
    let c = ""; req.on("data", (d) => (c += d)); req.on("end", () => {
      const q = (() => { try { return JSON.parse(c).query as string; } catch { return ""; } })();
      res.writeHead(200, { "content-type": "application/json" });
      if (/__schema/.test(q)) return res.end(JSON.stringify({ errors: [{ message: "introspection is disabled" }] }));
      if (/usr|nodee|serch|postz|__typenam/.test(q)) return res.end(JSON.stringify({ errors: [{ message: 'Cannot query field. Did you mean "users"?' }] }));
      res.end(JSON.stringify({ data: {} }));
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    // Read-only near-miss queries: no active mode needed.
    const found = await graphql.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });
    const sugg = found.find((f) => f.id.startsWith("graphql:suggestions:"));
    assert.ok(sugg, "field suggestions proven");
    assert.equal(sugg!.state, "proven");
  } finally { srv.close(); }
});

test("query batching is proven under active mode", async () => {
  const srv = createServer((req, res) => {
    let c = ""; req.on("data", (d) => (c += d)); req.on("end", () => {
      let body: any; try { body = JSON.parse(c); } catch { res.writeHead(400); return res.end("{}"); }
      res.writeHead(200, { "content-type": "application/json" });
      if (Array.isArray(body)) return res.end(JSON.stringify(body.map(() => ({ data: { __typename: "Query" } }))));
      if (/__schema/.test(body.query || "")) return res.end(JSON.stringify({ errors: [{ message: "introspection disabled" }] }));
      res.end(JSON.stringify({ data: { __typename: "Query" } }));
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const found = await graphql.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });
    assert.ok(found.find((f) => f.id.startsWith("graphql:batching:")), "batching proven");
    // without active mode, no batching finding
    const ro = await graphql.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });
    assert.ok(!ro.find((f) => f.id.startsWith("graphql:batching:")), "no batching without active mode");
  } finally { srv.close(); }
});

test("a server that refuses array bodies gets no batching finding", async () => {
  const srv = createServer((req, res) => {
    let c = ""; req.on("data", (d) => (c += d)); req.on("end", () => {
      let body: any; try { body = JSON.parse(c); } catch { res.writeHead(400); return res.end("{}"); }
      res.writeHead(200, { "content-type": "application/json" });
      if (Array.isArray(body)) return res.end(JSON.stringify({ errors: [{ message: "batching is not supported" }] }));
      if (/__schema/.test(body.query || "")) return res.end(JSON.stringify({ errors: [{ message: "introspection disabled" }] }));
      res.end(JSON.stringify({ data: { __typename: "Query" } }));
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const found = await graphql.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });
    assert.ok(!found.find((f) => f.id.startsWith("graphql:batching:")), "no batching finding when arrays are refused");
  } finally { srv.close(); }
});

test("a GraphiQL page is reported; an SPA index on the same path is not", async () => {
  for (const ide of [true, false]) {
    const srv = createServer((req, res) => {
      if (req.url === "/graphiql") { res.writeHead(200, { "content-type": "text/html" }); return res.end(ide ? '<html><script src="/static/graphiql.min.js"></script></html>' : "<html><div id=app></div></html>"); }
      res.writeHead(404); res.end("{}");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    try {
      const found = await graphql.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });
      assert.equal(found.some((f) => f.id.startsWith("graphql:ide:")), ide);
    } finally { srv.close(); }
  }
});
