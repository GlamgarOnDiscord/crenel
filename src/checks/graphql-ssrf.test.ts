import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, get } from "node:http";
import type { AddressInfo } from "node:net";
import { graphqlSsrf } from "./graphql-ssrf.js";
import { Scope } from "../core/scope.js";

// A GraphQL stand-in. Introspection advertises a vulnerable structured sink
// `fetchThing(host,port,path,scheme)` that REALLY fetches host:port/path (the
// SSRF), a destructive-named `deleteByUrl(url)` that would also fetch (must never
// be fired), and a safe `echo(url)` that never fetches (negative control).
function gqlServer() {
  return createServer((req, res) => {
    let body = ""; req.on("data", (c) => (body += c)); req.on("end", () => {
      const query = (() => { try { return JSON.parse(body).query as string; } catch { return ""; } })();
      const send = (o: unknown) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
      if (query.includes("__schema")) {
        const S = { kind: "SCALAR", name: "String", ofType: null };
        const I = { kind: "SCALAR", name: "Int", ofType: null };
        const arg = (name: string, t: unknown) => ({ name, type: t });
        return send({ data: { __schema: {
          // echo is a QUERY with a url arg: it IS probed (queries are safe) but it
          // never fetches, so it is the real negative control.
          queryType: { fields: [{ name: "echo", args: [arg("url", S)] }] },
          mutationType: { fields: [
            { name: "fetchThing", args: [arg("host", S), arg("port", I), arg("path", S), arg("scheme", S)] },
            { name: "deleteByUrl", args: [arg("url", S)] },
          ] },
        } } });
      }
      // A real server-side fetch for the vulnerable field; the attacker controls the host.
      const m = /fetchThing\(host:\s*"([^"]+)",\s*port:\s*(\d+),\s*path:\s*"([^"]+)"/.exec(query);
      if (m) { get(`http://${m[1]}:${m[2]}${m[3]}`, (r) => r.resume()).on("error", () => {}); return send({ data: { fetchThing: { __typename: "Thing" } } }); }
      // echo and deleteByUrl never fetch; deleteByUrl should never even be called.
      if (query.includes("deleteByUrl")) return send({ errors: [{ message: "deleteByUrl must not be probed" }] });
      return send({ data: { echo: { __typename: "E" } } });
    });
  });
}

test("graphql-ssrf: proves a schema-discovered SSRF out-of-band, skips destructive and safe fields", async () => {
  const srv = gqlServer();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as AddressInfo).port;
  let deleteProbed = false;
  srv.on("request", (req) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { if (b.includes("deleteByUrl")) deleteProbed = true; }); });
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true });
    const found = await graphqlSsrf.run({ scope, projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options: { "graphql-ssrf": { enabled: true, endpoint: "/", callbackHost: "127.0.0.1" } }, log: () => {} });
    const proven = found.filter((f) => f.state === "proven");
    assert.equal(proven.length, 1, "only the real SSRF sink is proven");
    assert.match(proven[0]!.id, /graphql-ssrf:mutation:fetchThing/);
    assert.equal(proven[0]!.severity, "high");
    assert.ok(!found.some((f) => /deleteByUrl/.test(f.id)), "a destructive-named field is never a finding");
    assert.ok(!deleteProbed, "a destructive-named field is never even fired");
    assert.ok(!found.some((f) => /echo/.test(f.id)), "a field that does not fetch is not proven");
  } finally {
    await new Promise<void>((r) => srv.close(() => r()));
  }
});

test("graphql-ssrf: does nothing unless opted in, and refuses without active mode", async () => {
  const off = await graphqlSsrf.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }), projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: {}, log: () => {} });
  assert.equal(off.length, 0);
  await assert.rejects(
    () => graphqlSsrf.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: false, allowPrivate: true }), projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: { "graphql-ssrf": { enabled: true } }, log: () => {} }),
    /active/i,
  );
});
