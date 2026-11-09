import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Scope } from "../core/scope.js";
import { autoClaims, runAutoProbe } from "./autoprobe.js";
import type { ValidatorEnv } from "./validators.js";

test("autoClaims: systematic set per endpoint x technique, no accounts -> no auth claims", () => {
  const none = autoClaims({ endpoints: [{ url: "/a", params: ["q"] }], accounts: [], origin: "http://x" });
  assert.ok(none.some((c) => c.class === "explore.cors"));
  assert.ok(none.some((c) => c.class === "explore.injection"));
  assert.ok(!none.some((c) => c.class === "explore.jwt-forge"), "no account -> no jwt-forge");
  assert.ok(!none.some((c) => c.class === "explore.cross-actor"), "no account B -> no cross-actor");
  const full = autoClaims({ endpoints: [{ url: "/obj/6", graphql: false }], accounts: ["a", "b"] });
  assert.ok(full.some((c) => c.class === "explore.jwt-forge"));
  assert.ok(full.some((c) => c.class === "explore.cross-actor" && c.detail.attacker === "anon"));
  assert.ok(full.some((c) => c.class === "explore.cross-actor" && c.detail.attacker === "a"));
});

test("runAutoProbe proves a public object leak deterministically (no model)", async () => {
  // /obj/6 returns B's object (with B's marker) to everyone incl. anon; non-existent id -> 404.
  const srv = createServer((req, res) => {
    const m = new URL(req.url!, "http://x").pathname.match(/^\/obj\/([^/]+)$/);
    const json = (s: number, b: unknown) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
    if (!m) return json(404, {});
    return m[1] === "6" ? json(200, { id: 6, owner: "acct_b_mk" }) : json(404, {});
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-ap-"));
  try {
    const env: ValidatorEnv = {
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }),
      projectDir: dir, stagingUrl: base, checks: [],
      options: { "authz-matrix": { accounts: { a: { token: "tok-a", marker: "acct_a_mk" }, b: { token: "tok-b", marker: "acct_b_mk" } } } },
    };
    const r = await runAutoProbe(env, { endpoints: [{ url: "/obj/6" }] });
    assert.ok(r.tried > 0);
    assert.ok(r.proven.some((v) => /no token at all reads/i.test(v.reason)), `anon leak proven deterministically: ${JSON.stringify(r.proven.map((p) => p.reason))}`);
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("graphqlArgClaims: every String argument of a root field becomes an injection claim; mutations only when asked", async () => {
  const { graphqlArgClaims } = await import("./autoprobe.js");
  const t = (kind: string, name: string | null, ofType: unknown = null) => ({ kind, name, ofType });
  const schema = JSON.stringify({ data: { __schema: {
    queryType: { name: "Q" }, mutationType: { name: "M" },
    types: [
      { name: "Q", kind: "OBJECT", fields: [
        { name: "items", type: t("LIST", null, t("OBJECT", "Item")), args: [{ name: "filter", type: t("SCALAR", "String") }, { name: "limit", type: t("SCALAR", "Int") }] },
        { name: "ping", type: t("SCALAR", "String"), args: [{ name: "msg", type: t("NON_NULL", null, t("SCALAR", "String")) }] },
      ] },
      { name: "M", kind: "OBJECT", fields: [{ name: "add", type: t("OBJECT", "Item"), args: [{ name: "title", type: t("SCALAR", "String") }] }] },
      { name: "Item", kind: "OBJECT", fields: [{ name: "id", type: t("SCALAR", "Int") }, { name: "owner", type: t("OBJECT", "User") }] },
    ],
  } } });
  const q = graphqlArgClaims(schema, "http://x/graphql", { mutations: false }).map((c) => c.detail.gql);
  assert.deepEqual(q, ['query { items(filter: "__INJECT__") { __typename id } }', 'query { ping(msg: "__INJECT__") }']);
  assert.equal(graphqlArgClaims(schema, "http://x/graphql", { mutations: true }).length, 3);
  assert.deepEqual(graphqlArgClaims("not json", "http://x/graphql", { mutations: true }), []);
});
