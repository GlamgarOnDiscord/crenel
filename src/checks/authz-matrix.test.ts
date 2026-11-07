import { test } from "node:test";
import assert from "node:assert/strict";
import { authzMatrix } from "./authz-matrix.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(partial: Partial<CheckContext> & { options?: Record<string, unknown> } = {}): CheckContext {
  return {
    scope: partial.scope ?? new Scope({ allowedHosts: [] }),
    projectDir: partial.projectDir ?? "/tmp/x",
    stagingUrl: partial.stagingUrl,
    options: partial.options ?? {},
    log: () => {},
  };
}

const RESOURCES = {
  "authz-matrix": {
    resources: [{ name: "project", path: "/api/projects/:id", methods: ["GET", "DELETE"] }],
    accounts: { a: { label: "A", token: "tok" }, b: { label: "B", owns: { project: ["p_b_1"] } } },
  },
};

test("no resources declared yields no findings", async () => {
  const found = await authzMatrix.run(ctx());
  assert.equal(found.length, 0);
});

test("offline, it emits one unproven plan with a generated test matrix", async () => {
  const found = await authzMatrix.run(ctx({ options: RESOURCES }));
  assert.equal(found.length, 1);
  const f = found[0];
  assert.ok(f);
  assert.equal(f.id, "authz-matrix:offline-plan");
  assert.equal(f.state, "unproven");
  assert.equal(f.severity, "medium");
  // the plan carries a runnable test that names the resource and both methods
  const gen = f.regressionHint ?? "";
  assert.match(gen, /\/api\/projects\/:id/);
  assert.match(gen, /GET another account/);
  assert.match(gen, /DELETE another account/);
  assert.match(gen, /\[401, 403, 404\]/);
});

test("a declared staging probe is refused unless active testing is enabled", async () => {
  // stagingUrl + token + cases => it would probe, but the scope gate must hold.
  const scope = new Scope({ allowedHosts: ["staging.example.com"], allowActiveTesting: false });
  await assert.rejects(
    () => authzMatrix.run(ctx({ scope, stagingUrl: "https://staging.example.com", options: RESOURCES })),
    /active/i,
  );
});

test("live probe: B's object returned to A is proven; a 403 or a soft 404 is not", async () => {
  const http = await import("node:http");
  // A tiny staging stand-in. /leak returns B's object to anyone with a token
  // (broken authz), /safe returns 403, /soft answers every id, real or not,
  // with the same 200 error page (a soft 404, not a leak).
  const server = http.createServer((req, res) => {
    const auth = req.headers.authorization;
    if (req.url?.endsWith("/leak") && auth) { res.writeHead(200); res.end('{"id":"leak","owner":"org_b"}'); }
    else if (req.url?.includes("/soft") || req.url?.includes("crenel-nonexistent")) { res.writeHead(200); res.end('{"ok":false}'); }
    else { res.writeHead(403); res.end("denied"); }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true });
    const options = {
      "authz-matrix": {
        resources: [{ name: "project", path: "/api/projects/:id", methods: ["GET"] }],
        accounts: { a: { label: "A", token: "tok-a" }, b: { label: "B", token: "tok-b", owns: { project: ["leak", "safe", "soft"] } } },
      },
    };
    const found = await authzMatrix.run({
      scope, projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {},
    });
    const proven = found.filter((f) => f.state === "proven");
    assert.equal(proven.length, 1, "only B's object handed to A is proven");
    assert.match(proven[0]!.id, /:leak$/);
    assert.equal(proven[0]!.severity, "critical");
    assert.ok(!found.some((f) => f.id.includes(":safe")), "the 403 case is not a finding");
    assert.ok(!found.some((f) => f.id.includes(":soft") && f.state === "proven"), "a soft 404 is never proven");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("discoverIds finds ids shaped like B's declared ones (prefix or UUID), nothing for undeclared shapes", async () => {
  const { discoverIds } = await import("./authz-matrix.js");
  const resources = [{ name: "file", path: "/f/:id" }, { name: "user", path: "/u/:id" }, { name: "note", path: "/n/:id" }];
  const body = '{"files":["file_b_9","file_b_10"],"owner":"3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e","note":"note_x"}';
  const got = discoverIds(body, resources, { file: ["file_b_1"], user: ["11111111-2222-4333-8444-555555555555"] }).map((d) => `${d.resource.name}:${d.id}`);
  assert.deepEqual(got, ["file:file_b_9", "file:file_b_10", "user:3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e"]);
});

test("distinct contexts: identical tokens, or JWTs with the same sub, are refused before any probe", async () => {
  const { sameIdentity } = await import("./authz-matrix.js");
  const jwt = (sub: string, n: string) => `x.${Buffer.from(JSON.stringify({ sub, n })).toString("base64url")}.y`;
  assert.equal(sameIdentity("t", "t"), "are identical");
  assert.match(sameIdentity(jwt("u1", "a"), jwt("u1", "b"))!, /sub=u1/);
  assert.equal(sameIdentity(jwt("u1", "a"), jwt("u2", "a")), null);
});

test("a route that leaks only once in three replays is not proven", async () => {
  const http = await import("node:http");
  let n = 0;
  const server = http.createServer((req, res) => {
    if (req.headers.authorization === "Bearer tok-b") { res.writeHead(200); return res.end('{"id":"x","owner":"org_b"}'); }
    if (req.url?.includes("crenel-nonexistent")) { res.writeHead(404); return res.end(); }
    n++;
    if (req.headers.authorization === "Bearer tok-a" && n === 1) { res.writeHead(200); return res.end('{"id":"x","owner":"org_b"}'); }
    res.writeHead(403); res.end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const found = await authzMatrix.run({
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }), projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, log: () => {},
      options: { "authz-matrix": { resources: [{ name: "p", path: "/p/:id" }], accounts: { a: { label: "A", token: "tok-a" }, b: { label: "B", token: "tok-b", owns: { p: ["x"] } } } } },
    });
    assert.ok(!found.some((f) => f.state === "proven"), "a one-off 200 is not a proof");
  } finally { server.close(); }
});
