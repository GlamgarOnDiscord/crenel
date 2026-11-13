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

test("live probe: cookie-session auth + an owner marker proves the leak; the anonymous caller is redirected, not a finding", async () => {
  const http = await import("node:http");
  // A Flask-Login-style app: /draft/<id> serves B's object (carrying the marker
  // "admin_draft") to any caller with a valid session cookie — broken authz —
  // 302-redirects a caller with no cookie to the login page, and 404s an id that
  // does not exist. No bearer token anywhere: the identity is a session cookie.
  const server = http.createServer((req, res) => {
    const cookie = req.headers.cookie ?? "";
    if (req.url?.includes("crenel-nonexistent")) { res.writeHead(404); return res.end("not found"); }
    if (!cookie.includes("session=")) { res.writeHead(302, { location: "/login" }); return res.end(); }
    res.writeHead(200); res.end('<input name="title" value="admin_draft"><textarea>flag{x}</textarea>');
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true });
    const options = {
      "authz-matrix": {
        resources: [{ name: "draft", path: "/draft/:id", methods: ["GET"] }],
        accounts: { a: { label: "user", cookie: "session=a-valid-user-session" }, b: { label: "admin", marker: "admin_draft", owns: { draft: ["1"] } } },
      },
    };
    const found = await authzMatrix.run({ scope, projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {} });
    const proven = found.filter((f) => f.state === "proven");
    assert.equal(proven.length, 1, "A's cookie session reaching B's draft is proven once");
    const p = proven[0]!;
    assert.match(p.id, /:draft:GET:1$/);
    assert.equal(p.severity, "critical");
    assert.match(p.proof?.replay ?? "", /cookie: <A_SESSION>/, "the replay hint reflects cookie auth, not a bearer");
    assert.ok(!found.some((f) => f.id.endsWith(":anon") && f.state === "proven"), "the redirected anonymous caller is not proven");
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

test("distinct contexts: accounts that share the same custom auth headers are refused, not proven", async () => {
  const http = await import("node:http");
  // The server would hand B's object to anyone carrying the shared API key, which
  // looks like a cross-tenant leak — but A and B ARE the same identity here, so the
  // guard must refuse to prove anything.
  const server = http.createServer((_req, res) => { res.writeHead(200); res.end('{"id":"x","owner":"org_b"}'); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true });
    const key = { "x-api-key": "shared-key-123" };
    const options = { "authz-matrix": { resources: [{ name: "p", path: "/p/:id", methods: ["GET"] }], accounts: { a: { label: "A", headers: key }, b: { label: "B", headers: key, owns: { p: ["x"] } } } } };
    const found = await authzMatrix.run({ scope, projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {} });
    assert.ok(found.some((f) => f.id === "authz-matrix:same-identity" && f.state === "unproven"), "same custom headers => same-identity, refused");
    assert.equal(found.filter((f) => f.state === "proven").length, 0, "nothing is proven when A and B are one identity");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
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

test("owner-id differential over GraphQL: an anonymous caller reading objects with distinct owner-ids is proven", async () => {
  const http = await import("node:http");
  // An unauthenticated GraphQL API: paste(id) returns the object with its ownerId,
  // regardless of who asks. Distinct owners across readable ids prove broken authz.
  const owners: Record<string, number> = { "1": 1, "2": 1, "3": 2, "4": 3 };
  const server = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      const q = (() => { try { return JSON.parse(b).query as string; } catch { return ""; } })();
      const id = q.match(/id:\s*([^)\s]+)/)?.[1] ?? "";
      const o = owners[id];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: { paste: o === undefined ? null : { ownerId: o } } }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const found = await authzMatrix.run({
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }), projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, log: () => {},
      options: { "authz-matrix": { resources: [{ name: "paste", path: "/graphql", ownerField: "ownerId", gql: "{ paste(id: :id) { ownerId } }", probeIds: ["1", "3", "4"] }] } },
    });
    assert.ok(found.some((f) => f.state === "proven" && /IDOR|BOLA/i.test(f.description ?? "")), "distinct owner-ids over GraphQL prove BOLA");
  } finally { server.close(); }
});

test("owner-id differential: a single owner across all reads is NOT proven (no false positive)", async () => {
  const http = await import("node:http");
  const server = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ data: { paste: { ownerId: 1 } } })); });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const found = await authzMatrix.run({
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }), projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, log: () => {},
      options: { "authz-matrix": { resources: [{ name: "paste", path: "/graphql", ownerField: "ownerId", gql: "{ paste(id: :id) { ownerId } }", probeIds: ["1", "2", "3"] }] } },
    });
    assert.ok(!found.some((f) => f.state === "proven"), "all one owner: nothing to prove");
  } finally { server.close(); }
});

test("public route: an anonymous caller already gets B's object, so another account reaching it is NOT a proven BOLA (zero false positive)", async () => {
  const http = await import("node:http");
  // A deliberately public endpoint: GET /users/v1/<name> returns the user's
  // record (carrying the marker email) to ANY caller — bearer, wrong token, or
  // none at all — and 404s a non-existent name. Account A reaching B's record is
  // not broken authorization here: everyone can. The guard must report it as a
  // lead ("readable without authentication"), never a critical cross-tenant proof.
  const server = http.createServer((req, res) => {
    if (req.url?.includes("crenel-nonexistent")) { res.writeHead(404); return res.end('{"error":"not found"}'); }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ username: "name2", email: "mail2@mail.com" }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true });
    const options = {
      "authz-matrix": {
        resources: [{ name: "user", path: "/users/v1/:id", methods: ["GET"] }],
        accounts: { a: { label: "A", token: "tok-a", owns: { user: ["name1"] } }, b: { label: "B", marker: "mail2@mail.com", owns: { user: ["name2"] } } },
      },
    };
    const found = await authzMatrix.run({ scope, projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {} });
    assert.ok(!found.some((f) => f.state === "proven"), "a public route is never a proven cross-tenant break");
    const lead = found.find((f) => f.id.endsWith(":public"));
    assert.ok(lead, "the public route is reported as a lead");
    assert.equal(lead!.state, "unproven");
    assert.match(lead!.title, /without authentication/i);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("explicit private contract: stable anonymous access to the owner's object is proven", async () => {
  const http = await import("node:http");
  const server = http.createServer((req, res) => {
    if (req.url?.includes("crenel-nonexistent")) { res.writeHead(404); return res.end('{"error":"not found"}'); }
    if (req.headers.authorization === "Bearer tok-a") { res.writeHead(403); return res.end('{"error":"forbidden"}'); }
    res.writeHead(200, { "content-type": "application/json" }); res.end('{"id":"secret-b","owner":"org-b"}');
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const found = await authzMatrix.run({
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }), projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, log: () => {},
      options: { "authz-matrix": { resources: [{ name: "export", path: "/exports/:id", access: "private" }], accounts: { a: { label: "A", token: "tok-a" }, b: { label: "B", token: "tok-b", owns: { export: ["secret-b"] } } } } },
    });
    const proof = found.find((f) => f.id.endsWith(":anonymous"));
    assert.equal(proof?.state, "proven");
    assert.equal(proof?.severity, "high");
    assert.match(proof?.proof?.method ?? "", /declared private contract/);
    assert.match(proof?.regressionHint ?? "", /anonymous cannot GET export/);
  } finally { server.close(); }
});

test("explicit public contract is a trust-boundary decoy and is never flagged", async () => {
  const http = await import("node:http");
  const server = http.createServer((_req, res) => { res.writeHead(200); res.end('{"id":"public-b","owner":"org-b"}'); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const found = await authzMatrix.run({
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }), projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, log: () => {},
      options: { "authz-matrix": { resources: [{ name: "profile", path: "/profiles/:id", access: "public" }], accounts: { a: { label: "A", token: "tok-a" }, b: { label: "B", token: "tok-b", owns: { profile: ["public-b"] } } } } },
    });
    assert.deepEqual(found, []);
  } finally { server.close(); }
});

test("public route guard: a one-off anonymous leak (stale cache, race) does not hide a real cross-tenant break", async () => {
  const http = await import("node:http");
  // The first anonymous read of B's record leaks (a shared cache entry), every
  // later anonymous read is refused; account A keeps reading B's record. One
  // anonymous response is not enough to call the route public: A's read is a BOLA.
  let anonReads = 0;
  const server = http.createServer((req, res) => {
    if (req.url?.includes("crenel-nonexistent")) { res.writeHead(404); return res.end('{"error":"not found"}'); }
    if (!req.headers.authorization && anonReads++ > 0) { res.writeHead(401); return res.end('{"error":"auth"}'); }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ username: "name2", email: "mail2@mail.com" }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as import("node:net").AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true });
    const options = {
      "authz-matrix": {
        resources: [{ name: "user", path: "/users/v1/:id", methods: ["GET"] }],
        accounts: { a: { label: "A", token: "tok-a", owns: { user: ["name1"] } }, b: { label: "B", marker: "mail2@mail.com", owns: { user: ["name2"] } } },
      },
    };
    const found = await authzMatrix.run({ scope, projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {} });
    assert.ok(!found.some((f) => f.id.endsWith(":public")), "one anonymous leak is not a public route");
    assert.ok(found.some((f) => f.state === "proven"), "A reading B's record stays a proven cross-tenant break");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});
