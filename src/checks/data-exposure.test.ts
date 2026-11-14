import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { dataExposure } from "./data-exposure.js";
import { Scope } from "../core/scope.js";
import type { CheckContext, Finding } from "../core/types.js";

function run(server: Server, body: Record<string, unknown>): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const ctx: CheckContext = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }),
        projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options: { "data-exposure": { endpoints: ["/_debug"] } }, log: () => {},
        ...body,
      } as CheckContext;
      try { resolve(await dataExposure.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

function serve(payload: string): Server {
  return createServer((_req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(payload); });
}

test("data-exposure: an endpoint returning multiple plaintext passwords is proven", async () => {
  const found = await run(serve(JSON.stringify({ users: [{ username: "a", password: "pass1" }, { username: "b", password: "hunter2" }] })), {});
  const proven = found.filter((f) => f.state === "proven");
  assert.equal(proven.length, 1);
  assert.match(proven[0]!.title, /plaintext passwords/i);
  assert.equal(proven[0]!.severity, "critical");
  assert.doesNotMatch(JSON.stringify(proven[0]!), /pass1|hunter2/, "the password values are never written into the finding");
});

test("data-exposure: a column of bcrypt hashes is not a finding (hashes are not plaintext)", async () => {
  const found = await run(serve(JSON.stringify({ users: [{ password: "$2b$10$abcdefghijklmnopqrstuv" }, { password: "$2b$10$zyxwvutsrqponmlkjihgfe" }] })), {});
  assert.ok(!found.some((f) => f.state === "proven"), "hashed passwords are not a plaintext leak");
});

test("data-exposure: a single password-shaped field is a lead, not proven (no false positive)", async () => {
  const found = await run(serve(JSON.stringify({ form: { password: "" }, label: "password" })), {});
  assert.ok(!found.some((f) => f.state === "proven"), "one field is not an excessive-exposure proof");
});

test("data-exposure: no endpoints declared yields nothing", async () => {
  const found = await dataExposure.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});

function serveAuth(authBody: string, anonStatus: number): Server {
  return createServer((req, res) => {
    if (!req.headers.authorization) { res.writeHead(anonStatus); res.end("{}"); return; }
    res.writeHead(200, { "content-type": "application/json" }); res.end(authBody);
  });
}
const PII_OPTS = { options: { "data-exposure": { endpoints: ["/_debug"], pii: true, as: "a" }, "authz-matrix": { accounts: { a: { token: "tok-a" } } } } };

test("data-exposure PII: several emails plus an anonymous denial is a lead without a privacy contract", async () => {
  const found = await run(serveAuth(JSON.stringify({ posts: [{ author: { email: "alice@corp.io" } }, { author: { email: "bob@corp.io" } }] }), 401), PII_OPTS);
  const pii = found.filter((f) => /excessive data exposure/i.test(f.title));
  assert.equal(pii.length, 1);
  assert.equal(pii[0]!.state, "unproven", "a member directory can legitimately return several emails");
  assert.doesNotMatch(JSON.stringify(pii[0]!), /alice@corp\.io|bob@corp\.io/, "the email addresses are never written into the finding");
});

test("data-exposure PII: an explicit owner-only contract proves a foreign-owner record", async () => {
  const previous = process.env.CRENEL_TEST_OWNER;
  process.env.CRENEL_TEST_OWNER = "user-a";
  try {
    const options = { options: { "data-exposure": { endpoints: ["/_debug"], pii: { policy: "owner-only", ownerField: "ownerId", ownerValueEnv: "CRENEL_TEST_OWNER" }, as: "a" }, "authz-matrix": { accounts: { a: { token: "tok-a" } } } } };
    const payload = JSON.stringify({ records: [{ ownerId: "user-a", email: "me@corp.io" }, { ownerId: "user-b", email: "other@corp.io" }] });
    const found = await run(serveAuth(payload, 401), options);
    const proof = found.find((f) => f.state === "proven" && /owner-only/i.test(f.title));
    assert.ok(proof);
    assert.doesNotMatch(JSON.stringify(proof), /me@corp\.io|other@corp\.io|user-a|user-b/);
    assert.match(proof!.proof?.replay ?? "", /jq --arg owner "\$CRENEL_TEST_OWNER"/);
    assert.match(proof!.proof?.replay ?? "", /--arg field 'ownerId'/);
  } finally { if (previous === undefined) delete process.env.CRENEL_TEST_OWNER; else process.env.CRENEL_TEST_OWNER = previous; }
});

test("data-exposure PII: owner-only proof requires credentials for the declared owner", async () => {
  const previous = process.env.CRENEL_TEST_OWNER;
  process.env.CRENEL_TEST_OWNER = "user-a";
  try {
    const options = { options: { "data-exposure": { endpoints: ["/_debug"], pii: { policy: "owner-only", ownerField: "ownerId", ownerValueEnv: "CRENEL_TEST_OWNER" } } } };
    const payload = JSON.stringify({ records: [{ ownerId: "user-a", email: "me@corp.io" }, { ownerId: "user-b", email: "other@corp.io" }] });
    const found = await run(serve(payload), options);
    assert.ok(!found.some((f) => f.state === "proven" && /owner-only/i.test(f.title)));
    assert.ok(found.some((f) => f.state === "unproven" && /personal emails/i.test(f.title)));
  } finally { if (previous === undefined) delete process.env.CRENEL_TEST_OWNER; else process.env.CRENEL_TEST_OWNER = previous; }
});

test("data-exposure PII: a declared canary has a contract-specific replay", async () => {
  const previous = process.env.CRENEL_TEST_PII_CANARY;
  process.env.CRENEL_TEST_PII_CANARY = "private-canary-value";
  try {
    const options = { options: { "data-exposure": { endpoints: ["/_debug"], pii: { policy: "canary", canaryEnv: "CRENEL_TEST_PII_CANARY" }, as: "a" }, "authz-matrix": { accounts: { a: { token: "tok-a" } } } } };
    const found = await run(serveAuth(JSON.stringify({ nested: { value: "private-canary-value" } }), 401), options);
    const proof = found.find((f) => f.state === "proven" && /canary/i.test(f.title));
    assert.ok(proof);
    assert.match(proof!.proof?.replay ?? "", /jq --arg canary "\$CRENEL_TEST_PII_CANARY"/);
    assert.doesNotMatch(JSON.stringify(proof), /private-canary-value/);
  } finally { if (previous === undefined) delete process.env.CRENEL_TEST_PII_CANARY; else process.env.CRENEL_TEST_PII_CANARY = previous; }
});

test("data-exposure PII: a publicly readable endpoint (anonymous not refused) is not proven", async () => {
  const found = await run(serveAuth(JSON.stringify({ posts: [{ author: { email: "alice@corp.io" } }, { author: { email: "bob@corp.io" } }] }), 200), PII_OPTS);
  assert.equal(found.filter((f) => f.state === "proven" && /excessive data/i.test(f.title)).length, 0, "a public endpoint is a lead, not a proof");
});

test("data-exposure sends token and cookie together and replays both", async () => {
  const server = createServer((req, res) => {
    if (req.headers.authorization !== "Bearer tok-a" || req.headers.cookie !== "sid=a") { res.writeHead(401); return res.end("{}"); }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ users: [{ password: "pass-one" }, { password: "pass-two" }] }));
  });
  const found = await run(server, { options: { "data-exposure": { endpoints: ["/_debug"], as: "a" }, "authz-matrix": { accounts: { a: { token: "tok-a", cookie: "sid=a" } } } } });
  const proof = found.find((f) => f.state === "proven");
  assert.ok(proof);
  assert.match(proof!.proof?.replay ?? "", /authorization: Bearer <SESSION_TOKEN>/);
  assert.match(proof!.proof?.replay ?? "", /cookie: <SESSION_COOKIE>/);
});

test("data-exposure resolves only the selected account's login", async () => {
  let unwantedLogins = 0;
  const server = createServer((req, res) => {
    if (req.url === "/login-b") { unwantedLogins++; res.writeHead(500); return res.end("{}"); }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ users: [{ password: "pass-one" }, { password: "pass-two" }] }));
  });
  const previous = process.env.CRENEL_TEST_B_PASSWORD;
  process.env.CRENEL_TEST_B_PASSWORD = "b-password";
  try {
    const found = await run(server, { options: {
      "data-exposure": { endpoints: ["/_debug"], as: "a" },
      "authz-matrix": { accounts: { a: { token: "tok-a" }, b: { login: { url: "/login-b", username: "b", passwordEnv: "CRENEL_TEST_B_PASSWORD" } } } },
    } });
    assert.ok(found.some((f) => f.state === "proven"));
    assert.equal(unwantedLogins, 0);
  } finally { if (previous === undefined) delete process.env.CRENEL_TEST_B_PASSWORD; else process.env.CRENEL_TEST_B_PASSWORD = previous; }
});

test("data-exposure PII: a single email (the caller's own record) is not a finding", async () => {
  const found = await run(serveAuth(JSON.stringify({ email: "me@corp.io", name: "Me" }), 401), PII_OPTS);
  assert.equal(found.filter((f) => /excessive data/i.test(f.title)).length, 0, "one email is not a cross-account leak");
});
