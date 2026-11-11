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

test("data-exposure PII: >=2 other accounts' emails to an authed user while anon is refused is proven, emails redacted", async () => {
  const found = await run(serveAuth(JSON.stringify({ posts: [{ author: { email: "alice@corp.io" } }, { author: { email: "bob@corp.io" } }] }), 401), PII_OPTS);
  const proven = found.filter((f) => f.state === "proven" && /excessive data exposure/i.test(f.title));
  assert.equal(proven.length, 1, "a gated endpoint returning several accounts' emails is proven");
  assert.doesNotMatch(JSON.stringify(proven[0]!), /alice@corp\.io|bob@corp\.io/, "the email addresses are never written into the finding");
});

test("data-exposure PII: a publicly readable endpoint (anonymous not refused) is not proven", async () => {
  const found = await run(serveAuth(JSON.stringify({ posts: [{ author: { email: "alice@corp.io" } }, { author: { email: "bob@corp.io" } }] }), 200), PII_OPTS);
  assert.equal(found.filter((f) => f.state === "proven" && /excessive data/i.test(f.title)).length, 0, "a public endpoint is a lead, not a proof");
});

test("data-exposure PII: a single email (the caller's own record) is not a finding", async () => {
  const found = await run(serveAuth(JSON.stringify({ email: "me@corp.io", name: "Me" }), 401), PII_OPTS);
  assert.equal(found.filter((f) => /excessive data/i.test(f.title)).length, 0, "one email is not a cross-account leak");
});
