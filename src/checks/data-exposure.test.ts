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
