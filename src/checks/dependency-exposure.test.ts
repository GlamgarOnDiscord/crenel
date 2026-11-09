import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { dependencyExposure, vulnerableDeps, lowerBound } from "./dependency-exposure.js";
import { Scope } from "../core/scope.js";

test("lowerBound parses loose ranges", () => {
  assert.deepEqual(lowerBound("~8"), [8, 0, 0]);
  assert.deepEqual(lowerBound("^4.16.1"), [4, 16, 1]);
  assert.deepEqual(lowerBound("1.4.2"), [1, 4, 2]);
  assert.equal(lowerBound("git+https://x"), undefined);
});
test("vulnerableDeps flags below-patch versions, not patched ones", () => {
  assert.equal(vulnerableDeps('{"dependencies":{"lodash":"^4.17.4"}}').length, 1);
  assert.equal(vulnerableDeps('{"dependencies":{"lodash":"^4.17.21"}}').length, 0);
  assert.equal(vulnerableDeps("not json").length, 0);
});
async function run(path: string, body: string) {
  const srv = createServer((req, res) => {
    if ((req.url ?? "").split("?")[0] === path) { res.writeHead(200, { "content-type": "application/json" }); return res.end(body); }
    res.writeHead(404); res.end("no");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try { return await dependencyExposure.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: { "dependency-exposure": { paths: [path] } }, log: () => {} }); }
  finally { srv.close(); }
}
test("dependency-exposure: served manifest with a vulnerable dep is proven", async () => {
  const f = await run("/package.json.bak", '{"dependencies":{"jsonwebtoken":"~8"}}');
  assert.equal(f.length, 1); assert.equal(f[0]!.state, "proven");
});
test("dependency-exposure: a patched manifest is not flagged", async () => {
  assert.equal((await run("/package.json", '{"dependencies":{"jsonwebtoken":"^9.0.2"}}')).filter((x) => x.state === "proven").length, 0);
});
