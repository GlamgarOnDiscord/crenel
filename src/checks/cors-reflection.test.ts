import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { corsReflection } from "./cors-reflection.js";
import { Scope } from "../core/scope.js";

function target(mode: "reflect-creds" | "reflect-no-creds" | "wildcard") {
  return createServer((req, res) => {
    const origin = req.headers.origin ?? "";
    const h: Record<string, string> = { "content-type": "application/json" };
    if (mode === "reflect-creds") { h["access-control-allow-origin"] = origin; h["access-control-allow-credentials"] = "true"; }
    if (mode === "reflect-no-creds") h["access-control-allow-origin"] = origin;
    if (mode === "wildcard") { h["access-control-allow-origin"] = "*"; h["access-control-allow-credentials"] = "true"; }
    res.writeHead(200, h); res.end("{}");
  });
}
async function run(mode: "reflect-creds" | "reflect-no-creds" | "wildcard") {
  const srv = target(mode);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try { return await corsReflection.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: { "cors-reflection": { paths: ["/"] } }, log: () => {} }); }
  finally { srv.close(); }
}
test("cors-reflection: reflected origin + credentials is proven", async () => {
  const f = await run("reflect-creds");
  assert.equal(f.length, 1); assert.equal(f[0]!.state, "proven");
});
test("cors-reflection: reflected origin without credentials is not flagged", async () => {
  assert.equal((await run("reflect-no-creds")).filter((x) => x.state === "proven").length, 0);
});
test("cors-reflection: static wildcard + credentials is headers.ts's job, not flagged here", async () => {
  assert.equal((await run("wildcard")).filter((x) => x.state === "proven").length, 0);
});
