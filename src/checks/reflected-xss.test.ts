import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { reflectedXss } from "./reflected-xss.js";
import { Scope } from "../core/scope.js";

function target(mode: "raw" | "escaped" | "json") {
  const esc = (s: string) => s.replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]!));
  return createServer((req, res) => {
    const q = new URL(req.url ?? "/", "http://x").searchParams.get("q") ?? "";
    if (mode === "json") { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ q })); }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<html><body>You searched: ${mode === "raw" ? q : esc(q)}</body></html>`);
  });
}
async function run(mode: "raw" | "escaped" | "json") {
  const srv = target(mode);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try { return await reflectedXss.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: { "reflected-xss": { paths: ["/"], params: ["q"] } }, log: () => {} }); }
  finally { srv.close(); }
}
test("reflected-xss: an unescaped HTML reflection is proven", async () => {
  const f = await run("raw");
  assert.equal(f.length, 1); assert.equal(f[0]!.state, "proven");
});
test("reflected-xss: an HTML-escaped reflection is not proven", async () => {
  assert.equal((await run("escaped")).filter((x) => x.state === "proven").length, 0);
});
test("reflected-xss: a JSON response is not flagged (no HTML context)", async () => {
  assert.equal((await run("json")).filter((x) => x.state === "proven").length, 0);
});
