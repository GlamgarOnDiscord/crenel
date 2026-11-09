import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { headerInjection } from "./header-injection.js";
import { Scope } from "../core/scope.js";

function target(vuln: boolean) {
  return createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const raw = decodeURIComponent(u.searchParams.get("next") ?? "");
    if (vuln && raw.includes("\r\n")) {
      const extra = raw.split("\r\n").slice(1).join("\r\n");
      res.socket!.write(`HTTP/1.1 302 Found\r\nLocation: ${raw.split("\r\n")[0]}\r\n${extra}\r\nContent-Length: 0\r\n\r\n`);
      return res.socket!.end();
    }
    res.writeHead(302, { location: raw.replace(/[\r\n]/g, "") }); res.end();
  });
}
async function run(vuln: boolean) {
  const srv = target(vuln);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try { return await headerInjection.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: { "header-injection": { paths: ["/"], params: ["next"] } }, log: () => {} }); }
  finally { srv.close(); }
}
test("header-injection: a CRLF that adds a response header is proven", async () => {
  const f = await run(true);
  assert.equal(f.length, 1); assert.equal(f[0]!.state, "proven");
});
test("header-injection: a server that strips CR/LF is not flagged", async () => {
  assert.equal((await run(false)).filter((x) => x.state === "proven").length, 0);
});
