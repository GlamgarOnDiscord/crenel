import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { openRedirect } from "./open-redirect.js";
import { Scope } from "../core/scope.js";

test("a login that redirects to any ?next= URL is proven; a fixed redirect is not; nothing is followed", async () => {
  const hits: string[] = [];
  const srv = createServer((req, res) => {
    hits.push(req.url ?? "");
    const u = new URL(req.url ?? "/", "http://x");
    if (u.pathname === "/login" && u.searchParams.get("next")) { res.writeHead(302, { location: u.searchParams.get("next")! }); return res.end(); }
    if (u.pathname === "/logout" && u.searchParams.get("returnTo")) { res.writeHead(302, { location: "/goodbye" }); return res.end(); }
    res.writeHead(200); res.end("ok");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const found = await openRedirect.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });
    assert.deepEqual(found.map((f) => f.id), ["open-redirect:/login:next"]);
    assert.ok(!hits.some((h) => h.startsWith("/goodbye")), "redirects are read, never followed");
  } finally { srv.close(); }
});
