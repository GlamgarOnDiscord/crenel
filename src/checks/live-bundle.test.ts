import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { liveBundle, extractAssetUrls, crawlLiveBundle } from "./live-bundle.js";
import { Scope } from "../core/scope.js";

// A deployed site stand-in: the page loads an entry chunk, which lazily imports
// a second chunk carrying a server key and pointing at a public source map.
// One script lives on an undeclared CDN host and must never be fetched.
function site() {
  const files: Record<string, [string, string]> = {
    "/": ["text/html", '<html><head><link rel="modulepreload" href="/assets/vendor-1.js"><script type="module" src="/assets/index-a1.js"></script><script src="https://cdn.undeclared.example/x.js"></script></head></html>'],
    "/assets/index-a1.js": ["application/javascript", 'const p="pk_live_51PublishableOnlyNotASecret000000";const m=()=>import("./chunk-b2.js");'],
    "/assets/vendor-1.js": ["application/javascript", "export const v=1;"],
    "/assets/chunk-b2.js": ["application/javascript", 'export const k="sk_live_51ServerKeyInALazyChunk0000000000";\n//# sourceMappingURL=chunk-b2.js.map'],
    "/assets/chunk-b2.js.map": ["application/json", '{"version":3,"sources":["src/billing.ts"],"sourcesContent":["export const k = process.env.KEY"]}'],
  };
  return createServer((req, res) => {
    const f = files[req.url ?? ""];
    if (!f) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "content-type": f[0] });
    res.end(f[1]);
  });
}

test("extracts scripts, modulepreload, dynamic imports, Next chunks and source maps", () => {
  const base = "https://app.example.com/";
  assert.deepEqual(extractAssetUrls('<script src="/a.js"></script><link rel="modulepreload" href="b.js">', base, "html").sort(), ["https://app.example.com/a.js", "https://app.example.com/b.js"]);
  assert.deepEqual(extractAssetUrls('import("./c.js");from"./d.mjs";"static/chunks/pages/e-1.js"\n//# sourceMappingURL=f.js.map', "https://app.example.com/assets/x.js", "js").sort(),
    ["https://app.example.com/_next/static/chunks/pages/e-1.js", "https://app.example.com/assets/c.js", "https://app.example.com/assets/d.mjs", "https://app.example.com/assets/f.js.map"]);
});

test("follows the chunks of the live site, finds the server key in a lazy chunk, and the public source map", async () => {
  const srv = site();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/`;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    const logs: string[] = [];
    const found = await liveBundle.run({ scope, projectDir: "/nonexistent", stagingUrl: base, options: {}, log: (m) => logs.push(m) });
    const key = found.find((f) => f.state === "proven" && f.severity === "critical");
    assert.ok(key, "the sk_live key in the lazy chunk is found");
    assert.equal(key!.location, `${base}assets/chunk-b2.js:1`);
    assert.ok(!found.some((f) => /pk_live/.test(f.title + f.location) && f.severity !== "low"), "the publishable key is not a finding");
    assert.ok(found.some((f) => f.id.includes("sourcemap") && f.location.endsWith("chunk-b2.js.map")));
    assert.ok(logs.some((l) => l.includes("cdn.undeclared.example")), "the undeclared CDN is reported as skipped");
  } finally { srv.close(); }
});

test("an undeclared host is never fetched", async () => {
  const scope = new Scope({ allowedHosts: ["app.example.com"] });
  const { files, skipped } = await crawlLiveBundle({ scope, log: () => {} }, "https://elsewhere.example.net/");
  assert.equal(files.length, 0);
  assert.deepEqual(skipped, ["elsewhere.example.net"]);
});

test("extracts API routes from client code, ids normalised to :id, multi-id routes left out", async () => {
  const { extractEndpoints } = await import("./live-bundle.js");
  const js = 'fetch(`/api/projects/${id}`);a("/api/projects");b("/v1/invoices/123/pdf");c(`/api/orgs/${o}/members/${m}`);d("/api/users/3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e?x=1");e("/static/x.png")';
  assert.deepEqual(extractEndpoints(js), ["/api/projects", "/api/projects/:id", "/api/users/:id", "/v1/invoices/:id/pdf"]);
});
