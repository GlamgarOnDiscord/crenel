import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { dependencyExposure, vulnerableDeps, exactVersion } from "./dependency-exposure.js";
import { Scope } from "../core/scope.js";

test("exactVersion accepts only exact pins, rejects ranges and non-registry specs", () => {
  assert.deepEqual(exactVersion("1.4.2"), [1, 4, 2]);
  assert.deepEqual(exactVersion("=4.17.4"), [4, 17, 4]);
  assert.deepEqual(exactVersion("v2.0.1"), [2, 0, 1]);
  assert.equal(exactVersion("^4.16.1"), undefined); // a range is not an installed version
  assert.equal(exactVersion("~8"), undefined);
  assert.equal(exactVersion(">=1.2"), undefined);
  assert.equal(exactVersion("4.17"), undefined); // partial, not a full semver
  assert.equal(exactVersion("git+https://x"), undefined);
  assert.equal(exactVersion("github:user/lodash"), undefined);
});
test("vulnerableDeps flags only exactly-pinned below-patch versions", () => {
  // exact pin below the bound -> flagged
  assert.equal(vulnerableDeps('{"dependencies":{"lodash":"4.17.4"}}').length, 1);
  // a range whose lower bound looks old proves nothing (the resolved version may be patched)
  assert.equal(vulnerableDeps('{"dependencies":{"lodash":"^4.17.4"}}').length, 0);
  // exact pin at/above the patch -> not flagged
  assert.equal(vulnerableDeps('{"dependencies":{"lodash":"4.17.21"}}').length, 0);
  // a git/url spec is not a version
  assert.equal(vulnerableDeps('{"dependencies":{"lodash":"git+https://x"}}').length, 0);
  // a dev-only dependency is not installed/loaded in production: not proven
  assert.equal(vulnerableDeps('{"devDependencies":{"lodash":"4.17.4"}}').length, 0);
  // optionalDependencies ARE runtime
  assert.equal(vulnerableDeps('{"optionalDependencies":{"minimist":"1.2.5"}}').length, 1);
  assert.equal(vulnerableDeps("not json").length, 0);
});
test("vulnerableDeps reads exact versions from a package-lock (v1 and v2 shapes)", () => {
  assert.equal(vulnerableDeps('{"dependencies":{"minimist":{"version":"1.2.5"}}}').length, 1); // lock v1
  assert.equal(vulnerableDeps('{"packages":{"node_modules/minimist":{"version":"1.2.5"}}}').length, 1); // lock v2/v3
  assert.equal(vulnerableDeps('{"packages":{"node_modules/minimist":{"version":"1.2.6"}}}').length, 0); // patched
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
test("dependency-exposure: a served manifest with an exactly-pinned vulnerable dep is proven", async () => {
  const f = await run("/package.json.bak", '{"dependencies":{"jsonwebtoken":"8.5.1"}}');
  assert.equal(f.length, 1); assert.equal(f[0]!.state, "proven");
});
test("dependency-exposure: a patched or ranged manifest is not flagged", async () => {
  assert.equal((await run("/package.json", '{"dependencies":{"jsonwebtoken":"9.0.2"}}')).filter((x) => x.state === "proven").length, 0);
  assert.equal((await run("/package.json", '{"dependencies":{"jsonwebtoken":"^8.0.0"}}')).filter((x) => x.state === "proven").length, 0);
});
test("dependency-exposure: a JSON soft-404 without a dependency structure is not a manifest", async () => {
  assert.equal((await run("/package.json", '{"error":"not found","dependencies":"nope"}')).length, 0);
});

// Discovery via an open directory listing + a null-byte extension bypass. The
// server lists package.json.bak under /ftp/, blocks the plain .bak (extension
// filter), and serves it only through package.json.bak%2500.md — the generic
// poison-null-byte, mirroring how a real misconfigured static server behaves.
// No manifest path is configured, so only discovery can find it.
async function runListing(opts: { index: boolean; manifest?: string; bypassOnly?: boolean }) {
  const INDEX = '<html><head><title>listing directory /ftp/</title></head><body><ul>'
    + '<li><a href="coupons_2013.md.bak">coupons_2013.md.bak</a></li>'
    + '<li><a href="package.json.bak">package.json.bak</a></li></ul></body></html>';
  const srv = createServer((req, res) => {
    const u = req.url ?? "";
    if (u === "/ftp/" || u === "/ftp") { if (!opts.index) { res.writeHead(404); return res.end("no"); } res.writeHead(200, { "content-type": "text/html" }); return res.end(INDEX); }
    if (u === "/ftp/package.json.bak") { res.writeHead(403); return res.end("Error: only .md and .pdf allowed"); } // extension filter
    if (u === "/ftp/package.json.bak%2500.md" && opts.manifest) { res.writeHead(200, { "content-type": "application/json" }); return res.end(opts.manifest); }
    res.writeHead(404); res.end("no");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  // No "paths" option: the direct-path loop finds nothing, only discovery can.
  try { return await dependencyExposure.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} }); }
  finally { srv.close(); }
}
test("dependency-exposure: a manifest named in an open listing, served past an extension filter via a null byte, is proven", async () => {
  const f = await runListing({ index: true, manifest: '{"dependencies":{"sanitize-html":"1.4.2"}}' });
  assert.equal(f.length, 1);
  assert.equal(f[0]!.state, "proven");
  assert.match(f[0]!.location!, /\/ftp\/package\.json\.bak$/); // the discovered file, not a configured path
  assert.match(f[0]!.title, /sanitize-html/);
});
test("dependency-exposure: a listed manifest with only ranges is not proven", async () => {
  const f = await runListing({ index: true, manifest: '{"dependencies":{"sanitize-html":"~1.4.2","lodash":"^4.0.0"}}' });
  assert.equal(f.filter((x) => x.state === "proven").length, 0);
});
test("dependency-exposure: no proof without an open listing, even if the null-byte file would serve", async () => {
  const f = await runListing({ index: false, manifest: '{"dependencies":{"sanitize-html":"1.4.2"}}' });
  assert.equal(f.length, 0);
});
test("dependency-exposure: a listed manifest that does not actually serve is not proven", async () => {
  const f = await runListing({ index: true }); // listing names it, but no variant returns it
  assert.equal(f.length, 0);
});
