import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { directoryListing, isDirectoryListing, listedFiles } from "./directory-listing.js";
import { Scope } from "../core/scope.js";

test("isDirectoryListing: autoindex pages match, an SPA does not", () => {
  assert.ok(isDirectoryListing("<html><head><title>listing directory /ftp/</title></head><body>..."));
  assert.ok(isDirectoryListing("<html><body><h1>Index of /files</h1><pre>..."));
  assert.ok(!isDirectoryListing("<!DOCTYPE html><html><head><title>My App</title></head>..."));
});

test("listedFiles: pulls file names, drops parent and query links", () => {
  const body = `<a href="../">../</a> <a href="acquisitions.md">acquisitions.md</a> <a href="/ftp/notes.txt">notes.txt</a> <a href="?C=N">sort</a>`;
  const f = listedFiles(body);
  assert.ok(f.includes("acquisitions.md"));
  assert.ok(f.includes("notes.txt"));
  assert.ok(!f.includes(".."));
});

test("directory-listing: an open /ftp index that serves a confidential file is proven", async () => {
  const srv = createServer((req, res) => {
    if (req.url === "/ftp/") {
      res.writeHead(200, { "content-type": "text/html" });
      return res.end('<html><head><title>listing directory /ftp/</title></head><body><a href="../">../</a><a href="acquisitions.md">acquisitions.md</a></body></html>');
    }
    if (req.url === "/ftp/acquisitions.md") { res.writeHead(200, { "content-type": "text/markdown" }); return res.end("# Confidential acquisitions plan"); }
    res.writeHead(404); res.end("nope");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const found = await directoryListing.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: { "directory-listing": { paths: ["/ftp/"] } }, log: () => {} });
    assert.equal(found.length, 1);
    assert.equal(found[0]!.state, "proven");
    assert.match(found[0]!.description, /acquisitions\.md/);
  } finally { srv.close(); }
});

test("directory-listing: a 404 folder and an SPA produce nothing", async () => {
  const srv = createServer((req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end("<!DOCTYPE html><title>App</title><div id=root></div>"); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const found = await directoryListing.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: { "directory-listing": { paths: ["/ftp/", "/files/"] } }, log: () => {} });
    assert.equal(found.length, 0);
  } finally { srv.close(); }
});
