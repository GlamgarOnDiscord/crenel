import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { vulnLibs, cmpVersion, inRange, exactVersion, advisoriesFor, detectContent, detectUrl, isVersionedCdn, RETIRE_DB, type RetireDb } from "./vuln-libs.js";
import { Scope } from "../core/scope.js";
import type { CheckContext, Finding } from "../core/types.js";

// The head of the official jquery-2.2.4.min.js (MIT) with its banner comment
// removed, as a minifier or bundler leaves it: no comment, no file name, only
// the code shape retire.js keys on (`m="2.2.4",…n.fn=n.prototype={jquery:m,`).
const minifiedJquery = (version: string) => `!function(a,b){"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a document");return b(a)}:b(a)}("undefined"!=typeof window?window:this,function(a,b){var c=[],d=a.document,e=c.slice,f=c.concat,g=c.push,h=c.indexOf,i={},j=i.toString,k=i.hasOwnProperty,l={},m="${version}",n=function(a,b){return new n.fn.init(a,b)},o=/^[\\s\\uFEFF\\xA0]+|[\\s\\uFEFF\\xA0]+$/g,p=/^-ms-/,q=/-([\\da-z])/gi,r=function(a,b){return b.toUpperCase()};n.fn=n.prototype={jquery:m,constructor:n,selector:"",length:0,toArray:function(){return e.call(this)}};return n});`;

test("cmpVersion orders releases and pre-releases", () => {
  assert.ok(cmpVersion("1.6.1", "1.6.3") < 0);
  assert.ok(cmpVersion("1.10.0", "1.9.0") > 0);
  assert.equal(cmpVersion("2.2.4", "2.2.4"), 0);
  assert.equal(cmpVersion("3.5", "3.5.0"), 0);
  assert.ok(cmpVersion("1.9.0b1", "1.9.0") < 0, "a pre-release sorts below the release");
  assert.ok(cmpVersion("3.0.0-beta1", "3.0.0-rc.1") < 0);
  assert.ok(cmpVersion("15.0.0-canary.9", "15.0.0-canary.206") < 0, "tag numbers compare numerically");
  assert.ok(cmpVersion("3.0.0", "3.0.0-rc.1") > 0);
});

test("inRange is atOrAbove <= v < below, and needs an upper bound", () => {
  assert.ok(inRange("1.6.1", { below: "1.6.3" }));
  assert.ok(!inRange("1.6.3", { below: "1.6.3" }), "the fixed release itself is not vulnerable");
  assert.ok(inRange("1.7.0", { atOrAbove: "1.4.0", below: "2.0.0" }));
  assert.ok(!inRange("1.3.0", { atOrAbove: "1.4.0", below: "2.0.0" }));
  assert.ok(!inRange("1.0.0", {}), "an empty range matches nothing");
  assert.ok(!inRange("9.0.0", { atOrAbove: "1.0.0" }), "no upper bound, no proof");
});

test("exactVersion keeps exact releases and rejects what is not one", () => {
  assert.equal(exactVersion("2.2.4"), "2.2.4");
  assert.equal(exactVersion("1.6.1.min"), "1.6.1", "a file name's .min is not part of the version");
  assert.equal(exactVersion("2.18.0-min"), "2.18.0");
  assert.equal(exactVersion("3.0.0-rc.1"), "3.0.0-rc.1");
  assert.equal(exactVersion("1.9.0b1"), "1.9.0-b1");
  assert.equal(exactVersion("3"), undefined, "a major alone is a range");
  assert.equal(exactVersion("3.4", 3), undefined, "x.y in a URL is a range");
  assert.equal(exactVersion("1.2.3-custom"), undefined, "an unknown suffix (a fork, a backport) proves nothing");
  assert.equal(exactVersion("2.x"), undefined);
});

test("advisoriesFor: only documented advisories (CVE/GHSA) inside the range count", () => {
  const entry = { vulnerabilities: [{ below: "2.0.0", summary: "end of life" }, { below: "2.0.0", cve: ["CVE-0000-0001"] }, { atOrAbove: "2.0.0", below: "3.0.0", ghsa: "GHSA-xxxx" }] };
  assert.deepEqual(advisoriesFor(entry, "1.5.0").map((a) => a.cve?.[0] ?? a.ghsa), ["CVE-0000-0001"]);
  assert.deepEqual(advisoriesFor(entry, "2.5.0").map((a) => a.cve?.[0] ?? a.ghsa), ["GHSA-xxxx"]);
  assert.deepEqual(advisoriesFor(entry, "3.0.0"), []);
  assert.deepEqual(advisoriesFor(undefined, "1.0.0"), []);
});

test("detectContent: a banner, and a MINIFIED bundle with no banner (code-shape signature)", async () => {
  assert.deepEqual((await detectContent(RETIRE_DB, "/*! jQuery v1.6.1 | (c) jQuery */ var x=1;"))!.map((d) => [d.lib, d.version, d.via]), [["jquery", "1.6.1", "content"]]);
  const min = minifiedJquery("2.2.4");
  assert.ok(!/\/\*|jquery v/i.test(min), "the fixture has no comment and no banner");
  assert.deepEqual((await detectContent(RETIRE_DB, min))!.map((d) => [d.lib, d.version, d.via]), [["jquery", "2.2.4", "content"]]);
  // Wrapped in a bundler's module table, the same signature still reads it.
  const bundled = `(self.webpackChunkapp=self.webpackChunkapp||[]).push([[179],{4321:function(t,e,r){${min}},77:function(t){t.exports=function(){return 1}}}]);`;
  assert.deepEqual((await detectContent(RETIRE_DB, bundled))!.map((d) => `${d.lib}@${d.version}`), ["jquery@2.2.4"]);
});

test("detectContent: no version literal, no detection", async () => {
  assert.deepEqual(await detectContent(RETIRE_DB, "var app={};function boot(){return app}"), []);
  // The library's code shape with the version literal removed (tree-shaken, renamed).
  assert.deepEqual(await detectContent(RETIRE_DB, minifiedJquery("2.2.4").replace('m="2.2.4"', "m=void 0")), []);
  // A version that is not an exact release is not a detection.
  assert.deepEqual(await detectContent(RETIRE_DB, minifiedJquery("2.x")), []);
});

test("detectContent: a whole-file SHA-1 from the signature set names the release", async () => {
  const file = "var legacy=function(){return 42};";
  const db: RetireDb = { legacylib: { hashes: { [createHash("sha1").update(file).digest("hex")]: "1.0.2" }, vulnerabilities: [{ below: "1.1.0", cve: ["CVE-0000-0002"] }] } };
  assert.deepEqual((await detectContent(db, file))!.map((d) => [d.lib, d.version, d.via]), [["legacylib", "1.0.2", "hash"]]);
  assert.deepEqual(await detectContent(db, file + " "), [], "one byte off is another file");
});

test("detectContent: a signature that does not finish is cut off, not waited for", async () => {
  const db: RetireDb = { slow: { filecontent: ["^(a+)+$(§§version§§)"], vulnerabilities: [{ below: "9.0.0", cve: ["CVE-0000-0003"] }] } };
  const t = Date.now();
  assert.equal(await detectContent(db, "a".repeat(40) + "!", 300), null);
  assert.ok(Date.now() - t < 5000);
});

test("detectUrl: file name and CDN path, full x.y.z only", () => {
  const one = (u: string) => detectUrl(RETIRE_DB, u).map((d) => `${d.lib}@${d.version}`);
  assert.deepEqual(one("http://x.test/js/jquery-1.6.1.min.js"), ["jquery@1.6.1"]);
  assert.deepEqual(one("https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"), ["jquery@2.2.4"]);
  assert.deepEqual(one("https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2/jquery.min.js"), [], "x.y is a range");
  assert.deepEqual(one("http://x.test/app.js"), []);
  assert.ok(isVersionedCdn("https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"));
  assert.ok(!isVersionedCdn("https://static.example.com/2.2.4/jquery.min.js"));
});

function run(server: Server): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const ctx: CheckContext = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }),
        projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options: {}, log: () => {},
      };
      try { resolve(await vulnLibs.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

/** A site whose home page is `html` and whose other paths come from `files`. */
function site(html: string, files: Record<string, string> = {}, hits: string[] = []): Server {
  return createServer((req, res) => {
    hits.push(req.url ?? "");
    if (req.url === "/") { res.writeHead(200, { "content-type": "text/html" }); return res.end(html); }
    const body = files[req.url ?? ""];
    if (body !== undefined) { res.writeHead(200, { "content-type": "application/javascript" }); return res.end(body); }
    res.writeHead(404); res.end();
  });
}
const page = (src: string) => `<html><body><script src="${src}"></script></body></html>`;
const proven = (f: Finding[]) => f.filter((x) => x.state === "proven");

test("vuln-libs: a served vulnerable jQuery (banner) is proven with its CVE", async () => {
  const found = await run(site(page("/app.js"), { "/app.js": "/*! jQuery v1.6.1 | (c) jQuery */ var x=1;" }));
  assert.equal(found.length, 1);
  assert.equal(found[0]!.state, "proven");
  assert.equal(found[0]!.id, "vuln-libs:jquery:1.6.1");
  assert.match(found[0]!.proof?.evidence ?? "", /CVE-2011-4969/);
  assert.match(found[0]!.proof?.replay ?? "", /^curl -s 'http:\/\/127\.0\.0\.1:\d+\/app\.js' \| grep -c -F -- '/);
});

test("vuln-libs: a MINIFIED bundle with no banner and a hashed file name is proven by its code-shape signature", async () => {
  const found = await run(site(page("/main.5f3a9c1e.js"), { "/main.5f3a9c1e.js": minifiedJquery("2.2.4") }));
  assert.equal(proven(found).length, 1);
  assert.equal(found[0]!.id, "vuln-libs:jquery:2.2.4");
  assert.match(found[0]!.proof?.evidence ?? "", /CVE-2020-11022/);
  assert.match(found[0]!.description, /Fixed from 3\.5\.0/);
});

test("vuln-libs: a chunk the entry script imports is scanned too", async () => {
  const found = await run(site(page("/entry.js"), { "/entry.js": 'import("./vendor.js");', "/vendor.js": minifiedJquery("2.2.4") }));
  assert.deepEqual(proven(found).map((f) => f.id), ["vuln-libs:jquery:2.2.4"]);
});

test("vuln-libs control: the PATCHED version of the same library is not a finding (banner and minified)", async () => {
  assert.deepEqual(await run(site(page("/app.js"), { "/app.js": "/*! jQuery v3.7.1 | (c) OpenJS Foundation */ var x=1;" })), []);
  // Same minified code, same signature, only the version differs: the fixed release.
  assert.deepEqual(await run(site(page("/app.js"), { "/app.js": minifiedJquery("3.5.0") })), []);
});

test("vuln-libs control: a library with no detectable version yields nothing", async () => {
  assert.deepEqual(await run(site(page("/app.js"), { "/app.js": "var app = {}; // no library banner here" })), []);
  assert.deepEqual(await run(site(page("/app.js"), { "/app.js": minifiedJquery("2.2.4").replace('m="2.2.4"', "m=void 0") })), []);
});

test("vuln-libs: a version only the self-hosted file name states is a lead, never proven", async () => {
  const found = await run(site(page("/js/jquery-1.6.1.min.js"), { "/js/jquery-1.6.1.min.js": "var renamed=1;" }));
  assert.equal(found.length, 1);
  assert.equal(found[0]!.state, "unproven");
  assert.equal(found[0]!.severity, "low");
});

test("vuln-libs control: a vulnerable-looking file name over patched content is not a finding", async () => {
  assert.deepEqual(await run(site(page("/js/jquery-1.6.1.min.js"), { "/js/jquery-1.6.1.min.js": "/*! jQuery v3.7.1 | (c) OpenJS Foundation */" })), []);
});

test("vuln-libs: a script loaded from an immutable versioned CDN is proven from its URL, without fetching the CDN", async () => {
  const hits: string[] = [];
  const found = await run(site(page("//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"), {}, hits));
  assert.deepEqual(proven(found).map((f) => f.id), ["vuln-libs:jquery:2.2.4"]);
  assert.equal(found[0]!.location, "http://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js");
  assert.deepEqual(hits, ["/"], "only the declared host was requested");
});

test("vuln-libs control: off-scope scripts that prove nothing", async () => {
  // Patched release on the CDN.
  assert.deepEqual(await run(site(page("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"))), []);
  // An unknown third-party host: its path may mean anything, so a lead at most.
  const other = await run(site(page("https://static.example.com/2.2.4/jquery.min.js")));
  assert.deepEqual(other.map((f) => f.state), ["unproven"]);
  // A commented-out tag is not loaded by anyone.
  assert.deepEqual(await run(site('<html><!-- <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script> --></html>')), []);
});

test("vuln-libs control: an HTML page answering a script URL (SPA fallback) is not scanned", async () => {
  const s = createServer((_req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end(`${page("/app.js")}<pre>/*! jQuery v1.6.1 */</pre>`); });
  assert.deepEqual(await run(s), []);
});

test("vuln-libs: the embedded signature set is the generic retire.js repository", () => {
  const libs = Object.keys(RETIRE_DB);
  assert.ok(libs.length >= 50, `${libs.length} libraries`);
  for (const [name, e] of Object.entries(RETIRE_DB)) for (const v of e.vulnerabilities) assert.ok(v.below && ((v.cve?.length ?? 0) > 0 || v.ghsa), `${name}: every advisory has an upper bound and a CVE/GHSA id`);
});
