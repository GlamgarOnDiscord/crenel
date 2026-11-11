import { test } from "node:test";
import assert from "node:assert/strict";
import { Worker } from "node:worker_threads";
import { lastMatch, metaRefreshUrl, scriptBlocks, tagsOf } from "./html.js";

// The regex the helper replaces, kept as the parity oracle on ordinary input.
const OLD_META = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)/i;

test("metaRefreshUrl reads what the old regex read on ordinary pages", () => {
  const pages = [
    `<html><head><meta http-equiv="refresh" content="0;url=https://evil.invalid/x"></head></html>`,
    `<META HTTP-EQUIV=Refresh CONTENT='3; URL=/next'>`,
    `<meta charset=utf-8><meta name=x content=y><meta http-equiv="refresh"url=/q>`,
    `<meta http-equiv="refresh" content="5">`,
    `<meta content="0;url=/a" http-equiv="refresh">`,
    `<p>no meta</p>`,
    `<meta http-equiv=refresh content="0;url=/unclosed`,
  ];
  for (const p of pages) assert.equal(metaRefreshUrl(p), OLD_META.exec(p)?.[1] ?? null, p);
});

test("sourcePaths and the .env signature read what the old regexes read", async () => {
  const { sourcePaths } = await import("../checks/error-disclosure.js");
  const { ENV_LINE, GIT_CONFIG } = await import("../checks/exposed-files.js");
  const trace = "Error: boom\n    at f (/app/src/server/routes/users.ts:42:7)\n    at g (file:///srv/api/index.js:10:3)\n at /a/b.py:9 and C:/x/y.go:3";
  const old = /(?:\/[\w.-]+){2,}\.(?:js|ts|mjs|cjs|py|rb|php|go):\d+/g;
  assert.deepEqual(sourcePaths(trace), [...new Set([...trace.matchAll(old)].map((m) => m[0]))].slice(0, 5));
  const oldEnv = /^\s*(#.*\n\s*)*[A-Z][A-Z0-9_]{2,}\s*=\s*\S/m;
  for (const env of ["# db\n\nDATABASE_URL=postgres://x", "\uFEFFAPI_KEY=1", "  \tSTRIPE_KEY = sk", "<html>nope</html>", "lower=1\nAB=1"]) assert.equal(ENV_LINE.test(env), oldEnv.test(env), env);
  for (const g of ["[core]\n\trepositoryformatversion = 0", "x[core]y[core]repositoryformatversion", "repositoryformatversion [core]"]) assert.equal(GIT_CONFIG.test(g), /\[core\][\s\S]*repositoryformatversion/.test(g), g);
});

test("tagsOf, lastMatch, scriptBlocks", () => {
  assert.deepEqual([...tagsOf(`<a href=1><b><A HREF=2>x<a`, /<a/i)].map((t) => [t.text, t.closed]), [["<a href=1>", true], ["<A HREF=2>", true], ["<a", false]]);
  assert.equal(lastMatch("u=1 u=2 u=3", /u=(\d)/)?.[1], "3");
  assert.equal(lastMatch("none", /u=(\d)/), null);
  assert.deepEqual([...scriptBlocks(`<script>a()</script><SCRIPT type=module>b()</Script><script>never closed`)], ["a()", "b()"]);
});

// Each crafted body runs in a worker that is terminated at the deadline: a
// regression fails the test instead of hanging it (a regex cannot be interrupted).
const SIZE = 2 * 1024 * 1024; // the scoped client's body cap
function within(ms: number, mod: string, fn: string, body: string, ...rest: string[]): Promise<number> {
  const code = `const { parentPort, workerData } = require("node:worker_threads");
    import("tsx/esm/api").then((tsx) => { tsx.register(); return import(workerData.mod); }).then((m) => { const f = m[workerData.fn], t = performance.now(); f instanceof RegExp ? f.test(workerData.body) : f(workerData.body, ...workerData.rest); parentPort.postMessage(performance.now() - t); });`;
  return new Promise((resolve, reject) => {
    const w = new Worker(code, { eval: true, workerData: { mod: new URL(mod, import.meta.url).href, fn, body, rest } });
    const timer = setTimeout(() => { void w.terminate(); reject(new Error(`${fn} still running after ${ms} ms on a crafted ${body.length}-byte body`)); }, ms);
    w.once("message", (t: number) => { clearTimeout(timer); void w.terminate(); resolve(t); });
    w.once("error", (e) => { clearTimeout(timer); reject(e); });
  });
}
const pump = (unit: string, head = "") => head + unit.repeat(Math.ceil(SIZE / unit.length)).slice(0, SIZE - head.length);

// Shapes found by recheck on the old patterns, pumped to 2 MB: each old pattern
// was still running after 10 s on its body (most were quadratic or cubic). Now linear.
const CASES: [string, string, string, ...string[]][] = [
  ["./html.ts", "metaRefreshUrl", pump("<meta http-equiv=refresh ")],
  ["./html.ts", "metaRefreshUrl", pump("<meta")],
  ["../checks/directory-listing.ts", "listedFiles", pump("<a href=x ")],
  ["../checks/directory-listing.ts", "listedFiles", pump("<a")],
  ["../checks/live-bundle.ts", "extractAssetUrls", pump("<script "), "https://t.invalid/", "html"],
  ["../checks/live-bundle.ts", "extractAssetUrls", pump("<script>"), "https://t.invalid/", "html"],
  ["../checks/live-bundle.ts", "extractAssetUrls", pump("<link rel='preload' "), "https://t.invalid/", "html"],
  ["../checks/live-bundle.ts", "extractAssetUrls", "from'" + pump("a.js?"), "https://t.invalid/", "js"],
  ["../checks/live-bundle.ts", "runtimeChunkUrls", `r.p="/";"static/chunks/"+e+"."+{` + pump("a").slice(40) + `}[e]+".js"`, "https://t.invalid/"],
  ["../checks/error-disclosure.ts", "sourcePaths", pump("/a")],
  ["../checks/live-bundle.ts", "nextVersionOf", pump("0", 'window.next={version:"0.0.0')],
  ["../checks/live-bundle.ts", "nextVersionOf", pump("02", 'next/dist"12.1.0')],
  ["../checks/exposed-files.ts", "ENV_LINE", pump("\n")],
  ["../checks/exposed-files.ts", "ENV_LINE", pump("#\n")],
  ["../checks/exposed-files.ts", "GIT_CONFIG", pump("[core]")],
];

for (const [mod, fn, body, ...rest] of CASES) {
  test(`linear on a crafted 2 MB body: ${fn}(${JSON.stringify(body.slice(0, 24))}…)`, async () => {
    const ms = await within(5000, mod, fn, body, ...rest);
    assert.ok(ms < 5000);
  });
}
