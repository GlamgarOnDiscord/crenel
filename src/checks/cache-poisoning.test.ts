import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { cachePoisoning } from "./cache-poisoning.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

// A CDN in front of an app that builds its asset URL from X-Forwarded-Host.
// keyHeaders: headers the cache includes in its key; ignoreQuery: a cache that drops the query string.
function cdn({ keyHeaders = [] as string[], ignoreQuery = false } = {}) {
  const cache = new Map<string, { body: string; at: number }>();
  const seen: IncomingMessage[] = [];
  const srv = createServer((req, res) => {
    seen.push(req);
    const u = new URL(req.url!, "http://x");
    const key = (ignoreQuery ? u.pathname : u.pathname + u.search) + keyHeaders.map((h) => `|${req.headers[h] ?? ""}`).join("");
    const hit = cache.get(key);
    if (hit) { res.writeHead(200, { "x-cache": "HIT", age: "1" }); return res.end(hit.body); }
    const host = (req.headers["x-forwarded-host"] as string) ?? "app.acme.test";
    const body = `<script src="https://${host}/static/app.js"></script>`;
    cache.set(key, { body, at: Date.now() });
    res.writeHead(200, { "x-cache": "MISS" }); res.end(body);
  });
  return { srv, seen };
}
async function listen(s: ReturnType<typeof cdn>) {
  await new Promise<void>((r) => s.srv.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(s.srv.address() as AddressInfo).port}`;
}
const ctx = (base: string, opts: Record<string, unknown>, active = true): CheckContext =>
  ({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active }), projectDir: ".", stagingUrl: base, options: { "cache-poisoning": opts }, log: () => {} });

test("cache-poisoning: X-Forwarded-Host reflected and cached is proven; every request carries a crenel key", async () => {
  const s = cdn(); const base = await listen(s);
  try {
    const f = await cachePoisoning.run(ctx(base, { enabled: true }));
    assert.deepEqual(f.map((x) => x.id), ["cache-poisoning:/:x-forwarded-host"]);
    assert.equal(f[0]!.state, "proven");
    assert.ok(s.seen.every((r) => /[?&]crenel=[0-9a-f]{12}$/.test(r.url!)), "never touches the real page's cache entry");
    assert.ok(s.seen.every((r) => r.method === "GET"));
  } finally { s.srv.close(); }
});

test("cache-poisoning: a cache keyed on the header is clean", async () => {
  const s = cdn({ keyHeaders: ["x-forwarded-host"] }); const base = await listen(s);
  try { assert.equal((await cachePoisoning.run(ctx(base, { enabled: true }))).length, 0); } finally { s.srv.close(); }
});

test("cache-poisoning: a cache that ignores the query string is never poisoned (pre-check aborts)", async () => {
  const s = cdn({ ignoreQuery: true }); const base = await listen(s);
  try {
    await new Promise<void>((r) => { require_get(base, r); });
    const f = await cachePoisoning.run(ctx(base, { enabled: true }));
    assert.equal(f.length, 0);
    assert.ok(!s.seen.some((r) => r.headers["x-forwarded-host"]), "no poisoning request was sent");
  } finally { s.srv.close(); }
});

test("cache-poisoning: off unless enabled and active testing are both on", async () => {
  const s = cdn(); const base = await listen(s);
  try {
    assert.equal((await cachePoisoning.run(ctx(base, {}))).length, 0);
    assert.equal((await cachePoisoning.run(ctx(base, { enabled: true }, false))).length, 0);
    assert.equal(s.seen.length, 0);
  } finally { s.srv.close(); }
});

// Warm the real page once, as a visitor would, so the query-blind cache holds "/".
function require_get(base: string, done: () => void) { fetch(base + "/").then((r) => r.text()).then(() => done()); }
