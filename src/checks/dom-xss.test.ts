import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { domXss } from "./dom-xss.js";
import { Scope } from "../core/scope.js";
import type { CheckContext, Finding } from "../core/types.js";

// These tests run WITHOUT a browser (none is installed in CI), so they exercise the
// gates and the graceful degradation. The actual "executes in a browser" proof is
// covered by src/agent/domxss.test.ts (the proveDomXss oracle) and by a live run.

const opts = { "dom-xss": { enabled: true, targets: [{ name: "paste", store: { path: "/graphql", body: '{"q":"{{XSS}}"}' }, serve: "/view" }] } };

function run(server: Server, options: Record<string, unknown>, active = true): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const ctx: CheckContext = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: active, allowPrivate: true }),
        projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {},
      };
      try { resolve(await domXss.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

const ok = () => createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });

test("dom-xss: with no browser available, nothing is proven (never guesses a DOM XSS)", async () => {
  // Point CRENEL_PLAYWRIGHT at a module that cannot load, so proveDomXss reports unavailable.
  const prev = process.env.CRENEL_PLAYWRIGHT;
  process.env.CRENEL_PLAYWRIGHT = "/nonexistent/playwright-crenel-test";
  try {
    const found = await run(ok(), opts);
    assert.ok(!found.some((f) => f.state === "proven"), "no browser must yield no proof, not a false positive");
  } finally { if (prev === undefined) delete process.env.CRENEL_PLAYWRIGHT; else process.env.CRENEL_PLAYWRIGHT = prev; }
});

test("dom-xss: a target that stores is gated by active testing", async () => {
  const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: false });
  await assert.rejects(
    () => domXss.run({ scope, projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: opts, log: () => {} }),
    /active/i,
  );
});

test("dom-xss: disabled yields nothing and launches no browser", async () => {
  const found = await domXss.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});

test("dom-xss: a reflected target (no store) needs no active gate", async () => {
  // No store, so no write and no active requirement; without a browser it still proves nothing.
  const prev = process.env.CRENEL_PLAYWRIGHT;
  process.env.CRENEL_PLAYWRIGHT = "/nonexistent/playwright-crenel-test";
  try {
    const found = await run(ok(), { "dom-xss": { enabled: true, targets: [{ name: "hash", serve: "/#q={{XSS}}" }] } }, false);
    assert.equal(found.length, 0);
  } finally { if (prev === undefined) delete process.env.CRENEL_PLAYWRIGHT; else process.env.CRENEL_PLAYWRIGHT = prev; }
});
