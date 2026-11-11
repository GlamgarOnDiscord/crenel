import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { storedXss } from "./stored-xss.js";
import { Scope } from "../core/scope.js";
import type { CheckContext, Finding } from "../core/types.js";

function run(server: Server, options: Record<string, unknown>): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const ctx: CheckContext = {
        scope: new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: true, allowPrivate: true }),
        projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options, log: () => {},
      };
      try { resolve(await storedXss.run(ctx)); } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

const target = { "stored-xss": { enabled: true, targets: [{ name: "comment", store: { path: "/comments", body: '{"text":"{{XSS}}"}' }, serve: { path: "/comments" } }] } };

// A store that keeps the last comment and (bug) serves it back as raw HTML.
function vulnerable(): Server {
  let stored = "";
  return createServer((req, res) => {
    if (req.method === "POST" && req.url === "/comments") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { try { stored = JSON.parse(b).text; } catch { stored = ""; } res.writeHead(201); res.end('{"ok":true}'); });
      return;
    }
    res.writeHead(200, { "content-type": "text/html" }); res.end(`<ul><li>${stored}</li></ul>`); // unescaped
  });
}

test("stored-xss: markup stored and served unescaped is proven", async () => {
  const found = await run(vulnerable(), target);
  const proven = found.filter((f) => f.state === "proven");
  assert.equal(proven.length, 1, "the stored-then-served markup is the one proof");
  assert.match(proven[0]!.title, /Stored XSS/i);
  assert.equal(proven[0]!.severity, "high");
});

test("stored-xss: a store that HTML-escapes on output is not proven (no false positive)", async () => {
  let stored = "";
  const server = createServer((req, res) => {
    if (req.method === "POST") { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { try { stored = JSON.parse(b).text; } catch { stored = ""; } res.writeHead(201); res.end("{}"); }); return; }
    const esc = stored.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    res.writeHead(200, { "content-type": "text/html" }); res.end(`<ul><li>${esc}</li></ul>`);
  });
  const found = await run(server, target);
  assert.ok(!found.some((f) => f.state === "proven"), "escaped output is a lead, not a stored-XSS proof");
});

test("stored-xss: markup served back in a JSON response is not proven (no HTML context, no FP)", async () => {
  let stored = "";
  const server = createServer((req, res) => {
    if (req.method === "POST" && req.url === "/comments") { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { try { stored = JSON.parse(b).text; } catch { stored = ""; } res.writeHead(201); res.end("{}"); }); return; }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ items: [stored] })); // raw markup, but JSON
  });
  const found = await run(server, target);
  assert.ok(!found.some((f) => f.state === "proven"), "unescaped markup in a JSON data response is not executable XSS");
});

test("stored-xss: off unless active testing is enabled (scope gate holds)", async () => {
  const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowActiveTesting: false });
  await assert.rejects(
    () => storedXss.run({ scope, projectDir: "/tmp", stagingUrl: "http://127.0.0.1:1", options: target, log: () => {} }),
    /active/i,
  );
});

test("stored-xss: disabled (no enabled flag) yields nothing and sends no request", async () => {
  const found = await storedXss.run({ scope: new Scope({ allowedHosts: [] }), projectDir: "/tmp", options: {}, log: () => {} });
  assert.equal(found.length, 0);
});
