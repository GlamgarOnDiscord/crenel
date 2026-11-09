import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { errorDisclosure, hasStackTrace } from "./error-disclosure.js";
import { Scope } from "../core/scope.js";

test("hasStackTrace: node/python stacks match, a clean JSON error does not", () => {
  assert.ok(hasStackTrace("at parse (/app/node_modules/body-parser/lib/x.js:89:19)\n at /app/server.js:42:10"));
  assert.ok(hasStackTrace('Traceback (most recent call last):\n  File "/srv/app.py", line 12'));
  assert.ok(!hasStackTrace('{"error":"Internal Server Error"}'));
  assert.ok(!hasStackTrace("Invalid email or password."));
});

function target(leak: boolean) {
  const read = (req: import("node:http").IncomingMessage) => new Promise<string>((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
  return createServer(async (req, res) => {
    const body = await read(req);
    let ok = true; try { JSON.parse(body || "{}"); } catch { ok = false; }
    const send = (s: number, b: string) => { res.writeHead(s, { "content-type": "text/plain" }); res.end(b); };
    if (ok) return send(400, '{"error":"missing field"}');
    return leak ? send(500, "at parse (/app/node_modules/body-parser/lib/json.js:89:19)\n at /app/server.js:42:10") : send(500, '{"error":"Internal Server Error"}');
  });
}

async function run(leak: boolean, active = true) {
  const srv = target(leak);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    return await errorDisclosure.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active }), projectDir: ".", stagingUrl: base, options: { "error-disclosure": { enabled: true, endpoints: [{ url: "/api/x" }] } }, log: () => {} });
  } finally { srv.close(); }
}

test("error-disclosure: a malformed body that returns a stack trace is proven", async () => {
  const f = await run(true);
  assert.equal(f.length, 1);
  assert.equal(f[0]!.state, "proven");
});

test("error-disclosure: a clean generic error is not flagged (no false positive)", async () => {
  const f = await run(false);
  assert.equal(f.filter((x) => x.state === "proven").length, 0);
});

test("error-disclosure: without active mode the check refuses to probe", async () => {
  await assert.rejects(() => run(true, false));
});
