import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { devServer } from "./dev-server.js";
import { Scope } from "../core/scope.js";

function serve(handler: (url: string) => { status: number; body: string } | null) {
  return createServer((req, res) => {
    const r = handler(req.url ?? "/");
    if (!r) { res.writeHead(404); return res.end("not found"); }
    res.writeHead(r.status); res.end(r.body);
  });
}

async function run(server: ReturnType<typeof serve>) {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
  try {
    return await devServer.run({ scope, projectDir: "/tmp", stagingUrl: `http://127.0.0.1:${port}`, options: {}, log: () => {} });
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

test("dev-server: an exposed Werkzeug debugger is proven, with Flask-specific remediation", async () => {
  // Flask debug=True serves the debugger's own JS through the magic query.
  const server = serve((url) =>
    url.includes("__debugger__=yes") && url.includes("f=debugger.js")
      ? { status: 200, body: "docReady(() => { if (!EVALEX_TRUSTED) { initPinBox(); } if (CONSOLE_MODE && EVALEX) { createInteractiveConsole(); } });" }
      : url === "/" ? { status: 200, body: '{"message":"VAmPI"}' } : null,
  );
  const found = await run(server);
  const proven = found.filter((f) => f.state === "proven");
  assert.equal(proven.length, 1, "the exposed debugger is the one finding");
  assert.match(proven[0]!.title, /Werkzeug debugger/);
  assert.equal(proven[0]!.severity, "high");
  assert.match(proven[0]!.remediation ?? "", /debug off|FLASK_DEBUG/, "Flask users are told to turn debug off, not to run vite build");
  assert.doesNotMatch(proven[0]!.remediation ?? "", /vite|next build/i);
});

test("dev-server: an app NOT in debug mode (404 on the magic query) is not a finding", async () => {
  const server = serve((url) => (url === "/" ? { status: 200, body: '{"ok":true}' } : null));
  const found = await run(server);
  assert.equal(found.length, 0, "no debugger, nothing proven");
});

test("dev-server: a page that merely mentions debugging, without the debugger markers, is not a finding (no false positive)", async () => {
  // A 200 on the magic query, with the word "debug" but none of the Werkzeug
  // debugger's own markers; every other path 404s, so only the signature decides.
  const server = serve((url) =>
    url.includes("__debugger__=yes")
      ? { status: 200, body: "<html>Enable debug logging in settings; this is not a console.</html>" }
      : null,
  );
  const found = await run(server);
  assert.ok(!found.some((f) => /Werkzeug/.test(f.title)), "a prose mention of debug is not the debugger");
});
