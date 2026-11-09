import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { liveSsrf } from "./live-ssrf.js";
import { Scope } from "../core/scope.js";

// A target whose endpoint fetches the URL built from the body (a stand-in SSRF
// sink). The check must see the out-of-band hit and prove it; a target that does
// not call out stays unproven.
function ssrfTarget(vulnerable: boolean) {
  return createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", async () => {
      if (vulnerable) {
        const m = b.match(/http:\/\/[^"\\\s]+/); // the callback URL the check injected
        if (m) { try { await fetch(m[0]); } catch { /* ignore */ } }
      }
      res.writeHead(200, { "content-type": "application/json" }); res.end('{"ok":true}');
    });
  });
}

async function run(vulnerable: boolean, active = true) {
  const srv = ssrfTarget(vulnerable);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    return await liveSsrf.run({
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active }),
      projectDir: ".", stagingUrl: base, log: () => {},
      options: { "live-ssrf": { enabled: true, callbackHost: "127.0.0.1", endpoints: [{ url: "/fetch", method: "POST", body: '{"u":"http://__CBHOST__:__CBPORT__/__NONCE__"}' }] } },
    });
  } finally { srv.close(); }
}

test("live-ssrf: an out-of-band callback is proven", async () => {
  const f = await run(true);
  assert.equal(f.length, 1);
  assert.equal(f[0]!.state, "proven");
  assert.match(f[0]!.title, /SSRF/);
});

test("live-ssrf: a target that does not call out stays unproven (no false positive)", async () => {
  const f = await run(false);
  assert.equal(f.filter((x) => x.state === "proven").length, 0);
});

test("live-ssrf: without active mode the check refuses to probe", async () => {
  await assert.rejects(() => run(true, false));
});
