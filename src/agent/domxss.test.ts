import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Scope } from "../core/scope.js";
import { validateClaim, type Claim, type ValidatorEnv } from "./validators.js";

const PW = "/root/wt-sec-deps/node_modules/.pnpm/playwright@1.64.1/node_modules/playwright/index.mjs";
const CHR = "/root/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome";

test("explore.dom-xss proves DOM XSS when the page reflects a param into a DOM sink", async () => {
  const srv = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const q = u.searchParams.get("q") ?? "";
    const safe = u.pathname === "/safe";
    res.writeHead(200, { "content-type": "text/html" });
    // DOM sink: the page's own JS writes q into innerHTML (vulnerable) or textContent (safe).
    res.end(`<!doctype html><html><body><div id=o></div><script>
      var q=new URLSearchParams(location.search).get('q')||'';
      document.getElementById('o').${safe?'textContent':'innerHTML'}=q;
    </script></body></html>`);
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "crenel-dx-"));
  try {
    const env: ValidatorEnv = { scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: base }), projectDir: dir, stagingUrl: base, checks: [], options: { explore: { domXssPlaywright: PW, domXssBrowser: CHR } } };
    const mk = (path: string): Claim => ({ id: "d", class: "explore.dom-xss", source: "llm", detail: { url: path, param: "q" } });
    const vuln = await validateClaim(mk("/"), env);
    if (vuln.validator && /no browser|browser error/.test(vuln.reason)) { console.log("SKIP: browser unavailable"); return; }
    assert.equal(vuln.state, "proven", vuln.reason);
    const safe = await validateClaim(mk("/safe"), env);
    assert.equal(safe.state, "unproven", "a textContent sink must not be proven");
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});
