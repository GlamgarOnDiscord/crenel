import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { nullByteExposure } from "./null-byte-exposure.js";
import { Scope } from "../core/scope.js";

// A server that blocks *.bak directly (403) but serves it with a null-byte suffix;
// a /secure area blocks the bypass too (decoy). Mirrors the poison-null-byte class.
function target() {
  const FILES: Record<string, string> = { "/ftp/secret.bak": "db_password=Secret123\napi_key=sk_live_x" };
  const nb = /^(.*?)%(?:25)?00\.(?:md|png|ico|jpg|txt|json)$/i;
  return createServer((req, res) => {
    const raw = (req.url ?? "/").split("?")[0]!;
    const m = raw.match(nb);
    const send = (s: number, b: string) => { res.writeHead(s, { "content-type": "text/plain" }); res.end(b); };
    if (m) {
      const cap = m[1]!;
      const real = (() => { try { return decodeURIComponent(cap); } catch { return cap; } })();
      if (real.startsWith("/secure/")) return send(403, "Forbidden");
      return FILES[real] ? send(200, FILES[real]!) : send(404, "no");
    }
    if (/\.bak$/i.test(raw)) return send(403, "Forbidden");
    return send(404, "no");
  });
}

async function run(names: string[], dirs: string[]) {
  const srv = target();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    return await nullByteExposure.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: { "null-byte-exposure": { dirs, names } }, log: () => {} });
  } finally { srv.close(); }
}

test("null-byte-exposure: a *.bak blocked directly but served via %00 suffix is proven", async () => {
  const f = await run(["secret.bak"], ["/ftp"]);
  assert.equal(f.length, 1);
  assert.equal(f[0]!.state, "proven");
  assert.match(f[0]!.title, /secret\.bak/);
});

test("null-byte-exposure: a secured area that blocks the bypass is not flagged", async () => {
  const f = await run(["secret.bak"], ["/secure"]);
  assert.equal(f.filter((x) => x.state === "proven").length, 0);
});
