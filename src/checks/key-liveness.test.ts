import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkLiveness } from "./key-liveness.js";
import { exposedSecrets } from "./exposed-secrets.js";
import { Scope } from "../core/scope.js";

test("a provider answering 200 marks the key active, 401 revoked; the key goes only in the auth header", async () => {
  const seen: { url?: string; auth?: string }[] = [];
  const srv = createServer((req, res) => {
    seen.push({ url: req.url, auth: req.headers.authorization });
    res.writeHead(req.headers.authorization === "Bearer sk_live_good" ? 200 : 401);
    res.end("{}");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/v1/balance`;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    assert.equal((await checkLiveness("stripe-secret", "sk_live_good", scope, url)).liveness, "active");
    assert.equal((await checkLiveness("stripe-secret", "sk_live_old", scope, url)).liveness, "revoked");
    assert.ok(seen.every((s) => s.url === "/v1/balance" && !s.url.includes("sk_live")), "the key never appears in the URL");
  } finally { srv.close(); }
});

test("nothing is sent when the provider host is not declared, and the scan says how to enable it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-live-"));
  writeFileSync(join(dir, "app.js"), 'const k = "sk_live_ABCDEFGHIJKLMNOP1234";\n');
  try {
    const logs: string[] = [];
    const scope = new Scope({ allowedHosts: [] });
    const found = await exposedSecrets.run({ scope, projectDir: dir, options: { "exposed-secrets": { verify: true } }, log: (m) => logs.push(m) });
    assert.equal(found.length, 1);
    assert.doesNotMatch(found[0]!.title, /works right now|revoked/);
    assert.ok(logs.some((l) => l.includes("declare api.stripe.com")));
    assert.equal((await checkLiveness("private-key-block", "x", scope)).liveness, "unknown", "no verifier, no call");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
