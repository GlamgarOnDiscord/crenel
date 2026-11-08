import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { jwtConfig } from "./jwt-config.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(d: string): CheckContext { return { scope: new Scope({ allowedHosts: [] }), projectDir: d, options: {}, log: () => {} }; }
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-jwt-"));
  for (const [n, b] of Object.entries(files)) writeFileSync(join(dir, n), b);
  return dir;
}

test("flags alg none in its forms", async () => {
  const dir = project({
    "a.ts": 'jwt.sign(payload, key, { algorithm: "none" });\n',
    "b.ts": "jwt.verify(t, k, { algorithms: ['HS256', 'none'] });\n",
    "c.ts": 'jwt.verify(token, null);\n',
  });
  try {
    const ids = (await jwtConfig.run(ctx(dir))).map((f) => f.id.split(":")[1]);
    assert.ok(ids.includes("alg-none"));
    assert.ok(ids.includes("alg-none-list"));
    assert.ok(ids.includes("empty-secret"));
    assert.ok((await jwtConfig.run(ctx(dir))).every((f) => f.severity === "high"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a proper JWT config is not flagged", async () => {
  const dir = project({ "a.ts": 'jwt.verify(t, PUBLIC_KEY, { algorithms: ["RS256"] });\njwt.sign(p, k, { algorithm: "HS256" });\n' });
  try { assert.equal((await jwtConfig.run(ctx(dir))).length, 0); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});

test("an unsigned token built in test code is not a JWT config (seen on a real monorepo's 2FA test)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-jwt-"));
  const { mkdirSync } = await import("node:fs");
  mkdirSync(join(dir, "apps/api/test"), { recursive: true });
  mkdirSync(join(dir, "src"), { recursive: true });
  const fake = "const part = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');\nexport const t = `${part({ alg: 'none' })}.${part({ sub: 'u' })}.signature`;\n";
  writeFileSync(join(dir, "apps/api/test/google-2fa-reauth.test.ts"), fake);
  writeFileSync(join(dir, "src/auth.spec.ts"), fake);
  writeFileSync(join(dir, "src/jwt.ts"), 'jwt.sign(payload, key, { algorithm: "none" });\n');
  try {
    const found = await jwtConfig.run(ctx(dir));
    assert.deepEqual(found.map((f) => f.location), ["src/jwt.ts:1"], "production code is still flagged, test code is not");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
