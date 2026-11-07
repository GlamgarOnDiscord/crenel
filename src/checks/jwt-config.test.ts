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
