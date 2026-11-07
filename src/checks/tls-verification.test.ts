import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { tlsVerification } from "./tls-verification.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-tls-"));
  for (const [n, b] of Object.entries(files)) writeFileSync(join(dir, n), b);
  return dir;
}

test("flags the three TLS-bypass patterns as high leads", async () => {
  const dir = project({
    "client.ts": "const agent = new https.Agent({ rejectUnauthorized: false });\n",
    ".env": "NODE_TLS_REJECT_UNAUTHORIZED=0\n",
    "req.js": "request({ strictSSL: false });\n",
  });
  try {
    const ids = (await tlsVerification.run(ctx(dir))).map((f) => f.id.split(":")[1]);
    assert.ok(ids.includes("reject-unauthorized"));
    assert.ok(ids.includes("node-tls-reject"));
    assert.ok(ids.includes("strict-ssl"));
    const found = await tlsVerification.run(ctx(dir));
    assert.ok(found.every((f) => f.severity === "high" && f.state === "unproven"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("clean code is not flagged", async () => {
  const dir = project({ "client.ts": "const agent = new https.Agent({ ca: readFileSync('ca.pem') });\nconst ok = { rejectUnauthorized: true };\n" });
  try {
    assert.equal((await tlsVerification.run(ctx(dir))).length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
