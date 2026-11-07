import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { committedEnv } from "./committed-env.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-env-"));
  for (const [name, body] of Object.entries(files)) {
    const full = join(dir, name);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, body);
  }
  return dir;
}

test("a committed .env with values is a medium lead", async () => {
  const dir = project({ ".env": "DATABASE_URL=postgres://u:p@h/db\nDEBUG=true\n" });
  try {
    const found = await committedEnv.run(ctx(dir));
    assert.equal(found.length, 1);
    assert.equal(found[0]!.severity, "medium");
    assert.equal(found[0]!.state, "unproven");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test(".env.example and friends are not flagged", async () => {
  const dir = project({
    ".env.example": "DATABASE_URL=\n",
    ".env.sample": "X=\n",
    ".env.template": "Y=\n",
  });
  try {
    assert.equal((await committedEnv.run(ctx(dir))).length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test(".env.production and .env.local are flagged", async () => {
  const dir = project({ ".env.production": "API_TOKEN=abc\n", ".env.local": "K=v\n" });
  try {
    const ids = (await committedEnv.run(ctx(dir))).map((f) => f.id);
    assert.ok(ids.some((i) => i.includes(".env.production")));
    assert.ok(ids.some((i) => i.includes(".env.local")));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("node_modules is skipped", async () => {
  const dir = project({ "node_modules/pkg/.env": "SECRET=x\n", ".env.example": "A=\n" });
  try {
    assert.equal((await committedEnv.run(ctx(dir))).length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
