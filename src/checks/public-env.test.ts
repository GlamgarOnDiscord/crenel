import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { publicEnv } from "./public-env.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-penv-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

test("a NEXT_PUBLIC_ secret-named var is flagged high", async () => {
  const dir = project({ ".env": "NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_x\n" });
  try {
    const found = await publicEnv.run(ctx(dir));
    assert.equal(found.length, 1);
    assert.equal(found[0]!.severity, "high");
    assert.match(found[0]!.title, /NEXT_PUBLIC_STRIPE_SECRET_KEY/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("VITE_ and REACT_APP_ secret-named vars in source are flagged", async () => {
  const dir = project({
    "config.ts": "const a = process.env.VITE_API_TOKEN;\nconst b = import.meta.env.REACT_APP_CLIENT_SECRET;\n",
  });
  try {
    const names = (await publicEnv.run(ctx(dir))).map((f) => f.title);
    assert.ok(names.some((t) => /VITE_API_TOKEN/.test(t)));
    assert.ok(names.some((t) => /REACT_APP_CLIENT_SECRET/.test(t)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a public var that is NOT secret-named is not flagged", async () => {
  const dir = project({ ".env": "NEXT_PUBLIC_API_URL=https://api.example.com\nVITE_APP_NAME=Acme\n" });
  try {
    assert.equal((await publicEnv.run(ctx(dir))).length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a server-side secret (no public prefix) is not this check's concern", async () => {
  const dir = project({ ".env": "STRIPE_SECRET_KEY=sk_live_x\n" });
  try {
    assert.equal((await publicEnv.run(ctx(dir))).length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
