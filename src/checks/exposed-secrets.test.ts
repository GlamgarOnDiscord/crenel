import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exposedSecrets } from "./exposed-secrets.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}

test("detects a Stripe secret key and classifies it critical+proven", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec-"));
  try {
    writeFileSync(join(dir, "app.js"), 'const k = "sk_live_ABCDEFGHIJKLMNOP1234";\n');
    const found = await exposedSecrets.run(ctx(dir));
    const stripe = found.find((f) => f.id.includes("stripe-secret"));
    assert.ok(stripe, "should find the Stripe key");
    assert.equal(stripe!.severity, "critical");
    assert.equal(stripe!.state, "proven");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a clean directory yields no findings, and node_modules is skipped", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec-"));
  try {
    writeFileSync(join(dir, "app.js"), 'const k = "pk_live_safe_publishable";\n');
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "x.js"), 'sk_live_SHOULDBESKIPPED123456\n');
    const found = await exposedSecrets.run(ctx(dir));
    assert.equal(found.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
