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

test("a Stripe test key is a low-severity note, not a critical incident", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec-"));
  try {
    writeFileSync(join(dir, "app.js"), 'const k = "sk_test_ABCDEFGHIJKLMNOP1234";\n');
    const found = await exposedSecrets.run(ctx(dir));
    const hit = found.find((f) => f.id.includes("stripe-secret-test"));
    assert.ok(hit, "test key should still be detected");
    assert.equal(hit!.severity, "low");
    assert.doesNotMatch(hit!.description + hit!.remediation, /compromis|compromised|rotate now/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("detects additional distinctive-prefix secrets (slack, npm, github fine-grained, google oauth, sendgrid)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec2-"));
  try {
    writeFileSync(join(dir, "bundle.js"), [
      'a="xoxb-123456789012-abcdefghijkl"',
      'b="npm_' + "A".repeat(36) + '"',
      'c="github_pat_' + "A".repeat(22) + "_" + "B".repeat(59) + '"',
      'd="GOCSPX-abcdefghijklmnopqrstuvwx"',
      'e="SG.' + "A".repeat(22) + "." + "B".repeat(43) + '"',
    ].join("\n"));
    const ids = (await exposedSecrets.run(ctx(dir))).map((f) => f.id.split(":")[1]);
    for (const id of ["slack-token", "npm-token", "github-fine-grained-pat", "google-oauth-secret", "sendgrid-key"]) {
      assert.ok(ids.includes(id), `missing ${id}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ordinary minified code does not trip the new patterns", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec3-"));
  try {
    writeFileSync(join(dir, "app.js"), "const ghost=1;const box='xoxo';function sg(){return SG;}\nconst npmrc='registry';\n");
    const found = await exposedSecrets.run(ctx(dir));
    assert.equal(found.length, 0, "should not false-positive on ordinary code");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
