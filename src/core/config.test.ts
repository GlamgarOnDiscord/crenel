import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "./config.js";

function withConfig(yaml: string): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-cfg-"));
  const path = join(dir, "bastion.config.yaml");
  writeFileSync(path, yaml);
  return path;
}

test("a minimal valid config loads with defaults", () => {
  const p = withConfig("project: demo\nscope:\n  allowedHosts: [staging.example.com]\n");
  try {
    const c = loadConfig(p);
    assert.equal(c.project, "demo");
    assert.equal(c.projectDir, ".");
    assert.deepEqual(c.scope.allowedHosts, ["staging.example.com"]);
    assert.equal(c.scope.allowActiveTesting, false);
    assert.deepEqual(c.checks, []);
  } finally { rmSync(join(p, ".."), { recursive: true, force: true }); }
});

test("an unknown key fails loudly (strict schema)", () => {
  const p = withConfig("project: demo\nscope:\n  allowedHost: [x]\n"); // typo
  try {
    assert.throws(() => loadConfig(p), /Invalid config|Unrecognized/);
  } finally { rmSync(join(p, ".."), { recursive: true, force: true }); }
});

test("an empty host string is rejected", () => {
  const p = withConfig('project: demo\nscope:\n  allowedHosts: ["", "ok.example.com"]\n');
  try {
    assert.throws(() => loadConfig(p), /Invalid config|vide/);
  } finally { rmSync(join(p, ".."), { recursive: true, force: true }); }
});

test("an invalid stagingUrl is rejected", () => {
  const p = withConfig("project: demo\nscope:\n  allowedHosts: [x.example.com]\n  stagingUrl: not-a-url\n");
  try {
    assert.throws(() => loadConfig(p), /Invalid config/);
  } finally { rmSync(join(p, ".."), { recursive: true, force: true }); }
});

test("a missing file throws a clear error", () => {
  assert.throws(() => loadConfig("/no/such/bastion.config.yaml"), /Cannot read config file/);
});
