import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ciHardening } from "./ci-hardening.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}

function withWorkflow(yml: string): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-ci-"));
  mkdirSync(join(dir, ".github", "workflows"), { recursive: true });
  writeFileSync(join(dir, ".github", "workflows", "ci.yml"), yml);
  return dir;
}

test("flags pull_request_target, an unpinned action and install without --ignore-scripts", async () => {
  const dir = withWorkflow(
    "on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - run: pnpm install\n",
  );
  try {
    const found = await ciHardening.run(ctx(dir));
    const ids = found.map((f) => f.id.split(":")[1]);
    assert.ok(ids.includes("prt"));
    assert.ok(ids.includes("unpinned"));
    assert.ok(ids.includes("install-scripts"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a hardened workflow yields no findings", async () => {
  const dir = withWorkflow(
    "on:\n  pull_request:\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@0000000000000000000000000000000000000000\n      - run: pnpm install --ignore-scripts\n",
  );
  try {
    assert.equal((await ciHardening.run(ctx(dir))).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
