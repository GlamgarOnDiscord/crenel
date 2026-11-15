import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StateStore } from "./state.js";

/*
  I2 (HARDENING-LOG): `.crenel/` holds all of Crenel's state. If that directory
  is a symbolic link, every write lands wherever it points, outside the project.
  The secrets store already refuses a symlinked file; the state dir must too.
*/
test("StateStore refuses a state dir that is a symbolic link", () => {
  const base = mkdtempSync(join(tmpdir(), "crenel-state-link-"));
  try {
    const real = join(base, "elsewhere");
    mkdirSync(real);
    const link = join(base, ".crenel");
    symlinkSync(real, link);
    assert.throws(() => new StateStore(link), /symbolic link/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("StateStore creates a normal state dir and its runs subdir", () => {
  const base = mkdtempSync(join(tmpdir(), "crenel-state-ok-"));
  try {
    const dir = join(base, ".crenel");
    const store = new StateStore(dir);
    assert.equal(store.dir, dir);
    assert.ok(existsSync(join(dir, "runs")), "runs/ is created");
    // A second open of the same real directory stays fine.
    assert.doesNotThrow(() => new StateStore(dir));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
