import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GrantSet } from "./state.js";

test("an 'always' grant survives a restart, and removing it is persisted too", () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-grants-"));
  const path = join(dir, "grants.json");
  try {
    const first = new GrantSet(path);
    first.add("Staging.Example.com");
    assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), ["staging.example.com"]);
    const restarted = new GrantSet(path);
    assert.ok(restarted.has("staging.example.com"));
    restarted.delete("staging.example.com");
    assert.equal(new GrantSet(path).size, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a missing or corrupt grants file starts empty", () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-grants-"));
  try { assert.equal(new GrantSet(join(dir, "nope.json")).size, 0); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});
