import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { walkFiles, extOf } from "./walk.js";

function tree(): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-walk-"));
  writeFileSync(join(dir, "a.ts"), "");
  writeFileSync(join(dir, "b.txt"), "");
  mkdirSync(join(dir, "sub"));
  writeFileSync(join(dir, "sub", "c.ts"), "");
  mkdirSync(join(dir, "node_modules", "pkg"), { recursive: true });
  writeFileSync(join(dir, "node_modules", "pkg", "d.ts"), "");
  return dir;
}

test("walkFiles skips node_modules and .git by default", () => {
  const dir = tree();
  try {
    const got = [...walkFiles(dir)].map((p) => basename(p)).sort();
    assert.deepEqual(got, ["a.ts", "b.txt", "c.ts"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("accept filters files", () => {
  const dir = tree();
  try {
    const got = [...walkFiles(dir, { accept: (n) => extOf(n) === ".ts" })].map((p) => basename(p)).sort();
    assert.deepEqual(got, ["a.ts", "c.ts"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("maxDepth bounds recursion", () => {
  const dir = tree();
  try {
    const got = [...walkFiles(dir, { maxDepth: 0 })].map((p) => basename(p)).sort();
    assert.deepEqual(got, ["a.ts", "b.txt"]); // top level only
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a missing directory yields nothing, no throw", () => {
  assert.deepEqual([...walkFiles("/no/such/dir")], []);
});

test("extOf returns the extension or empty", () => {
  assert.equal(extOf("x.ts"), ".ts");
  assert.equal(extOf(".env"), ".env");
  assert.equal(extOf("Dockerfile"), "");
});

test("isCommentedAt detects line comments", async () => {
  const { isCommentedAt } = await import("./walk.js");
  const t1 = "  // rejectUnauthorized: false\n";
  assert.equal(isCommentedAt(t1, t1.indexOf("reject")), true);
  const t2 = "const x = 1; // trailing rejectUnauthorized: false\n";
  assert.equal(isCommentedAt(t2, t2.indexOf("reject")), true);
  const t3 = "const a = { rejectUnauthorized: false };\n";
  assert.equal(isCommentedAt(t3, t3.indexOf("reject")), false);
  const t4 = " * jsdoc rejectUnauthorized: false\n";
  assert.equal(isCommentedAt(t4, t4.indexOf("reject")), true);
});
