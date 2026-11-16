import { test } from "node:test";
import assert from "node:assert/strict";
import { VERCEL_HOST } from "./vercel-preview.js";

const match = (s: string) => (s.match(VERCEL_HOST) || []).map((x) => x.toLowerCase());

test("VERCEL_HOST matches preview and plain Vercel hostnames", () => {
  assert.deepEqual(match("see https://myapp-git-main-team.vercel.app/ here"), ["myapp-git-main-team.vercel.app"]);
  assert.deepEqual(match("project-abc123-myteam.vercel.app"), ["project-abc123-myteam.vercel.app"]);
  // a bare project host the previous three-part pattern missed (R2 fix also widens recall)
  assert.deepEqual(match("saas26.vercel.app"), ["saas26.vercel.app"]);
  assert.deepEqual(match("x.vercel.app"), ["x.vercel.app"]);
  // several on one line
  assert.deepEqual(match("a.vercel.app b-c.vercel.app"), ["a.vercel.app", "b-c.vercel.app"]);
});

test("VERCEL_HOST does not match a non-Vercel host", () => {
  assert.deepEqual(match("example.com or vercel.app.evil.com"), []);
});

test("VERCEL_HOST has no catastrophic backtracking (R2)", () => {
  // a long run of hyphens with no .vercel.app suffix: the old ambiguous
  // pattern took seconds here; the linear one returns immediately.
  const evil = "x" + "-".repeat(50000) + "!";
  const started = Date.now();
  VERCEL_HOST.lastIndex = 0;
  assert.equal(VERCEL_HOST.test(evil), false);
  assert.ok(Date.now() - started < 100, `match should be linear, took ${Date.now() - started}ms`);
});
