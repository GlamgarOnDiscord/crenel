import { test } from "node:test";
import assert from "node:assert/strict";
import { diff, hasRegression, toBaseline } from "./baseline.js";
import type { RunResult } from "./runner.js";
import type { Finding } from "./types.js";

function finding(over: Partial<Finding>): Finding {
  return {
    id: "x", check: "c", title: "t", severity: "high", state: "proven",
    location: "l", description: "d", remediation: "r", ...over,
  };
}
// checksRun defaults to the check the finding() helper uses, since a check that
// ran but found nothing is still "run" (that is how a fix is detected).
function result(findings: Finding[], checksRun: string[] = ["c"]): RunResult {
  return { project: "p", startedAt: "2026-01-01T00:00:00Z", findings, errors: [], checksRun };
}

test("diff splits added, fixed and persisting by id", () => {
  const base = toBaseline(result([finding({ id: "a" }), finding({ id: "b" })]));
  const now = result([finding({ id: "b" }), finding({ id: "c" })]);
  const d = diff(now, base);
  assert.deepEqual(d.added.map((f) => f.id), ["c"]);
  assert.deepEqual(d.fixed.map((e) => e.id), ["a"]);
  assert.deepEqual(d.persisting.map((f) => f.id), ["b"]);
});

test("only a previously proven, now-absent finding counts as fixed", () => {
  const base = toBaseline(result([finding({ id: "a", state: "unproven" })]));
  const d = diff(result([]), base);
  assert.equal(d.fixed.length, 0);
});

test("a new proven high or critical is a regression; a new lead is not", () => {
  const base = toBaseline(result([]));
  assert.equal(hasRegression(diff(result([finding({ id: "n", state: "proven", severity: "critical" })]), base)), true);
  assert.equal(hasRegression(diff(result([finding({ id: "n", state: "unproven", severity: "critical" })]), base)), false);
  assert.equal(hasRegression(diff(result([finding({ id: "n", state: "proven", severity: "low" })]), base)), false);
});

test("a proven finding whose check did not run is NOT reported as fixed", () => {
  const base = toBaseline(result([finding({ id: "a", check: "headers", state: "proven" })]));
  // this run: the headers check crashed, so it is absent from checksRun
  const now = result([], ["exposed-secrets"]);
  const d = diff(now, base);
  assert.equal(d.fixed.length, 0, "a crashed check must not read as a fix");
});

test("loadBaseline: absent is null, corrupt throws, valid loads", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { loadBaseline } = await import("./baseline.js");
  const dir = mkdtempSync(join(tmpdir(), "crenel-base-"));
  try {
    assert.equal(loadBaseline(join(dir, "nope.json")), null);
    writeFileSync(join(dir, "bad.json"), "{ not json");
    assert.throws(() => loadBaseline(join(dir, "bad.json")), /illisible/);
    writeFileSync(join(dir, "mal.json"), JSON.stringify({ savedAt: "x", findings: [{ no: "id" }] }));
    assert.throws(() => loadBaseline(join(dir, "mal.json")), /malformée/);
    writeFileSync(join(dir, "ok.json"), JSON.stringify({ savedAt: "x", findings: [] }));
    assert.deepEqual(loadBaseline(join(dir, "ok.json"))?.findings, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
