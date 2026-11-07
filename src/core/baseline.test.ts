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
function result(findings: Finding[]): RunResult {
  return { project: "p", startedAt: "2026-01-01T00:00:00Z", findings, errors: [], checksRun: [] };
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
