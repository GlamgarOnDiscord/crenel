import { test } from "node:test";
import assert from "node:assert/strict";
import { exitCode, sortFindings, renderText, renderJson } from "./render.js";
import type { RunResult } from "../core/runner.js";
import type { Finding } from "../core/types.js";

const f = (o: Partial<Finding>): Finding => ({
  id: "x", check: "c", title: "t", severity: "high", state: "proven",
  location: "l", description: "d", remediation: "r", ...o,
});
const result = (findings: Finding[], errors: RunResult["errors"] = []): RunResult => ({
  project: "p", startedAt: "2026-01-01T00:00:00Z", findings, errors, checksRun: ["c"],
});

test("exitCode: non-zero only on a proven high or critical", () => {
  assert.equal(exitCode(result([f({ state: "proven", severity: "critical" })])), 1);
  assert.equal(exitCode(result([f({ state: "proven", severity: "high" })])), 1);
  assert.equal(exitCode(result([f({ state: "proven", severity: "medium" })])), 0);
  assert.equal(exitCode(result([f({ state: "unproven", severity: "critical" })])), 0); // a lead never gates
  assert.equal(exitCode(result([])), 0);
});

test("sortFindings: proven before leads, then by severity", () => {
  const out = sortFindings([
    f({ id: "a", state: "unproven", severity: "critical" }),
    f({ id: "b", state: "proven", severity: "low" }),
    f({ id: "c", state: "proven", severity: "critical" }),
  ]);
  assert.deepEqual(out.map((x) => x.id), ["c", "b", "a"]);
});

test("renderText shows proven counts, leads, proof and fix; renderJson round-trips", () => {
  const r = result([f({ title: "Secret", state: "proven", severity: "critical", proof: { method: "m", replay: "grep x" } }), f({ id: "y", state: "unproven", severity: "low" })]);
  const txt = renderText(r);
  assert.match(txt, /Proven:/);
  assert.match(txt, /grep x/); // proof replay shown
  assert.match(txt, /Leads \(unproven\): 1/);
  assert.deepEqual(JSON.parse(renderJson(r)).findings.length, 2);
});

test("renderText surfaces errored checks", () => {
  const txt = renderText(result([], [{ check: "headers", message: "timeout" }]));
  assert.match(txt, /errored/i);
  assert.match(txt, /headers: timeout/);
});
