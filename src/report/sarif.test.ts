import { test } from "node:test";
import assert from "node:assert/strict";
import { toSarif } from "./sarif.js";
import type { RunResult } from "../core/runner.js";
import type { Finding } from "../core/types.js";

function f(over: Partial<Finding>): Finding {
  return {
    id: "x", check: "exposed-secrets", title: "t", severity: "critical", state: "proven",
    location: "dist/app.js:5", description: "d", remediation: "r", ...over,
  };
}
function result(findings: Finding[]): RunResult {
  return { project: "p", startedAt: "2026-01-01T00:00:00Z", findings, errors: [], checksRun: [] };
}

test("SARIF has version, a tool driver, and one result per finding", () => {
  const s = JSON.parse(toSarif(result([f({}), f({ id: "y", check: "authz-matrix", severity: "high" })])));
  assert.equal(s.version, "2.1.0");
  assert.equal(s.runs[0].tool.driver.name, "Crenel");
  assert.equal(s.runs[0].results.length, 2);
});

test("severity and state map to SARIF level", () => {
  const s = JSON.parse(toSarif(result([
    f({ id: "a", severity: "critical", state: "proven" }),
    f({ id: "b", severity: "medium", state: "proven" }),
    f({ id: "c", severity: "high", state: "unproven" }),
  ])));
  const by = Object.fromEntries(s.runs[0].results.map((r: any) => [r.properties.id, r.level]));
  assert.equal(by.a, "error");
  assert.equal(by.b, "warning");
  assert.equal(by.c, "note"); // a lead is never a blocking alert
});

test("location path:line becomes uri + startLine", () => {
  const s = JSON.parse(toSarif(result([f({ location: "dist/app.js:5" })])));
  const loc = s.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(loc.artifactLocation.uri, "dist/app.js");
  assert.equal(loc.region.startLine, 5);
});
