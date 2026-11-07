import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendAudit, toAuditEntry } from "./audit.js";
import type { RunResult } from "./runner.js";

const result: RunResult = {
  project: "acme", startedAt: "2026-01-01T00:00:00Z", checksRun: ["exposed-secrets"], errors: [],
  findings: [{ id: "f1", check: "exposed-secrets", title: "t", severity: "critical", state: "proven", location: "l", description: "d", remediation: "r" }],
};

test("audit entry carries scan metadata and finding states", () => {
  const e = toAuditEntry(result);
  assert.equal(e.project, "acme");
  assert.deepEqual(e.checks, ["exposed-secrets"]);
  assert.deepEqual(e.findings, [{ id: "f1", severity: "critical", state: "proven" }]);
});

test("appendAudit writes one JSON line per call", () => {
  const p = join(tmpdir(), `crenel-audit-${Date.now()}.jsonl`);
  try {
    appendAudit(p, result);
    appendAudit(p, result);
    const lines = readFileSync(p, "utf8").trim().split("\n");
    assert.equal(lines.length, 2);
    assert.equal(JSON.parse(lines[0]!).project, "acme");
  } finally {
    rmSync(p, { force: true });
  }
});
