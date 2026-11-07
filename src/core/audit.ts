// Replayable audit log. One JSON line per scan, appended: when it ran, the
// scope it was allowed, which checks ran, and the id/severity/state of every
// finding. This is the "journal rejouable" from the research backlog: a durable,
// greppable record of what the tool did and saw over time, outside the model.

import { appendFileSync } from "node:fs";
import type { RunResult } from "./runner.js";

/** The scope a scan was allowed, recorded so the log says what was in bounds. */
export interface AuditScope {
  allowedHosts: string[];
  allowActiveTesting: boolean;
  stagingUrl?: string;
}

export interface AuditEntry {
  at: string;
  project: string;
  scope?: AuditScope;
  checks: string[];
  errors: number;
  findings: { id: string; severity: string; state: string }[];
}

export function toAuditEntry(result: RunResult, scope?: AuditScope): AuditEntry {
  return {
    at: result.startedAt,
    project: result.project,
    ...(scope ? { scope } : {}),
    checks: result.checksRun,
    errors: result.errors.length,
    findings: result.findings.map((f) => ({ id: f.id, severity: f.severity, state: f.state })),
  };
}

/** Append one line to the audit log. Creates the file if missing. */
export function appendAudit(path: string, result: RunResult, scope?: AuditScope): void {
  appendFileSync(path, JSON.stringify(toAuditEntry(result, scope)) + "\n");
}
