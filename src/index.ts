// Public API, for using Crenel as a library instead of a CLI.
export { run } from "./core/runner.js";
export type { RunResult, RunOptions } from "./core/runner.js";
export { loadConfig } from "./core/config.js";
export type { Config } from "./core/config.js";
export { Scope, ScopeError } from "./core/scope.js";
export { REGISTRY, resolveChecks } from "./core/registry.js";
export { renderText, renderJson, renderDiff, exitCode } from "./report/render.js";
export { loadBaseline, saveBaseline, toBaseline, diff, hasRegression } from "./core/baseline.js";
export type { Baseline, BaselineEntry, Diff } from "./core/baseline.js";
export { toSarif } from "./report/sarif.js";
export { appendAudit, toAuditEntry } from "./core/audit.js";
export type { AuditEntry } from "./core/audit.js";
export { triageFinding, triageLeads } from "./agent/triage.js";
export type { TriageResult } from "./agent/triage.js";
export type { Check, CheckContext, Finding, Severity } from "./core/types.js";
