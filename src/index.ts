// Public API, for using Bastion as a library instead of a CLI.
export { run } from "./core/runner.js";
export type { RunResult, RunOptions } from "./core/runner.js";
export { loadConfig } from "./core/config.js";
export type { Config } from "./core/config.js";
export { Scope, ScopeError } from "./core/scope.js";
export { REGISTRY, resolveChecks } from "./core/registry.js";
export { renderText, renderJson, exitCode } from "./report/render.js";
export type { Check, CheckContext, Finding, Severity } from "./core/types.js";
