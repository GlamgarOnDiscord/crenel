// The runner ties a config to a set of findings. It builds the scope guard,
// resolves the checks, runs each inside a try/catch (one failing check must not
// sink the whole run), and returns everything for the reporter.

import { isAbsolute, resolve, dirname } from "node:path";
import { scopeSettings, type Config } from "./config.js";
import { accessFindings, redactFindings } from "./access.js";
import { Scope } from "./scope.js";
import { resolveChecks } from "./registry.js";
import type { Check, CheckContext, Finding } from "./types.js";

export interface RunResult {
  project: string;
  startedAt: string;
  findings: Finding[];
  errors: { check: string; message: string }[];
  checksRun: string[];
  /** Wall-clock duration of the run, in milliseconds. */
  durationMs?: number;
  /** HTTP requests sent through the scoped client (each redirect hop counts). */
  requests?: number;
}

export interface RunOptions {
  verbose?: boolean;
}

export async function run(
  config: Config,
  configPath: string,
  opts: RunOptions = {},
  // Checks to run. Defaults to the registry; overridable for tests.
  checksOverride?: Check[],
): Promise<RunResult> {
  const configDir = dirname(resolve(configPath));
  const projectDir = isAbsolute(config.projectDir)
    ? config.projectDir
    : resolve(configDir, config.projectDir);

  const scope = new Scope(scopeSettings(config.scope));

  const checks = checksOverride ?? resolveChecks(config.checks, config.options);
  const log = (msg: string) => {
    if (opts.verbose) process.stderr.write(`  ${msg}\n`);
  };

  const ctx: CheckContext = {
    scope,
    projectDir,
    stagingUrl: scope.stagingUrl,
    options: config.options,
    log,
  };

  const started = Date.now();
  const findings: Finding[] = [];
  const errors: RunResult["errors"] = [];
  const checksRun: string[] = [];

  for (const check of checks) {
    try {
      // A check that writes never runs without allowActiveTesting, whatever it does inside.
      if (!check.readOnly) scope.assertActiveAllowed(check.name);
      const out = await check.run(ctx);
      findings.push(...out);
      checksRun.push(check.name);
    } catch (err) {
      errors.push({ check: check.name, message: (err as Error).message });
    }
  }
  // One info lead per host that answered with Cloudflare Access instead of the app.
  findings.push(...accessFindings(scope));

  return {
    project: config.project,
    startedAt: new Date(started).toISOString(),
    findings: redactFindings(findings),
    errors,
    checksRun,
    durationMs: Date.now() - started,
    requests: scope.requestsSent,
  };
}
