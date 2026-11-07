// The runner ties a config to a set of findings. It builds the scope guard,
// resolves the checks, runs each inside a try/catch (one failing check must not
// sink the whole run), and returns everything for the reporter.

import { isAbsolute, resolve, dirname } from "node:path";
import type { Config } from "./config.js";
import { Scope } from "./scope.js";
import { resolveChecks } from "./registry.js";
import type { Check, CheckContext, Finding } from "./types.js";

export interface RunResult {
  project: string;
  startedAt: string;
  findings: Finding[];
  errors: { check: string; message: string }[];
  checksRun: string[];
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

  const scope = new Scope({
    allowedHosts: config.scope.allowedHosts,
    allowActiveTesting: config.scope.allowActiveTesting,
    allowPrivate: config.scope.allowPrivate,
    stagingUrl: config.scope.stagingUrl,
  });

  const checks = checksOverride ?? resolveChecks(config.checks);
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

  const findings: Finding[] = [];
  const errors: RunResult["errors"] = [];
  const checksRun: string[] = [];

  for (const check of checks) {
    try {
      const out = await check.run(ctx);
      findings.push(...out);
      checksRun.push(check.name);
    } catch (err) {
      errors.push({ check: check.name, message: (err as Error).message });
    }
  }

  return {
    project: config.project,
    startedAt: new Date().toISOString(),
    findings,
    errors,
    checksRun,
  };
}
