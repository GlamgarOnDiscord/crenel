#!/usr/bin/env node
// Bastion CLI. Three commands:
//   scan   run the checks against a config and report
//   list   show available checks
//   init   write a starter config
//
// Kept dependency-free (no arg parser) so the tool stays small and auditable.

import { writeFileSync, existsSync } from "node:fs";
import { loadConfig } from "./core/config.js";
import { run } from "./core/runner.js";
import { REGISTRY } from "./core/registry.js";
import { renderText, renderJson, renderDiff, exitCode } from "./report/render.js";
import { toSarif } from "./report/sarif.js";
import { appendAudit } from "./core/audit.js";
import { generateRegressionFile } from "./generate/tests.js";
import { loadBaseline, saveBaseline, diff, hasRegression } from "./core/baseline.js";
import { triageLeads } from "./agent/triage.js";

const STARTER = `# Bastion config. Declare only what you own.
project: my-saas
projectDir: ./dist          # the directory to scan for secrets (your built bundle)

scope:
  allowedHosts:
    - staging.example.com    # hosts you own and may test
  allowActiveTesting: false  # keep false until you are testing your own staging
  # stagingUrl: https://staging.example.com

# Empty = all read-only checks. Name checks to restrict, e.g. [exposed-secrets]
checks: []

options:
  authz-matrix:
    resources:
      - name: project
        path: /api/projects/:id
        methods: [GET]
    accounts:
      a: { token: "" }       # test account A's bearer token (staging only)
      b: { owns: { project: [] } }  # ids that belong to account B
`;

// Flags that never take a value, so they do not swallow the following token
// (e.g. `bastion --verbose scan` must keep `scan` as the command).
const BOOLEAN_FLAGS = new Set(["verbose", "json", "force", "update-baseline", "help"]);
// Flags that require a value; a missing one is an error, not a silent skip.
const VALUE_FLAGS = new Set(["config", "out", "sarif", "audit", "baseline", "model", "max"]);

function parseFlags(argv: string[]): { _: string[]; flags: Record<string, string | boolean>; warnings: string[] } {
  const _: string[] = [];
  const flags: Record<string, string | boolean> = {};
  const warnings: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) { _.push(a); continue; }
    const body = a.slice(2);
    const eq = body.indexOf("=");
    if (eq >= 0) { // --key=value
      flags[body.slice(0, eq)] = body.slice(eq + 1);
      continue;
    }
    const key = body;
    if (!BOOLEAN_FLAGS.has(key) && !VALUE_FLAGS.has(key)) warnings.push(`flag inconnu ignoré: --${key}`);
    if (BOOLEAN_FLAGS.has(key)) { flags[key] = true; continue; }
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("-")) { flags[key] = next; i++; }
    else { // value flag with no value
      flags[key] = true;
      if (VALUE_FLAGS.has(key)) warnings.push(`--${key} attend une valeur, ignoré`);
    }
  }
  return { _, flags, warnings };
}

async function main(): Promise<number> {
  const { _, flags, warnings } = parseFlags(process.argv.slice(2));
  for (const w of warnings) process.stderr.write(`Attention: ${w}\n`);
  const cmd = _[0] ?? "help";

  if (cmd === "list") {
    process.stdout.write("Available checks:\n");
    for (const c of REGISTRY) {
      const kind = c.readOnly ? "read-only" : "active";
      process.stdout.write(`  ${c.name.padEnd(18)} [${kind}]  ${c.title}\n`);
    }
    return 0;
  }

  if (cmd === "init") {
    const path = (flags.config as string) ?? "bastion.config.yaml";
    if (existsSync(path) && !flags.force) {
      process.stderr.write(`${path} already exists. Use --force to overwrite.\n`);
      return 1;
    }
    writeFileSync(path, STARTER);
    process.stdout.write(`Wrote ${path}. Edit it, then run: bastion scan --config ${path}\n`);
    return 0;
  }

  if (cmd === "scan") {
    const configPath = (flags.config as string) ?? "bastion.config.yaml";
    let config;
    try {
      config = loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const result = await run(config, configPath, { verbose: !!flags.verbose });
    if (flags.json) {
      process.stdout.write(renderJson(result) + "\n");
    } else {
      process.stdout.write(renderText(result) + "\n");
    }
    // A check that threw produced no findings; surface it loudly so a partial
    // run is never mistaken for a clean one (the exit code reflects it below).
    if (result.errors.length > 0) {
      process.stderr.write(`\n${result.errors.length} check(s) ont échoué, résultat partiel:\n`);
      for (const e of result.errors) process.stderr.write(`  - ${e.check}: ${e.message}\n`);
    }
    if (flags.out && typeof flags.out === "string") {
      writeFileSync(flags.out, renderJson(result));
    }
    if (flags.sarif && typeof flags.sarif === "string") {
      writeFileSync(flags.sarif, toSarif(result));
    }
    if (flags.audit && typeof flags.audit === "string") {
      appendAudit(flags.audit, result);
    }

    // Baseline: diff against a saved snapshot, and/or update it.
    const baselinePath = typeof flags.baseline === "string" ? flags.baseline : undefined;
    let regressed = false;
    let baselineBroken = false;
    if (baselinePath) {
      let base;
      try {
        base = loadBaseline(baselinePath);
      } catch (err) {
        // Do not silently treat a corrupt baseline as absent (and then overwrite
        // it): report it and fail, so a real regression cannot be masked.
        process.stderr.write(`${(err as Error).message}\n`);
        baselineBroken = true;
      }
      if (base && !flags.json) {
        const d = diff(result, base);
        process.stdout.write("\n" + renderDiff(d));
        regressed = hasRegression(d);
      } else if (!base && !baselineBroken) {
        process.stderr.write(`Pas de baseline à ${baselinePath} (utilise --update-baseline pour en créer une).\n`);
      }
    }
    // Never overwrite a baseline we could not read.
    if (flags["update-baseline"] && baselinePath && !baselineBroken) {
      saveBaseline(baselinePath, result);
      process.stdout.write(`Baseline écrite dans ${baselinePath}.\n`);
    }

    // Exit non-zero on a proven high/critical, on a regression vs baseline, when
    // a check failed, or when the baseline was unreadable (fail closed).
    const errExit = result.errors.length > 0 || baselineBroken ? 2 : 0;
    return Math.max(exitCode(result), regressed ? 1 : 0, errExit);
  }

  if (cmd === "generate-tests") {
    const configPath = (flags.config as string) ?? "bastion.config.yaml";
    let config;
    try {
      config = loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const result = await run(config, configPath, { verbose: !!flags.verbose });
    const content = generateRegressionFile(result.findings);
    const out = typeof flags.out === "string" ? flags.out : "crenel.regression.test.ts";
    writeFileSync(out, content);
    const n = content.match(/\btest\(/g)?.length ?? 0;
    process.stdout.write(`${n} test(s) de régression écrits dans ${out}.\n`);
    return 0;
  }

  if (cmd === "triage") {
    // Experimental: LLM triage of leads via the local Claude CLI. Advice only.
    const configPath = (flags.config as string) ?? "bastion.config.yaml";
    let config;
    try {
      config = loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const result = await run(config, configPath, { verbose: !!flags.verbose });
    const model = typeof flags.model === "string" ? flags.model : "opus";
    const max = typeof flags.max === "string" ? Number(flags.max) : 3;
    process.stdout.write(`Triage de ${Math.min(max, result.findings.filter((f) => f.state === "unproven").length)} lead(s) via claude -p (${model})...\n\n`);
    const advice = await triageLeads(result.findings, model, max);
    for (const a of advice) {
      const f = result.findings.find((x) => x.id === a.id);
      process.stdout.write(`• ${f?.title ?? a.id}\n${a.advice}\n\n`);
    }
    process.stdout.write("Note: ceci est un avis du modèle, jamais une preuve. Seul un validateur déterministe marque 'prouvé'.\n");
    return 0;
  }

  process.stdout.write(
    [
      "Bastion - a defensive security harness for SaaS",
      "",
      "Usage:",
      "  bastion init   [--config path] [--force]   write a starter config",
      "  bastion scan   [--config path] [--json] [--out file.json] [--sarif file.sarif] [--verbose]",
      "                 [--baseline file.json] [--update-baseline] [--audit log.jsonl]",
      "  bastion generate-tests [--config path] [--out file.test.ts]  regression test per finding",
      "  bastion triage [--config path] [--model opus] [--max 3]  LLM triage of leads (claude -p)",
      "  bastion list                                show available checks",
      "",
      "Bastion only tests hosts you declare you own. Active checks stay off until",
      "you enable them in the config for your own staging.",
      "",
    ].join("\n"),
  );
  return cmd === "help" ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`Fatal: ${(err as Error).message}\n`);
    process.exit(2);
  },
);
