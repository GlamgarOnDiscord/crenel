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
import { renderText, renderJson, exitCode } from "./report/render.js";

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

function parseFlags(argv: string[]): { _: string[]; flags: Record<string, string | boolean> } {
  const _: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      _.push(a);
    }
  }
  return { _, flags };
}

async function main(): Promise<number> {
  const { _, flags } = parseFlags(process.argv.slice(2));
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
    if (flags.out && typeof flags.out === "string") {
      writeFileSync(flags.out, renderJson(result));
    }
    return exitCode(result);
  }

  process.stdout.write(
    [
      "Bastion - a defensive security harness for SaaS",
      "",
      "Usage:",
      "  bastion init   [--config path] [--force]   write a starter config",
      "  bastion scan   [--config path] [--json] [--out file.json] [--verbose]",
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
