#!/usr/bin/env node
// Crenel CLI:
//   scan   run the checks against a config and report
//   serve  local web console + JSON API (127.0.0.1, random token)
//   list   show available checks
//   init   write a starter config
//   explore free exploration by a model (claude -p), every claim replayed by a validator
//   tools  optional toolbox (nuclei, katana, trufflehog, httpx) behind the scoped proxy: Docker, or WSL on Windows
//
// Kept dependency-free (no arg parser) so the tool stays small and auditable.

import { writeFileSync, existsSync } from "node:fs";
import { loadConfig, scopeSettings } from "./core/config.js";
import { run } from "./core/runner.js";
import { REGISTRY } from "./core/registry.js";
import { renderText, renderJson, renderDiff, exitCode } from "./report/render.js";
import { toSarif, sarifOptionsFor } from "./report/sarif.js";
import { appendAudit } from "./core/audit.js";
import { generateRegressionFile } from "./generate/tests.js";
import { loadBaseline, saveBaseline, diff, hasRegression } from "./core/baseline.js";
import { triageLeads } from "./agent/triage.js";
import { reviewBundle } from "./agent/bundle-review.js";
import { checkModelEndpoint, claudeCli, DEFAULT_MODEL, detectClaude, parseEffort, selectLlm } from "./agent/llm.js";
import { crawlLiveBundle, extractEndpoints, extractQueryParams } from "./checks/live-bundle.js";
import { runAutoProbe, type Endpoint } from "./agent/autoprobe.js";
import { Scope } from "./core/scope.js";
import { toJunit } from "./report/junit.js";
import { SEVERITIES } from "./report/render.js";
import type { Severity } from "./core/types.js";
import { spawn } from "node:child_process";
import { dirname, isAbsolute, resolve } from "node:path";
import { VERSION } from "./version.js";

// Default config file. `crenel.config.yaml`, falling back to the pre-rename
// `bastion.config.yaml` when only that one exists, so older setups keep working.
function defaultConfigPath(): string {
  if (!existsSync("crenel.config.yaml") && existsSync("bastion.config.yaml")) return "bastion.config.yaml";
  return "crenel.config.yaml";
}

const STARTER = `# Crenel config. Declare only what you own.
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
// (e.g. `crenel --verbose scan` must keep `scan` as the command).
const BOOLEAN_FLAGS = new Set(["version", "verbose", "json", "force", "update-baseline", "help", "open", "llm", "no-llm", "notify", "exit-with-stdin"]);
// Flags that require a value; a missing one is an error, not a silent skip.
const VALUE_FLAGS = new Set(["config", "out", "sarif", "audit", "baseline", "model", "max", "junit", "fail-on", "port", "host", "report", "mode", "max-calls", "llm-script", "state", "model-base-url", "model-api-key-env", "effort"]);

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
    if (!BOOLEAN_FLAGS.has(key) && !VALUE_FLAGS.has(key)) warnings.push(`unknown flag ignored: --${key}`);
    if (BOOLEAN_FLAGS.has(key)) { flags[key] = true; continue; }
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("-")) { flags[key] = next; i++; }
    else { // value flag with no value
      flags[key] = true;
      if (VALUE_FLAGS.has(key)) warnings.push(`--${key} expects a value, ignored`);
    }
  }
  return { _, flags, warnings };
}

// Run the checks, turning a scope/config error (e.g. a stagingUrl not in
// allowedHosts, which the Scope constructor rejects) into a clean message and a
// null result the caller reports as exit 2, instead of an uncaught "Fatal:".
async function runGuarded(config: Parameters<typeof run>[0], configPath: string, verbose: boolean) {
  try {
    return await run(config, configPath, { verbose });
  } catch (err) {
    process.stderr.write(`Scope or configuration error: ${(err as Error).message}\n`);
    return null;
  }
}

// Locations become repository-relative (the cwd, as in a GitHub checkout);
// rules get the registry's titles. See src/report/sarif.ts.
function sarifOptions(config: { projectDir: string }, configPath: string) {
  return sarifOptionsFor(config.projectDir, configPath, Object.fromEntries(REGISTRY.map((c) => [c.name, c.title])));
}

async function main(): Promise<number> {
  const { _, flags, warnings } = parseFlags(process.argv.slice(2));
  for (const w of warnings) process.stderr.write(`Attention: ${w}\n`);
  const cmd = _[0] ?? "help";

  if (cmd === "version" || (flags.version && _.length === 0)) {
    process.stdout.write(`crenel ${VERSION}\n`);
    return 0;
  }

  if (cmd === "list") {
    process.stdout.write("Available checks:\n");
    for (const c of REGISTRY) {
      const kind = c.readOnly ? "read-only" : "active";
      process.stdout.write(`  ${c.name.padEnd(18)} [${kind}]  ${c.title}\n`);
    }
    return 0;
  }

  if (cmd === "init") {
    const path = (flags.config as string) ?? defaultConfigPath();
    if (existsSync(path) && !flags.force) {
      process.stderr.write(`${path} already exists. Use --force to overwrite.\n`);
      return 1;
    }
    writeFileSync(path, STARTER);
    process.stdout.write(`Wrote ${path}. Edit it, then run: crenel scan --config ${path}\n`);
    return 0;
  }

  if (cmd === "scan") {
    const configPath = (flags.config as string) ?? defaultConfigPath();
    let config;
    try {
      config = loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const result = await runGuarded(config, configPath, !!flags.verbose);
    if (!result) return 2;
    if (flags.json) {
      process.stdout.write(renderJson(result) + "\n");
    } else {
      process.stdout.write(renderText(result) + "\n");
    }
    // A check that threw produced no findings; surface it loudly so a partial
    // run is never mistaken for a clean one (the exit code reflects it below).
    if (result.errors.length > 0) {
      process.stderr.write(`\n${result.errors.length} check(s) failed, partial result:\n`);
      for (const e of result.errors) process.stderr.write(`  - ${e.check}: ${e.message}\n`);
    }
    if (flags.out && typeof flags.out === "string") {
      writeFileSync(flags.out, renderJson(result));
    }
    if (flags.sarif && typeof flags.sarif === "string") {
      writeFileSync(flags.sarif, toSarif(result, sarifOptions(config, configPath)));
    }
    if (flags.junit && typeof flags.junit === "string") {
      writeFileSync(flags.junit, toJunit(result));
    }
    if (flags.audit && typeof flags.audit === "string") {
      appendAudit(flags.audit, result, {
        allowedHosts: config.scope.allowedHosts,
        allowActiveTesting: config.scope.allowActiveTesting,
        stagingUrl: config.scope.stagingUrl,
      });
    }

    // Integrations (Slack, webhooks) only when asked: a scan never calls out
    // to a destination by itself. See docs/INTEGRATIONS.md.
    if (flags.notify) {
      const { notifyAfterScan } = await import("./integrations/cli.js");
      await notifyAfterScan(config, configPath, result.findings, (m) => process.stderr.write(`${m}\n`));
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
        process.stderr.write(`No baseline at ${baselinePath} (use --update-baseline to create one).\n`);
      }
    }
    // Never overwrite a baseline we could not read.
    if (flags["update-baseline"] && baselinePath && !baselineBroken) {
      saveBaseline(baselinePath, result);
      process.stdout.write(`Baseline written to ${baselinePath}.\n`);
    }

    // Exit non-zero on a proven high/critical, on a regression vs baseline, when
    // a check failed, or when the baseline was unreadable (fail closed).
    const errExit = result.errors.length > 0 || baselineBroken ? 2 : 0;
    const failOn = typeof flags["fail-on"] === "string" ? flags["fail-on"] : "high";
    if (!SEVERITIES.includes(failOn as Severity)) {
      process.stderr.write(`--fail-on expects one of ${SEVERITIES.join(", ")}\n`);
      return 2;
    }
    return Math.max(exitCode(result, failOn as Severity), regressed ? 1 : 0, errExit);
  }

  if (cmd === "generate-tests") {
    const configPath = (flags.config as string) ?? defaultConfigPath();
    let config;
    try {
      config = loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const result = await runGuarded(config, configPath, !!flags.verbose);
    if (!result) return 2;
    const content = generateRegressionFile(result.findings);
    const out = typeof flags.out === "string" ? flags.out : "crenel.regression.test.ts";
    writeFileSync(out, content);
    const n = content.match(/\btest\(/g)?.length ?? 0;
    process.stdout.write(`${n} regression test(s) written to ${out}.\n`);
    return 0;
  }

  if (cmd === "serve") {
    const configPath = (flags.config as string) ?? defaultConfigPath();
    try {
      loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const { startServer } = await import("./server/http.js");
    const host = typeof flags.host === "string" ? flags.host : "127.0.0.1";
    if (!["127.0.0.1", "localhost", "::1"].includes(host)) {
      process.stderr.write(`Warning: listening on ${host}, reachable from other machines. The token is the only lock.\n`);
    }
    // The model is opt-in: `claude -p` spends the user's subscription, so it only
    // runs when asked with --llm. Without it everything stays deterministic.
    const useLlm = !!flags.llm && !flags["no-llm"];
    const claudeAvailable = useLlm ? await detectClaude() : false;
    if (useLlm && !claudeAvailable) process.stderr.write("--llm: the claude CLI was not found, running without a model.\n");
    const srv = await startServer({ configPath, host, port: typeof flags.port === "string" ? Number(flags.port) : 4100, llm: useLlm ? "auto" : "off", claudeAvailable });
    const link = `${srv.url}/?token=${srv.token}`;
    process.stdout.write([
      "Crenel console",
      `  ${link}`,
      "",
      `  config   ${configPath}`,
      `  model    ${claudeAvailable ? "claude -p (local CLI), advice and prose only" : "none (deterministic only; add --llm to use claude -p)"}`,
      `  state    .crenel/ next to the config (journals, findings, audit)`,
      "",
      "Local only. Ctrl+C stops the server and every run.",
      "",
    ].join("\n"));
    if (flags.open) openBrowser(link);
    await new Promise<void>((ok) => {
      const bye = () => { void srv.close().then(ok); };
      process.once("SIGINT", bye);
      process.once("SIGTERM", bye);
      // A parent app (the desktop window) keeps our stdin open: when it goes
      // away, even killed, stdin closes and the server stops with it.
      if (flags["exit-with-stdin"]) {
        process.stdin.once("end", bye);
        process.stdin.once("close", bye);
        process.stdin.resume();
      }
    });
    return 0;
  }

  if (cmd === "tools") {
    const configPath = (flags.config as string) ?? defaultConfigPath();
    let config;
    try {
      config = loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const { toolsCommand } = await import("./toolbox/cli.js");
    try {
      return await toolsCommand({
        sub: _[1] ?? "status", config, configPath, json: !!flags.json,
        audit: typeof flags.audit === "string" ? flags.audit : undefined,
        wsl: !!flags.wsl, yes: !!flags.yes,
        out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s),
      });
    } catch (err) {
      process.stderr.write(`crenel tools: ${(err as Error).message}\n`);
      return 2;
    }
  }

  if (cmd === "integrations") {
    const configPath = (flags.config as string) ?? defaultConfigPath();
    let config;
    try {
      config = loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const { integrationsCommand } = await import("./integrations/cli.js");
    try {
      return await integrationsCommand({
        sub: _[1] ?? "status", arg: _[2], config, configPath, json: !!flags.json,
        out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s),
        stdin: async () => { const chunks: Buffer[] = []; for await (const c of process.stdin) chunks.push(c as Buffer); return Buffer.concat(chunks).toString("utf8"); },
      });
    } catch (err) {
      process.stderr.write(`crenel integrations: ${(err as Error).message}\n`);
      return 2;
    }
  }

  if (cmd === "github-comment") {
    // In a GitHub Action: one PR comment summarising the proven findings of a
    // JSON report (crenel scan --out), with the workflow's GITHUB_TOKEN.
    if (typeof flags.report !== "string") {
      process.stderr.write("crenel github-comment --report crenel.json\n");
      return 2;
    }
    const { githubCommentCommand } = await import("./integrations/cli.js");
    return githubCommentCommand({
      reportPath: flags.report, configPath: (flags.config as string) ?? defaultConfigPath(),
      out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s),
    });
  }

  if (cmd === "github-check") {
    // In a GitHub Action with a GitHub App token: a "Crenel" check run with a summary and line annotations.
    if (typeof flags.report !== "string") {
      process.stderr.write("crenel github-check --report crenel.json [--fail-on high]\n");
      return 2;
    }
    const { githubCheckCommand } = await import("./integrations/cli.js");
    return githubCheckCommand({
      reportPath: flags.report, configPath: (flags.config as string) ?? defaultConfigPath(), failOn: String(flags["fail-on"] ?? "high"),
      out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s),
    });
  }

  if (cmd === "explore") {
    // Free exploration alone: the model picks its requests and reads within the
    // declared perimeter; only the generic validators decide what is proven.
    // The CLI cannot ask, so it runs like `scan`: perimeter and budgets enforced,
    // every request in the audit of the state directory.
    const configPath = (flags.config as string) ?? defaultConfigPath();
    let config;
    try { config = loadConfig(configPath); } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const mode = typeof flags.mode === "string" ? flags.mode : config.explore ?? "assist";
    if (mode !== "assist" && mode !== "full") {
      process.stderr.write(`--mode must be assist or full (got ${mode}).\n`);
      return 2;
    }
    if (typeof flags["max-calls"] === "string") {
      const n = Number(flags["max-calls"]);
      if (!Number.isInteger(n) || n < 1) { process.stderr.write("--max-calls expects a positive integer\n"); return 2; }
      config = { ...config, options: { ...config.options, explore: { ...((config.options.explore ?? {}) as object), maxCalls: n } } };
    }
    const { readFileSync, mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { scriptedLlm } = await import("./agent/llm.js");
    let llm;
    if (typeof flags["llm-script"] === "string") {
      // A recorded exploration (bench, tests): replayed answers, no model spent.
      const script = JSON.parse(readFileSync(flags["llm-script"], "utf8")) as unknown[];
      llm = scriptedLlm(script.map((x) => (typeof x === "string" ? x : JSON.stringify(x))), `scripted (${script.length} turn(s))`);
    } else {
      // --model opus|sonnet|haiku -> claude CLI (unchanged). With a provider
      // prefix -> a custom/local endpoint: openai:<m>, ollama:<m>, anthropic-api:<m>,
      // tuned by --model-base-url / --model-api-key-env or options.llm. Keys come
      // only from the env var named by --model-api-key-env/apiKeyEnv, never argv.
      if (typeof flags.effort === "string" && !parseEffort(flags.effort)) { process.stderr.write(`--effort must be low, medium, high, xhigh or max\n`); return 2; }
      // The model endpoint is outside the scoped client (it is not a scan target): it gets the same checks as the
      // console's, so prompts that carry target responses go over https (or to the loopback), never to a scan target,
      // and the key's variable is a NAME. On the owner's own command line any variable name they choose is allowed.
      const keyFlag = typeof flags["model-api-key-env"] === "string" ? flags["model-api-key-env"] : undefined;
      const cfgLlm = (config.options.llm ?? {}) as { baseUrl?: unknown; apiKeyEnv?: unknown };
      const effBase = typeof flags["model-base-url"] === "string" ? flags["model-base-url"] : typeof cfgLlm.baseUrl === "string" ? cfgLlm.baseUrl : undefined;
      const badEndpoint = checkModelEndpoint({ baseUrl: effBase, apiKeyEnv: keyFlag, scanHosts: config.scope.allowedHosts, configKeyEnv: keyFlag });
      if (badEndpoint) { process.stderr.write(`${badEndpoint}\n`); return 2; }
      const sel = selectLlm({
        spec: typeof flags.model === "string" ? flags.model : undefined,
        baseUrl: typeof flags["model-base-url"] === "string" ? flags["model-base-url"] : undefined,
        apiKeyEnv: typeof flags["model-api-key-env"] === "string" ? flags["model-api-key-env"] : undefined,
        effort: parseEffort(flags.effort),
        config: config.options.llm,
      });
      if (sel.error) { process.stderr.write(`${sel.error}\n`); return 2; }
      llm = sel.llm;
      if (!llm) {
        process.stderr.write(`--model not recognised: use opus|sonnet|haiku, or openai:<model> / ollama:<model> / anthropic-api:<model>.\n`);
        return 2;
      }
      if (sel.usesCli && !(await detectClaude())) {
        process.stderr.write(`explore needs a model: the claude CLI, a custom provider (openai:/ollama:/anthropic-api:) via --model, or --llm-script for a recorded run.\n`);
        return 2;
      }
    }
    const { AgentRun } = await import("./agent/run.js");
    const { StateStore } = await import("./agent/state.js");
    const stateDir = typeof flags.state === "string" ? resolve(flags.state) : mkdtempSync(join(tmpdir(), "crenel-explore-"));
    const store = new StateStore(stateDir);
    const agent = new AgentRun({ config, configPath, store, grants: new Set(), llm }, { prompt: "/explore", mode: "bypass", explore: mode });
    const stop = () => agent.stop("stopped by the user (signal)");
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    if (!flags.json) process.stderr.write(`Exploring (${mode}, ${llm.label}); journal: ${store.runPath(agent.id)}\n`);
    await agent.start();
    const findings = store.findings().items.filter((f) => f.run === agent.id && f.check === "explore");
    const end = agent.journal.since(0).find((e) => e.type === "explore.end")?.data as Record<string, unknown> | undefined;
    if (flags.json) {
      process.stdout.write(JSON.stringify({ findings, explore: end ?? null, status: agent.status, journal: store.runPath(agent.id) }, null, 2) + "\n");
    } else {
      for (const f of findings) process.stdout.write(`${f.state === "proven" ? "PROVEN" : "lead  "} ${f.severity.padEnd(8)} ${f.title}\n         ${f.location}\n         ${f.state === "proven" ? f.proof?.method ?? "" : f.verdict ?? ""}\n`);
      process.stdout.write(`\n${findings.filter((f) => f.state === "proven").length} proven, ${findings.filter((f) => f.state !== "proven").length} lead(s); ${String(end?.calls ?? 0)} model call(s), ${String(end?.requests ?? 0)} request(s)${end?.stopped ? `, stopped: ${String(end.stopped)}` : ""}.\n`);
      process.stdout.write("Only a validator's replay makes a finding proven; everything else stays a lead.\n");
    }
    return agent.status === "error" ? 1 : 0;
  }

  if (cmd === "triage") {
    // Experimental: LLM triage of leads via the local Claude CLI. Advice only.
    const configPath = (flags.config as string) ?? defaultConfigPath();
    let config;
    try {
      config = loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    const result = await runGuarded(config, configPath, !!flags.verbose);
    if (!result) return 2;
    const model = typeof flags.model === "string" ? flags.model : DEFAULT_MODEL;
    const max = typeof flags.max === "string" ? Number(flags.max) : 3;
    process.stdout.write(`Triaging ${Math.min(max, result.findings.filter((f) => f.state === "unproven").length)} lead(s) via claude -p (${model})...\n\n`);
    const advice = await triageLeads(result.findings, model, max);
    for (const a of advice) {
      const f = result.findings.find((x) => x.id === a.id);
      process.stdout.write(`• ${f?.title ?? a.id}\n${a.advice}\n\n`);
    }
    process.stdout.write("Note: this is the model's opinion, never proof. Only a deterministic validator marks a finding proven.\n");
    return 0;
  }

  if (cmd === "review-bundle") {
    // Hand the whole JavaScript the deployed site serves to the model (claude -p)
    // and list what it sees. Advice only: every item is a lead, quotes checked.
    const configPath = (flags.config as string) ?? defaultConfigPath();
    let config;
    try {
      config = loadConfig(configPath);
    } catch (err) {
      process.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
    if (!config.scope.stagingUrl) {
      process.stderr.write("review-bundle needs scope.stagingUrl: the page whose JavaScript is reviewed.\n");
      return 2;
    }
    const model = typeof flags.model === "string" ? flags.model : DEFAULT_MODEL;
    const llm = claudeCli(model);
    if (!llm || !(await detectClaude())) {
      process.stderr.write(`review-bundle needs the claude CLI (model ${model}).\n`);
      return 2;
    }
    const scope = new Scope(scopeSettings(config.scope));
    const log = (m: string) => process.stderr.write(`${m}\n`);
    const { files, bytes } = await crawlLiveBundle({ scope, log }, config.scope.stagingUrl);
    process.stdout.write(`Fetched ${files.length} file(s), ${Math.round(bytes / 1024)} KB, from ${config.scope.stagingUrl}. Reviewing with ${llm.label}...\n\n`);
    const maxCalls = typeof flags.max === "string" ? Number(flags.max) : undefined;
    const r = await reviewBundle(files, llm, { maxCalls, log });
    for (const f of r.findings) process.stdout.write(`• ${f.severity.toUpperCase()} ${f.title}\n  ${f.location}\n  ${f.description}\n  quote: ${f.proof?.evidence}\n\n`);
    if (r.endpoints.length) process.stdout.write(`Endpoints to add to authz-matrix:\n${r.endpoints.map((e) => `  ${e.method} ${e.path}`).join("\n")}\n\n`);
    process.stdout.write(`${r.findings.length} lead(s), ${r.calls} model call(s), ${r.dropped} item(s) dropped (quote not found in the file)${r.unseenChars ? `, ${Math.round(r.unseenChars / 1024)} KB not reviewed (raise --max)` : ""}.\n`);
    process.stdout.write("These are the model's readings, never proof. Only a deterministic validator marks a finding proven.\n");
    if (typeof flags.out === "string") writeFileSync(flags.out, JSON.stringify(r, null, 2));
    return 0;
  }

  if (cmd === "autoprobe") {
    // Deterministic exploration: recon the endpoints, then submit a systematic set
    // of claims to the generic validators (no model, reproducible). Proof stays gated.
    const configPath = (flags.config as string) ?? defaultConfigPath();
    let config;
    try { config = loadConfig(configPath); } catch (err) { process.stderr.write(`${(err as Error).message}\n`); return 2; }
    if (!config.scope.stagingUrl) { process.stderr.write("autoprobe needs a stagingUrl in the config.\n"); return 2; }
    const scope = new Scope(scopeSettings(config.scope));
    const log = (m: string) => { if (!flags.json) process.stderr.write(`${m}\n`); };
    const base = config.scope.stagingUrl.replace(/\/+$/, "");
    const { files } = await crawlLiveBundle({ scope, log }, config.scope.stagingUrl);
    const paths = new Set<string>();
    const qp: Record<string, Set<string>> = {};
    for (const f of files) if (f.kind !== "map") {
      for (const e of extractEndpoints(f.body)) paths.add(e);
      for (const [p, ks] of Object.entries(extractQueryParams(f.body))) for (const k of ks) (qp[p] ??= new Set()).add(k);
    }
    const authz = (config.options["authz-matrix"] ?? {}) as { resources?: { path?: string }[] };
    for (const r of authz.resources ?? []) if (typeof r.path === "string") paths.add(r.path);
    // The usual GraphQL paths, as the graphql floor check probes them: the validators confirm they speak GraphQL.
    for (const p of ["/graphql", "/api/graphql"]) paths.add(p);
    const endpoints: Endpoint[] = [...paths].map((p) => {
      const u = new URL(p.replace(/:id|\{[^}]+\}/g, "1"), base + "/").toString();
      const ps = [...new Set([...new URL(u).searchParams.keys(), ...(qp[p.split("?")[0]!] ?? [])])];
      return { url: u.split("?")[0]! + (ps.length ? `?${new URL(u).searchParams.toString()}` : ""), params: ps, graphql: /graphql|\/gql(\/|$)/i.test(p) };
    });
    log(`autoprobe: ${endpoints.length} endpoint(s) discovered; probing...`);
    const env = { scope, projectDir: config.projectDir, options: config.options, stagingUrl: config.scope.stagingUrl, checks: REGISTRY };
    const r = await runAutoProbe(env, { endpoints, origin: base }, { maxClaims: typeof flags.max === "string" ? Number(flags.max) : 200 });
    const findings = r.proven.map((v) => ({ check: "autoprobe", title: v.reason.slice(0, 160), state: "proven", severity: v.ceiling ?? "high", location: "/", proof: { evidence: v.reason }, validator: v.validator }));
    if (flags.json) process.stdout.write(JSON.stringify({ findings, tried: r.tried, proven: findings.length }, null, 2) + "\n");
    else { for (const f of findings) process.stdout.write(`• PROVEN ${f.title}\n`); process.stdout.write(`\n${findings.length} proven / ${r.tried} claims tried (deterministic, no model).\n`); }
    return 0;
  }

  process.stdout.write(
    [
      "Crenel - a defensive security harness for SaaS",
      "",
      "Usage:",
      "  crenel init   [--config path] [--force]   write a starter config",
      "  crenel scan   [--config path] [--json] [--out file.json] [--sarif file.sarif] [--junit file.xml]",
      "                 [--fail-on critical|high|medium|low] [--baseline file.json] [--update-baseline]",
      "                 [--audit log.jsonl] [--notify] [--verbose]",
      "                 --notify: send new proven findings to the configured Slack and webhooks",
      "  crenel serve  [--config path] [--port 4100] [--open] [--llm]      local web console and API",
      "                 [--exit-with-stdin]: stop when stdin closes (used by the desktop app)",
      "  bastion generate-tests [--config path] [--out file.test.ts]  regression test per finding",
      "  crenel triage [--config path] [--model opus-4-8] [--max 3]  LLM triage of leads (claude -p)",
      "  crenel review-bundle [--config path] [--model opus-4-8] [--max 20] [--out review.json]",
      "                 the model reads every JS chunk the live site serves (leads only)",
      "  crenel explore [--config path] [--mode assist|full] [--model sonnet|openai:<m>|ollama:<m>|anthropic-api:<m>] [--model-base-url URL] [--model-api-key-env NAME] [--effort low|medium|high|max] [--max-calls N] [--llm-script file] [--json] [--state dir]",
      "                 free exploration by the model (claude -p); claims proven only by a validator's replay",
      "                 [--llm-script turns.json]: replay a recorded exploration, no model spent",
      "  crenel tools  status|build|selftest|nuclei|katana|trufflehog|httpx [--config path] [--json] [--audit log.jsonl]",
      "                 optional toolbox (Docker, or a WSL distro on Windows); network only via Crenel's scoped proxy",
      "  crenel tools  install --wsl [--yes]   apt-get install the allowlisted tools in the WSL distro (asks first)",
      "  crenel integrations status|test slack|test webhook:<name>|set-secret slack|webhook:<name> [--json]",
      "                 Slack and signed webhooks (secret on stdin, kept in .crenel/secrets.json, 0600)",
      "  crenel github-comment --report crenel.json   PR comment of the proven findings (GitHub Action, GITHUB_TOKEN)",
      "  crenel github-check --report crenel.json     \"Crenel\" check run with annotations (GitHub Action, GitHub App token)",
      "  crenel list                                show available checks",
      "  crenel --version                           print the version",
      "",
      "Crenel only tests hosts you declare you own. Active checks stay off until",
      "you enable them in the config for your own staging.",
      "",
    ].join("\n"),
  );
  return cmd === "help" ? 0 : 1;
}

// Open a URL in the default browser, portably: no shell string, no Unix-only tool.
function openBrowser(url: string): void {
  const [cmd, args] =
    process.platform === "win32" ? ["cmd", ["/c", "start", "", url.replace(/&/g, "^&")]]
    : process.platform === "darwin" ? ["open", [url]]
    : ["xdg-open", [url]];
  try {
    spawn(cmd as string, args as string[], { stdio: "ignore", detached: true, windowsHide: true }).on("error", () => {}).unref();
  } catch {
    /* no browser: the link is printed */
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`Fatal: ${(err as Error).message}\n`);
    process.exit(2);
  },
);
