// `crenel integrations status|test|set-secret` and `crenel github-comment`.
// Every outbound call is journaled in .crenel/audit.jsonl next to the config
// (kind "integration": destination host, event, status; never a URL path, a
// body or a secret) and printed as one line with the host only.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { loadConfig, type Config } from "../core/config.js";
import type { Finding } from "../core/types.js";
import { StateStore } from "../agent/state.js";
import type { DeliveryRecord, FetchLike } from "./deliver.js";
import { integrationsOptions, secretKey, webhookSecretEnv } from "./options.js";
import { SecretStore, maskUrl, redact } from "./secrets.js";
import { isSlackWebhookUrl, sendSlack, slackTestMessage } from "./slack.js";
import { MIN_SECRET_LENGTH, sendWebhook } from "./webhook.js";
import { notify } from "./notify.js";
import { postPrComment } from "./github.js";
import { postCheckRun } from "./checks.js";
import type { Severity } from "../core/types.js";
import { messages, resolveLocale } from "./i18n.js";

export const stateDirOf = (configPath: string) => join(dirname(resolve(configPath)), ".crenel");

export function describeRecord(r: DeliveryRecord): string {
  return `${r.integration} ${r.event} -> ${r.host || "(no host)"}: ${r.ok ? "sent" : "not sent"}${r.status ? ` (${r.status})` : ""}${r.error ? `, ${r.error}` : ""}`;
}

export interface IntegrationsCli {
  sub: string;
  arg?: string;
  config: Config;
  configPath: string;
  json?: boolean;
  out: (s: string) => void;
  err: (s: string) => void;
  stdin?: () => Promise<string>;
  fetch?: FetchLike;
  env?: NodeJS.ProcessEnv;
}

/** Status of each destination, without any secret value. */
export function integrationsStatus(config: Config, stateDir: string, env: NodeJS.ProcessEnv = process.env) {
  const opts = integrationsOptions(config);
  const secrets = new SecretStore(stateDir, env);
  const src = (key: string, envVar: string) => { try { return secrets.get(key, envVar).source; } catch (err) { return `error: ${(err as Error).message}` as const; } };
  const slackEnv = opts.slack?.webhookUrlEnv ?? "CRENEL_SLACK_WEBHOOK_URL";
  const slackSecret = (() => { try { return secrets.get(secretKey.slack, slackEnv).value; } catch { return null; } })();
  return {
    allowedHosts: opts.allowedHosts,
    scanHosts: config.scope.allowedHosts,
    slack: {
      enabled: !!opts.slack?.enabled, minSeverity: opts.slack?.minSeverity ?? "high", envVar: slackEnv,
      source: src(secretKey.slack, slackEnv), destination: slackSecret ? maskUrl(slackSecret) : null,
      configured: !!slackSecret,
    },
    webhooks: opts.webhooks.map((w) => ({
      name: w.name, enabled: w.enabled, events: w.events, minSeverity: w.minSeverity, host: (() => { try { return new URL(w.url).hostname; } catch { return ""; } })(),
      destination: maskUrl(w.url), envVar: webhookSecretEnv(w), source: src(secretKey.webhook(w.name), webhookSecretEnv(w)),
    })),
    secretsFile: secrets.path,
  };
}

/** Send a test message to one destination. */
export async function testIntegration(target: string, config: Config, stateDir: string, opts: { fetch?: FetchLike; env?: NodeJS.ProcessEnv } = {}): Promise<DeliveryRecord> {
  const io = integrationsOptions(config);
  const secrets = new SecretStore(stateDir, opts.env);
  const base = { event: "test", allowedHosts: io.allowedHosts, scanHosts: config.scope.allowedHosts, fetch: opts.fetch, secrets: secrets.values() };
  const locale = resolveLocale(io.locale, opts.env);
  const refused = (integration: string, error: string): DeliveryRecord => ({ at: new Date().toISOString(), kind: "integration", integration, event: "test", host: "", ok: false, error, ms: 0 });
  if (target === "slack") {
    const envVar = io.slack?.webhookUrlEnv ?? "CRENEL_SLACK_WEBHOOK_URL";
    const url = secrets.get(secretKey.slack, envVar).value;
    if (!url) return refused("slack", `no webhook URL (set ${envVar} or save it from the console)`);
    return (await sendSlack(url, slackTestMessage(config.project, locale), base)).record;
  }
  const name = target.replace(/^webhook:/, "");
  const hook = io.webhooks.find((w) => w.name === name);
  if (!hook) return refused(`webhook:${name}`, "no such webhook in options.integrations.webhooks");
  const secret = secrets.get(secretKey.webhook(hook.name), webhookSecretEnv(hook)).value;
  if (!secret) return refused(`webhook:${name}`, `no signing secret (set ${webhookSecretEnv(hook)})`);
  return (await sendWebhook(hook, secret, "test", { project: config.project, locale }, { message: messages(locale).hookTest(config.project) }, base)).record;
}

export async function integrationsCommand(c: IntegrationsCli): Promise<number> {
  const stateDir = stateDirOf(c.configPath);
  const store = new StateStore(stateDir);
  if (c.sub === "status") {
    const st = integrationsStatus(c.config, stateDir, c.env);
    if (c.json) { c.out(JSON.stringify(st, null, 2) + "\n"); return 0; }
    c.out(`Destinations allowed: ${st.allowedHosts.join(", ") || "(none: options.integrations.allowedHosts)"}\n`);
    c.out(`slack     ${st.slack.enabled ? "on" : "off"}, ${st.slack.configured ? `webhook ${st.slack.destination} from ${st.slack.source}` : `no webhook URL (${st.slack.envVar})`}, ${st.slack.minSeverity}+\n`);
    for (const w of st.webhooks) c.out(`webhook   ${w.name}: ${w.enabled ? "on" : "off"}, ${w.destination}, secret ${w.source ?? `missing (${w.envVar})`}, ${w.events.join(" ")}\n`);
    return 0;
  }
  if (c.sub === "test") {
    if (!c.arg) { c.err("crenel integrations test slack|webhook:<name>\n"); return 2; }
    const r = await testIntegration(c.arg, c.config, stateDir, { fetch: c.fetch, env: c.env });
    store.appendAudit({ ...r });
    c.out(describeRecord(r) + "\n");
    return r.ok ? 0 : 1;
  }
  if (c.sub === "set-secret") {
    // The value is read from stdin, never from argv (it would sit in the shell history).
    const io = integrationsOptions(c.config);
    const key = c.arg === "slack" ? secretKey.slack : c.arg?.startsWith("webhook:") ? secretKey.webhook(c.arg.slice(8)) : null;
    if (!key || !c.stdin) { c.err("crenel integrations set-secret slack|webhook:<name>  (value on stdin)\n"); return 2; }
    if (c.arg !== "slack" && !io.webhooks.some((w) => `webhook:${w.name}` === c.arg)) { c.err(`${c.arg}: declare it in options.integrations.webhooks first\n`); return 2; }
    const value = (await c.stdin()).trim();
    if (c.arg === "slack" && !isSlackWebhookUrl(value)) { c.err("not a Slack Incoming Webhook URL (https://hooks.slack.com/services/…)\n"); return 2; }
    if (c.arg !== "slack" && value.length < MIN_SECRET_LENGTH) { c.err(`a signing secret needs at least ${MIN_SECRET_LENGTH} characters\n`); return 2; }
    const secrets = new SecretStore(stateDir, c.env);
    secrets.set(key, value);
    store.appendAudit({ at: new Date().toISOString(), kind: "integration-secret-set", integration: c.arg });
    c.out(`Saved in ${secrets.path} (mode 0600).\n`);
    return 0;
  }
  c.err("crenel integrations status|test|set-secret\n");
  return 2;
}

/** After `crenel scan --notify`. */
export async function notifyAfterScan(config: Config, configPath: string, findings: Finding[], log: (s: string) => void, fetch?: FetchLike): Promise<void> {
  const stateDir = stateDirOf(configPath);
  const store = new StateStore(stateDir);
  try {
    const r = await notify({ config, stateDir, findings, fetch });
    for (const rec of r.records) { store.appendAudit({ ...rec }); log(describeRecord(rec)); }
    for (const s of r.skipped) log(`integrations: ${s}`);
  } catch (err) {
    log(`integrations: ${redact((err as Error).message, [])}`);
  }
}

/** `crenel github-comment --report crenel.json`: never fails the job on GitHub's answer. */
export async function githubCommentCommand(o: { reportPath: string; configPath: string; project?: string; out: (s: string) => void; err: (s: string) => void; fetch?: FetchLike; env?: NodeJS.ProcessEnv }): Promise<number> {
  let report: { project?: string; findings?: Finding[] };
  try { report = JSON.parse(readFileSync(o.reportPath, "utf8")); } catch (err) { o.err(`Cannot read the report ${o.reportPath}: ${(err as Error).message}\n`); return 2; }
  if (!Array.isArray(report.findings)) { o.err(`${o.reportPath} is not a Crenel JSON report (crenel scan --out)\n`); return 2; }
  // Language and logo come from options.integrations when the config is readable.
  let io: ReturnType<typeof integrationsOptions> | null = null;
  try { io = integrationsOptions(loadConfig(o.configPath)); } catch { /* no config: defaults */ }
  const locale = resolveLocale(io?.locale, o.env);
  const r = await postPrComment({ findings: report.findings, project: o.project ?? report.project ?? "project", env: o.env, fetch: o.fetch, locale, logoUrl: io?.github?.logoUrl });
  const store = new StateStore(stateDirOf(o.configPath));
  for (const rec of r.records) store.appendAudit({ ...rec });
  // A workflow command on stdout: shows as a warning annotation on the run.
  if (r.action === "skipped") o.out(`::warning::Crenel PR comment skipped: ${r.reason}\n`);
  else o.out(`PR comment ${r.action}${r.url ? `: ${r.url}` : ""}\n`);
  return 0;
}

/** `crenel github-check --report crenel.json --fail-on high`: a "Crenel" check run under the GitHub App; never fails the job. */
export async function githubCheckCommand(o: { reportPath: string; configPath: string; failOn: string; project?: string; out: (s: string) => void; err: (s: string) => void; fetch?: FetchLike; env?: NodeJS.ProcessEnv }): Promise<number> {
  let report: { project?: string; findings?: Finding[] };
  try { report = JSON.parse(readFileSync(o.reportPath, "utf8")); } catch (err) { o.err(`Cannot read the report ${o.reportPath}: ${(err as Error).message}\n`); return 2; }
  if (!Array.isArray(report.findings)) { o.err(`${o.reportPath} is not a Crenel JSON report (crenel scan --out)\n`); return 2; }
  const failOn = (["critical", "high", "medium", "low", "info", "none"].includes(o.failOn) ? o.failOn : "high") as Severity | "none";
  let io: ReturnType<typeof integrationsOptions> | null = null;
  try { io = integrationsOptions(loadConfig(o.configPath)); } catch { /* no config: defaults */ }
  const r = await postCheckRun({ findings: report.findings, project: o.project ?? report.project ?? "project", failOn, env: o.env, fetch: o.fetch, locale: resolveLocale(io?.locale, o.env) });
  const store = new StateStore(stateDirOf(o.configPath));
  for (const rec of r.records) store.appendAudit({ ...rec });
  if (r.action === "skipped") o.out(`::warning::Crenel check run skipped: ${r.reason}\n`);
  else o.out(`Check run created (${r.conclusion})${r.url ? `: ${r.url}` : ""}\n`);
  return 0;
}
