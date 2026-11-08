// After a run: send the NEW proven findings to the configured destinations.
//
// "New" is per destination: .crenel/integrations.json remembers which finding
// ids each destination already received, and an id is only marked once its
// delivery succeeded (a failed one is retried after the next run). A finding
// that gets fixed then proven again is sent again. Leads are never sent.
//
//   Slack     one message per run, proven findings at or above minSeverity
//             (critical or high only), at most 10 listed;
//   webhooks  one POST per new proven finding at or above the hook's
//             minSeverity (at most 50 per run, the rest stay pending), and one
//             run.completed POST per run when subscribed.
// Every attempt is returned as a DeliveryRecord for the caller to journal.

import { existsSync, readFileSync, renameSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "../core/config.js";
import type { Finding, Severity } from "../core/types.js";
import type { DeliveryRecord, FetchLike } from "./deliver.js";
import { integrationsOptions, secretKey, webhookSecretEnv, type IntegrationsOptions } from "./options.js";
import { SecretStore } from "./secrets.js";
import { sendSlack, slackFindingsMessage } from "./slack.js";
import { findingPayload, sendWebhook } from "./webhook.js";
import { messages, resolveLocale } from "./i18n.js";

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const MAX_WEBHOOK_FINDINGS = 50;

type Sent = Record<string, string[]>;

export class SentLog {
  readonly path: string;
  constructor(dir: string) { this.path = join(dir, "integrations.json"); }
  read(): Sent {
    if (!existsSync(this.path)) return {};
    try { return ((JSON.parse(readFileSync(this.path, "utf8")) as { notified?: Sent }).notified) ?? {}; } catch { return {}; }
  }
  mark(key: string, ids: string[]): void {
    if (!ids.length) return;
    const cur = this.read();
    cur[key] = [...new Set([...(cur[key] ?? []), ...ids])].slice(-5000);
    mkdirSync(join(this.path, ".."), { recursive: true });
    writeFileSync(this.path + ".tmp", JSON.stringify({ notified: cur }, null, 2));
    renameSync(this.path + ".tmp", this.path);
  }
  /** A fixed finding may come back: forget it so it is sent again. */
  forget(ids: string[]): void {
    if (!ids.length) return;
    const cur = this.read();
    const gone = new Set(ids);
    let changed = false;
    for (const k of Object.keys(cur)) {
      const next = cur[k]!.filter((id) => !gone.has(id));
      if (next.length !== cur[k]!.length) { cur[k] = next; changed = true; }
    }
    if (changed) { writeFileSync(this.path + ".tmp", JSON.stringify({ notified: cur }, null, 2)); renameSync(this.path + ".tmp", this.path); }
  }
}

export interface NotifyInput {
  config: Config;
  /** .crenel/ directory: secrets.json and integrations.json live there. */
  stateDir: string;
  findings: Finding[];
  run?: string;
  fetch?: FetchLike;
  env?: NodeJS.ProcessEnv;
  sleep?: (ms: number) => Promise<void>;
  /** Run counters for run.completed. */
  counts?: { proven: number; leads: number; fixed: number };
}

export interface NotifyResult { records: DeliveryRecord[]; skipped: string[] }

/** True when at least one destination is switched on. */
export function hasIntegrations(opts: IntegrationsOptions): boolean {
  return !!opts.slack?.enabled || opts.webhooks.some((w) => w.enabled);
}

export async function notify(input: NotifyInput): Promise<NotifyResult> {
  const opts = integrationsOptions(input.config);
  const records: DeliveryRecord[] = [];
  const skipped: string[] = [];
  if (!hasIntegrations(opts)) return { records, skipped };
  const secrets = new SecretStore(input.stateDir, input.env);
  const sent = new SentLog(input.stateDir);
  sent.forget(input.findings.filter((f) => f.state === "fixed").map((f) => f.id));
  const already = sent.read();
  const proven = input.findings.filter((f) => f.state === "proven");
  const base = { allowedHosts: opts.allowedHosts, scanHosts: input.config.scope.allowedHosts, fetch: input.fetch, run: input.run, secrets: secrets.values() };
  const locale = resolveLocale(opts.locale, input.env);
  const m = messages(locale);
  const ctx = { project: input.config.project, run: input.run, locale };

  if (opts.slack?.enabled) {
    const min = RANK[opts.slack.minSeverity];
    const seen = new Set(already.slack ?? []);
    const fresh = proven.filter((f) => RANK[f.severity] >= min && !seen.has(f.id)).sort((a, b) => RANK[b.severity] - RANK[a.severity]);
    if (fresh.length) {
      let url: string | null = null;
      try { url = secrets.get(secretKey.slack, opts.slack.webhookUrlEnv).value; } catch (err) { skipped.push(`slack: ${(err as Error).message}`); }
      if (url) {
        const { record } = await sendSlack(url, slackFindingsMessage(fresh, ctx), { ...base, event: "finding.proven" }, input.sleep);
        records.push(record);
        if (record.ok) sent.mark("slack", fresh.map((f) => f.id));
      } else if (!skipped.length) skipped.push(`slack: no webhook URL (set ${opts.slack.webhookUrlEnv} or save it from the console)`);
    }
  }

  for (const hook of opts.webhooks.filter((w) => w.enabled)) {
    const key = `webhook:${hook.name}`;
    let secret: string | null = null;
    try { secret = secrets.get(secretKey.webhook(hook.name), webhookSecretEnv(hook)).value; } catch (err) { skipped.push(`${key}: ${(err as Error).message}`); continue; }
    if (!secret) { skipped.push(`${key}: no signing secret (set ${webhookSecretEnv(hook)} or create it from the console)`); continue; }
    const seen = new Set(already[key] ?? []);
    const fresh = proven.filter((f) => RANK[f.severity] >= RANK[hook.minSeverity] && !seen.has(f.id));
    const delivered: string[] = [];
    if (hook.events.includes("finding.proven")) {
      for (const f of fresh.slice(0, MAX_WEBHOOK_FINDINGS)) {
        const { record } = await sendWebhook(hook, secret, "finding.proven", ctx, { summary: m.hookFinding(m.severity[f.severity], f.title, ctx.project), finding: findingPayload(f) }, { ...base });
        records.push(record);
        if (record.ok) delivered.push(f.id);
        else if (record.error?.startsWith("refused")) break; // the next ones would be refused too
      }
      sent.mark(key, delivered);
    }
    if (hook.events.includes("run.completed")) {
      const counts = input.counts ?? {
        proven: proven.length, leads: input.findings.filter((f) => f.state === "unproven").length, fixed: input.findings.filter((f) => f.state === "fixed").length,
      };
      const { record } = await sendWebhook(hook, secret, "run.completed", ctx, { summary: m.hookRun(counts.proven, fresh.length, counts.leads, ctx.project), ...counts, newProven: fresh.map((f) => f.id) }, { ...base });
      records.push(record);
    }
  }
  return { records, skipped };
}
