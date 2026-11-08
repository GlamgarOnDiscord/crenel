// GitHub check run: a "Crenel" entry in the pull request's checks list, shown
// with the GitHub App's name and logo, a summary and line annotations.
//
// REST endpoint (https://docs.github.com/en/rest/checks/runs#create-a-check-run):
//   POST /repos/{owner}/{repo}/check-runs
//   { name, head_sha, status: "completed", conclusion, output: { title, summary, annotations } }
// Only a GitHub App with the "Checks: read and write" permission can create a
// check run under its own name; GITHUB_TOKEN would show it under GitHub
// Actions, so Crenel only posts a check run with an app token. At most 50
// annotations go in one request (same page), the rest are counted in the
// summary. Annotations need a repository path and a line; findings located on
// a URL or a host stay in the summary only.

import type { Finding, Severity } from "../core/types.js";
import type { DeliveryRecord, FetchLike } from "./deliver.js";
import { GITHUB_API_VERSION, cell } from "./github.js";
import { messages, type Locale } from "./i18n.js";
import { readFileSync } from "node:fs";

const MAX_ANNOTATIONS = 50;
const MAX_SUMMARY = 60_000;
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export type Conclusion = "success" | "failure" | "neutral";

export interface Annotation {
  path: string; start_line: number; end_line: number;
  annotation_level: "failure" | "warning" | "notice"; title: string; message: string;
}

/** "src/a.ts:12" or "src/a.ts:12:4" -> path and line; URLs, hosts and bare folders give nothing. */
export function locate(location: string): { path: string; line: number } | null {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(location)) return null;
  const m = /^([^\s:]+\.[^\s:/]+|[^\s:]*\/[^\s:]+):(\d+)(?::\d+)?$/.exec(location.trim());
  if (!m || m[1]!.startsWith("/") || m[1]!.includes("..")) return null;
  return { path: m[1]!.replace(/^\.\//, ""), line: Math.max(1, Number(m[2])) };
}

export function conclusionOf(findings: Finding[], failOn: Severity | "none"): Conclusion {
  const proven = findings.filter((f) => f.state === "proven");
  if (failOn !== "none" && proven.some((f) => RANK[f.severity] >= RANK[failOn])) return "failure";
  if (proven.length || findings.some((f) => f.state === "unproven")) return "neutral";
  return "success";
}

export function checkRunOutput(findings: Finding[], ctx: { project: string; locale?: Locale }): { title: string; summary: string; annotations: Annotation[] } {
  const m = messages(ctx.locale ?? "en");
  const proven = findings.filter((f) => f.state === "proven").sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  const leads = findings.filter((f) => f.state === "unproven");
  const title = m.prTitle(proven.length, ctx.project);
  const lines = [`### ${cell(title)}`, ""];
  if (proven.length) {
    lines.push(`| ${m.prColumns.join(" | ")} |`, "|---|---|---|---|");
    for (const f of proven.slice(0, 100)) lines.push(`| ${m.severity[f.severity]} | \`${cell(f.check)}\` | ${cell(f.title)} | \`${cell(f.location)}\` |`);
    lines.push("");
  }
  lines.push(m.prFooter(leads.length));
  const annotations: Annotation[] = [];
  for (const f of [...proven, ...leads]) {
    const at = locate(f.location);
    if (!at) continue;
    annotations.push({
      path: at.path, start_line: at.line, end_line: at.line,
      annotation_level: f.state !== "proven" ? "notice" : RANK[f.severity] >= RANK.high ? "failure" : "warning",
      title: `${m.severity[f.severity]} · ${f.check}`.slice(0, 255),
      message: (f.state === "proven" ? f.title : `${m.lead}: ${f.title}`).slice(0, 1000),
    });
    if (annotations.length >= MAX_ANNOTATIONS) break;
  }
  const summary = lines.join("\n");
  return { title: title.slice(0, 255), summary: summary.length <= MAX_SUMMARY ? summary : summary.slice(0, MAX_SUMMARY - 20) + "\n\n(…)", annotations };
}

export interface CheckRunInput {
  findings: Finding[]; project: string; failOn: Severity | "none";
  env?: NodeJS.ProcessEnv; fetch?: FetchLike; locale?: Locale; headSha?: string; name?: string;
}
export interface CheckRunResult { action: "created" | "skipped"; reason?: string; conclusion?: Conclusion; records: DeliveryRecord[]; url?: string }

function headShaFromEvent(path: string | undefined): string | undefined {
  if (!path) return undefined;
  try {
    const ev = JSON.parse(readFileSync(path, "utf8")) as { pull_request?: { head?: { sha?: string } } };
    return ev.pull_request?.head?.sha;
  } catch { return undefined; }
}

export async function postCheckRun(input: CheckRunInput): Promise<CheckRunResult> {
  const env = input.env ?? process.env;
  const records: DeliveryRecord[] = [];
  const token = env.GITHUB_TOKEN;
  const repo = env.GITHUB_REPOSITORY;
  if (!token) return { action: "skipped", reason: "no GitHub App token (a check run needs an app with Checks: read and write)", records };
  if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo)) return { action: "skipped", reason: "GITHUB_REPOSITORY is missing", records };
  // On pull_request events GITHUB_SHA is the merge commit; the check belongs on the PR head.
  const sha = input.headSha ?? headShaFromEvent(env.GITHUB_EVENT_PATH) ?? env.GITHUB_SHA;
  if (!sha || !/^[0-9a-f]{40}$/.test(sha)) return { action: "skipped", reason: "no head commit SHA", records };
  let api: URL;
  try { api = new URL(env.GITHUB_API_URL ?? "https://api.github.com"); } catch { return { action: "skipped", reason: "GITHUB_API_URL is invalid", records }; }
  if (api.protocol !== "https:") return { action: "skipped", reason: "GITHUB_API_URL must be https", records };
  const conclusion = conclusionOf(input.findings, input.failOn);
  const output = checkRunOutput(input.findings, { project: input.project, locale: input.locale });
  const server = env.GITHUB_SERVER_URL ?? "https://github.com";
  const payload = {
    name: input.name ?? "Crenel", head_sha: sha, status: "completed", conclusion,
    completed_at: new Date().toISOString(), output,
    ...(env.GITHUB_RUN_ID ? { details_url: `${server}/${repo}/actions/runs/${env.GITHUB_RUN_ID}` } : {}),
  };
  const f = input.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const t0 = Date.now();
  try {
    const res = await f(`${api.toString().replace(/\/+$/, "")}/repos/${repo}/check-runs`, {
      method: "POST", redirect: "manual", signal: AbortSignal.timeout(15_000), body: JSON.stringify(payload),
      headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": GITHUB_API_VERSION, "user-agent": "Crenel-Integrations/1", "content-type": "application/json" },
    });
    const text = await res.text().catch(() => "");
    let json: { html_url?: string; message?: string } | null = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
    const ok = res.status === 201;
    records.push({ at: new Date(t0).toISOString(), kind: "integration", integration: "github", event: "check-run.create", host: api.hostname, ok, status: res.status, ms: Date.now() - t0,
      ...(ok ? {} : { error: String(json?.message ?? `HTTP ${res.status}`).slice(0, 120) }) });
    if (!ok) return { action: "skipped", reason: res.status === 403 ? "the app lacks the Checks: read and write permission (or the installation has not accepted it)" : `GitHub answered ${res.status}`, records };
    return { action: "created", conclusion, records, url: json?.html_url };
  } catch (err) {
    records.push({ at: new Date(t0).toISOString(), kind: "integration", integration: "github", event: "check-run.create", host: api.hostname, ok: false, error: (err as Error).name === "TimeoutError" ? "timeout" : "network error", ms: Date.now() - t0 });
    return { action: "skipped", reason: "network error", records };
  }
}
