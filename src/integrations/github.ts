// GitHub pull request comment: one summary of the PROVEN findings, kept up to
// date on each push (edited, not re-posted), using only the workflow's
// GITHUB_TOKEN.
//
// REST endpoints (https://docs.github.com/en/rest/issues/comments): a pull
// request is an issue for comments, so
//   GET   /repos/{owner}/{repo}/issues/{pull_number}/comments   find ours by its marker
//   PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}    update it
//   POST  /repos/{owner}/{repo}/issues/{pull_number}/comments   or create it
// with `Accept: application/vnd.github+json` and `X-GitHub-Api-Version`.
// Permission: `pull-requests: write` covers all three
// (https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens);
// nothing else is needed for the comment. On a pull request from a fork the
// token is read-only (workflow syntax, `permissions`), so the comment is
// skipped with a warning and the job does not fail. Crenel never asks for
// pull_request_target.
//
// The API host is the runner's GITHUB_API_URL (https only), not a user URL.
// The comment lists title, severity, check and location, never a proof's
// replay or evidence. Leads are only counted.

import { readFileSync } from "node:fs";
import type { Finding, Severity } from "../core/types.js";
import type { DeliveryRecord, FetchLike } from "./deliver.js";

export const PR_MARKER = "<!-- crenel:pr-summary -->";
export const GITHUB_API_VERSION = "2026-03-10";
const MAX_ROWS = 50;
const MAX_BODY = 60_000;
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Markdown table cell: no pipe, no newline, no HTML, no @mention, no autolinked issue. */
export function cell(s: string): string {
  return s.replace(/\r?\n/g, " ").replace(/\|/g, "\\|").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/`/g, "'")
    .replace(/@/g, "@\u200b").replace(/#(\d)/g, "#\u200b$1").slice(0, 300);
}

export function prCommentBody(findings: Finding[], ctx: { project: string; codeScanningUrl?: string; runUrl?: string }): string {
  const proven = findings.filter((f) => f.state === "proven").sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  const leads = findings.filter((f) => f.state === "unproven").length;
  const lines = [PR_MARKER, `### Crenel: ${proven.length ? `${proven.length} proven finding${proven.length > 1 ? "s" : ""}` : "no proven finding"} on ${cell(ctx.project)}`, ""];
  if (proven.length) {
    lines.push("| Severity | Check | Finding | Location |", "|---|---|---|---|");
    for (const f of proven.slice(0, MAX_ROWS)) lines.push(`| ${f.severity} | \`${cell(f.check)}\` | ${cell(f.title)} | \`${cell(f.location)}\` |`);
    if (proven.length > MAX_ROWS) lines.push("", `…and ${proven.length - MAX_ROWS} more.`);
    lines.push("");
  }
  lines.push(`Each proven finding has a replayable proof${ctx.codeScanningUrl ? ` in [code scanning](${ctx.codeScanningUrl})` : ""}. ${leads} lead${leads === 1 ? "" : "s"} not listed: a lead is not proven and never fails the build.`);
  if (ctx.runUrl) lines.push("", `[Workflow run](${ctx.runUrl})`);
  const body = lines.join("\n");
  return body.length <= MAX_BODY ? body : body.slice(0, MAX_BODY - 20) + "\n\n(truncated)";
}

export interface PrCommentInput {
  findings: Finding[];
  project: string;
  env?: NodeJS.ProcessEnv;
  fetch?: FetchLike;
  /** Pull request number; default from GITHUB_EVENT_PATH. */
  pull?: number;
}

export interface PrCommentResult { action: "created" | "updated" | "skipped"; reason?: string; records: DeliveryRecord[]; url?: string }

export function pullNumberFromEvent(path: string | undefined): number | undefined {
  if (!path) return undefined;
  try {
    const ev = JSON.parse(readFileSync(path, "utf8")) as { pull_request?: { number?: number } };
    return typeof ev.pull_request?.number === "number" ? ev.pull_request.number : undefined;
  } catch { return undefined; }
}

export async function postPrComment(input: PrCommentInput): Promise<PrCommentResult> {
  const env = input.env ?? process.env;
  const records: DeliveryRecord[] = [];
  const token = env.GITHUB_TOKEN;
  const repo = env.GITHUB_REPOSITORY;
  const pull = input.pull ?? pullNumberFromEvent(env.GITHUB_EVENT_PATH);
  if (!pull) return { action: "skipped", reason: "not a pull request event", records };
  if (!token) return { action: "skipped", reason: "GITHUB_TOKEN is not set (pass github.token to the step)", records };
  if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo)) return { action: "skipped", reason: "GITHUB_REPOSITORY is missing", records };
  let api: URL;
  try { api = new URL(env.GITHUB_API_URL ?? "https://api.github.com"); } catch { return { action: "skipped", reason: "GITHUB_API_URL is invalid", records }; }
  if (api.protocol !== "https:") return { action: "skipped", reason: "GITHUB_API_URL must be https", records };
  const server = env.GITHUB_SERVER_URL ?? "https://github.com";
  const body = prCommentBody(input.findings, {
    project: input.project,
    codeScanningUrl: `${server}/${repo}/security/code-scanning?query=${encodeURIComponent(`is:open pr:${pull}`)}`,
    runUrl: env.GITHUB_RUN_ID ? `${server}/${repo}/actions/runs/${env.GITHUB_RUN_ID}` : undefined,
  });
  const f = input.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const base = api.toString().replace(/\/+$/, "");
  const headers = {
    authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": GITHUB_API_VERSION,
    "user-agent": "Crenel-Integrations/1", "content-type": "application/json",
  };
  async function call(method: string, path: string, event: string, payload?: unknown): Promise<{ status: number; json: unknown }> {
    const t0 = Date.now();
    try {
      const res = await f(`${base}${path}`, { method, headers, ...(payload !== undefined ? { body: JSON.stringify(payload) } : {}), redirect: "manual", signal: AbortSignal.timeout(15_000) });
      const text = await res.text().catch(() => "");
      let json: unknown = null;
      try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
      const ok = res.status >= 200 && res.status < 300;
      records.push({ at: new Date(t0).toISOString(), kind: "integration", integration: "github", event, host: api.hostname, ok, status: res.status, ms: Date.now() - t0,
        ...(ok ? {} : { error: String((json as { message?: string } | null)?.message ?? `HTTP ${res.status}`).slice(0, 120) }) });
      return { status: res.status, json };
    } catch (err) {
      records.push({ at: new Date(t0).toISOString(), kind: "integration", integration: "github", event, host: api.hostname, ok: false, error: (err as Error).name === "TimeoutError" ? "timeout" : "network error", ms: Date.now() - t0 });
      return { status: 0, json: null };
    }
  }
  const readOnly = (s: number) => s === 403 || s === 404
    ? "the token cannot comment: a pull request from a fork gets a read-only token, or the job lacks `permissions: pull-requests: write`"
    : `GitHub answered ${s || "nothing"}`;

  // Find our earlier comment (a bot's comment carrying the marker).
  let existing: number | undefined;
  for (let page = 1; page <= 10 && existing === undefined; page++) {
    const r = await call("GET", `/repos/${repo}/issues/${pull}/comments?per_page=100&page=${page}`, "pr-comment.list");
    if (r.status !== 200 || !Array.isArray(r.json)) return { action: "skipped", reason: readOnly(r.status), records };
    const mine = (r.json as { id: number; body?: string; user?: { type?: string } }[]).find((c) => c.user?.type === "Bot" && (c.body ?? "").startsWith(PR_MARKER));
    if (mine) existing = mine.id;
    if ((r.json as unknown[]).length < 100) break;
  }
  const proven = input.findings.some((f) => f.state === "proven");
  if (existing === undefined && !proven) return { action: "skipped", reason: "no proven finding and no earlier comment to update", records };
  const r = existing !== undefined
    ? await call("PATCH", `/repos/${repo}/issues/comments/${existing}`, "pr-comment.update", { body })
    : await call("POST", `/repos/${repo}/issues/${pull}/comments`, "pr-comment.create", { body });
  if (r.status !== 200 && r.status !== 201) return { action: "skipped", reason: readOnly(r.status), records };
  return { action: existing !== undefined ? "updated" : "created", records, url: (r.json as { html_url?: string } | null)?.html_url };
}
