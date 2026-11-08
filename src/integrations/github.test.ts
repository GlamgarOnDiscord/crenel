import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "../core/types.js";
import type { FetchLike } from "./deliver.js";
import { GITHUB_API_VERSION, PR_MARKER, cell, postPrComment, prCommentBody } from "./github.js";

function f(over: Partial<Finding> = {}): Finding {
  return { id: "a", check: "exposed-secrets", title: "Stripe key", severity: "critical", state: "proven", location: "dist/app.js:3", description: "", remediation: "",
    proof: { method: "m", replay: "curl -H 'Authorization: Bearer LEAKME'" }, ...over };
}

function event(n: number): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-gh-"));
  writeFileSync(join(dir, "event.json"), JSON.stringify({ pull_request: { number: n } }));
  return join(dir, "event.json");
}

function github(routes: Record<string, { status: number; json?: unknown }>) {
  const calls: { method: string; url: string; headers: Record<string, string>; body?: string }[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ method: init.method, url, headers: init.headers, body: init.body });
    const key = `${init.method} ${new URL(url).pathname}`;
    const r = routes[key] ?? { status: 404, json: { message: "Not Found" } };
    return { status: r.status, headers: { get: () => null }, text: async () => JSON.stringify(r.json ?? {}) };
  };
  return { fetch, calls };
}

const env = (extra: Record<string, string> = {}) => ({ GITHUB_TOKEN: "ghs_token", GITHUB_REPOSITORY: "acme/app", GITHUB_EVENT_PATH: event(7), GITHUB_RUN_ID: "99", ...extra });

test("PR comment: created with the documented endpoint, headers and only the proven findings", async () => {
  const gh = github({ "GET /repos/acme/app/issues/7/comments": { status: 200, json: [] }, "POST /repos/acme/app/issues/7/comments": { status: 201, json: { html_url: "https://github.com/acme/app/pull/7#c" } } });
  const r = await postPrComment({ findings: [f(), f({ id: "b", state: "unproven", title: "unproven-title-xyz" })], project: "acme", env: env(), fetch: gh.fetch });
  assert.equal(r.action, "created");
  const post = gh.calls.find((c) => c.method === "POST")!;
  assert.equal(post.url, "https://api.github.com/repos/acme/app/issues/7/comments");
  assert.equal(post.headers.accept, "application/vnd.github+json");
  assert.equal(post.headers["x-github-api-version"], GITHUB_API_VERSION);
  assert.equal(post.headers.authorization, "Bearer ghs_token");
  const body = JSON.parse(post.body!).body as string;
  assert.ok(body.startsWith(PR_MARKER));
  assert.match(body, /Stripe key/);
  assert.doesNotMatch(body, /unproven-title-xyz|LEAKME/);
  assert.match(body, /1 lead not listed/);
  assert.ok(r.records.every((x) => x.integration === "github" && x.host === "api.github.com"));
  assert.doesNotMatch(JSON.stringify(r.records), /ghs_token/);
});

test("PR comment: our earlier bot comment is edited, not re-posted", async () => {
  const gh = github({
    "GET /repos/acme/app/issues/7/comments": { status: 200, json: [{ id: 1, body: PR_MARKER + " spoof", user: { type: "User" } }, { id: 42, body: PR_MARKER + "\nold", user: { type: "Bot" } }] },
    "PATCH /repos/acme/app/issues/comments/42": { status: 200, json: {} },
  });
  const r = await postPrComment({ findings: [], project: "acme", env: env(), fetch: gh.fetch });
  assert.equal(r.action, "updated");
  assert.match(JSON.parse(gh.calls.at(-1)!.body!).body, /No proven finding/);
});

test("PR comment: nothing proven and no earlier comment means no comment", async () => {
  const gh = github({ "GET /repos/acme/app/issues/7/comments": { status: 200, json: [] } });
  const r = await postPrComment({ findings: [f({ state: "unproven" })], project: "acme", env: env(), fetch: gh.fetch });
  assert.equal(r.action, "skipped");
  assert.equal(gh.calls.filter((c) => c.method !== "GET").length, 0);
});

test("PR comment: a read-only token (fork) is skipped with a reason, not an error", async () => {
  const gh = github({ "GET /repos/acme/app/issues/7/comments": { status: 200, json: [] }, "POST /repos/acme/app/issues/7/comments": { status: 403, json: { message: "Resource not accessible by integration" } } });
  const r = await postPrComment({ findings: [f()], project: "acme", env: env(), fetch: gh.fetch });
  assert.equal(r.action, "skipped");
  assert.match(r.reason!, /pull-requests: write/);
  assert.equal(r.records.at(-1)!.error, "Resource not accessible by integration");
});

test("PR comment: outside a pull request, without a token or with a plain-http API, nothing is sent", async () => {
  const gh = github({});
  assert.equal((await postPrComment({ findings: [f()], project: "p", env: { ...env(), GITHUB_EVENT_PATH: "" }, fetch: gh.fetch })).action, "skipped");
  assert.equal((await postPrComment({ findings: [f()], project: "p", env: { ...env(), GITHUB_TOKEN: "" }, fetch: gh.fetch })).action, "skipped");
  assert.equal((await postPrComment({ findings: [f()], project: "p", env: env({ GITHUB_API_URL: "http://ghe.local/api/v3" }), fetch: gh.fetch })).action, "skipped");
  assert.equal(gh.calls.length, 0);
});

test("comment cells neutralise markdown tables, HTML and @mentions", () => {
  assert.equal(cell("a|b\n<img> @team #12"), "a\\|b &lt;img&gt; @​team #​12");
  const body = prCommentBody([f({ title: "x | y" })], { project: "p" });
  assert.match(body, /x \\\| y/);
});

test("PR comment: French, with the name always and the logo only from a public https URL", () => {
  const fr = prCommentBody([f(), f({ id: "b", state: "unproven" })], { project: "acme", locale: "fr" });
  assert.match(fr, /^<!-- crenel:pr-summary -->\n\*\*Crenel\*\*\n/);
  assert.match(fr, /### 1 faille prouvée sur acme/);
  assert.match(fr, /\| Sévérité \| Contrôle \| Faille \| Emplacement \|/);
  assert.match(fr, /\| Critique \|/);
  assert.match(fr, /1 piste non listée : une piste n'est pas prouvée/);
  assert.doesNotMatch(fr, /<img/);
  const logo = prCommentBody([f()], { project: "acme", logoUrl: "https://example.org/crenel-icon-512.png" });
  assert.match(logo, /<img src="https:\/\/example.org\/crenel-icon-512.png" width="20" height="20" alt="Crenel" align="top"> \*\*Crenel\*\*/);
  assert.doesNotMatch(prCommentBody([f()], { project: "acme", logoUrl: 'https://x.org/a.png" onerror="x' }), /<img/);
  assert.doesNotMatch(prCommentBody([f()], { project: "acme", logoUrl: "http://x.org/a.png" }), /<img/);
  assert.match(prCommentBody([f()], { project: "acme" }), /### 1 proven finding on acme/);
});

test("PR comment: with a GitHub App, only the app's own comment is edited", async () => {
  const gh = github({
    "GET /repos/acme/app/issues/7/comments": { status: 200, json: [{ id: 5, body: PR_MARKER + "\nold", user: { type: "Bot", login: "github-actions[bot]" } }] },
    "POST /repos/acme/app/issues/7/comments": { status: 201, json: {} },
  });
  const r = await postPrComment({ findings: [f()], project: "acme", env: env({ CRENEL_COMMENT_AUTHOR: "crenel-acme[bot]" }), fetch: gh.fetch });
  assert.equal(r.action, "created", "the github-actions comment is not the app's: a new one is posted");
});
