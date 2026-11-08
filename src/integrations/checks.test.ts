import { test } from "node:test";
import assert from "node:assert/strict";
import { checkRunOutput, conclusionOf, locate, postCheckRun } from "./checks.js";
import type { Finding } from "../core/types.js";

const f = (o: Partial<Finding>): Finding => ({ id: "x", check: "exposed-secrets", title: "Stripe key", severity: "critical", state: "proven", location: "dist/app.js:5", description: "", remediation: "", ...o } as Finding);

test("locate: repo paths with a line become annotations, URLs and hosts do not", () => {
  assert.deepEqual(locate("dist/app.js:5"), { path: "dist/app.js", line: 5 });
  assert.deepEqual(locate("./src/a.ts:12:4"), { path: "src/a.ts", line: 12 });
  assert.equal(locate("https://staging.example.com/api:3"), null);
  assert.equal(locate("staging.example.com"), null);
  assert.equal(locate("../etc/passwd:1"), null);
  assert.equal(locate("/abs/path.ts:1"), null);
});

test("conclusion follows fail-on; leads alone are neutral", () => {
  assert.equal(conclusionOf([f({})], "high"), "failure");
  assert.equal(conclusionOf([f({ severity: "medium" })], "high"), "neutral");
  assert.equal(conclusionOf([f({ state: "unproven" })], "high"), "neutral");
  assert.equal(conclusionOf([], "high"), "success");
  assert.equal(conclusionOf([f({})], "none"), "neutral");
});

test("output: localized title, failure annotation for proven high+, notice for leads", () => {
  const o = checkRunOutput([f({}), f({ id: "y", state: "unproven", severity: "low", location: "src/b.ts:3" }), f({ id: "z", location: "https://x.example/" })], { project: "demo", locale: "fr" });
  assert.match(o.title, /2 failles prouvées sur demo|failles prouvées/);
  assert.equal(o.annotations.length, 2);
  assert.equal(o.annotations[0]!.annotation_level, "failure");
  assert.equal(o.annotations[1]!.annotation_level, "notice");
  assert.match(o.annotations[1]!.message, /Piste/);
});

test("postCheckRun posts on the PR head SHA and reports a missing permission", async () => {
  let sent: { url: string; body: Record<string, unknown> } | null = null;
  const env = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "o/r", GITHUB_SHA: "a".repeat(40) };
  const ok = await postCheckRun({ findings: [f({})], project: "demo", failOn: "high", env, fetch: async (url: string, init: { body?: string }) => { sent = { url, body: JSON.parse(init.body!) }; return new Response(JSON.stringify({ html_url: "https://github.com/o/r/runs/1" }), { status: 201 }); } } as never);
  assert.equal(ok.action, "created");
  assert.equal(ok.conclusion, "failure");
  assert.match(sent!.url, /\/repos\/o\/r\/check-runs$/);
  assert.equal(sent!.body.name, "Crenel");
  const denied = await postCheckRun({ findings: [], project: "demo", failOn: "high", env, fetch: async () => new Response(JSON.stringify({ message: "Resource not accessible by integration" }), { status: 403 }) } as never);
  assert.equal(denied.action, "skipped");
  assert.match(denied.reason!, /Checks/);
  assert.equal((await postCheckRun({ findings: [], project: "d", failOn: "high", env: {} })).action, "skipped");
});
