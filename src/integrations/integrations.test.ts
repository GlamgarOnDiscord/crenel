import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, statSync, chmodSync, readFileSync, writeFileSync, symlinkSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../core/config.js";
import type { Finding } from "../core/types.js";
import { checkDestination, deliver, type FetchLike } from "./deliver.js";
import { SecretStore, maskUrl, redact } from "./secrets.js";
import { escapeMrkdwn, isSlackWebhookUrl, sendSlack, slackFindingsMessage } from "./slack.js";
import { sendWebhook, signCrenel, verifyCrenelSignature } from "./webhook.js";
import { notify } from "./notify.js";
import { integrationsCommand, integrationsStatus } from "./cli.js";
import { localeFromTag, messages as msgs, resolveLocale, LOCALES } from "./i18n.js";

const SLACK_URL = "https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX";
const HOOK_SECRET = "s3cr3t-s3cr3t-s3cr3t-s3cr3t-s3cr3t-0123";

interface Call { url: string; headers: Record<string, string>; body: string; redirect: string }
function mockFetch(responses: { status: number; body?: string; headers?: Record<string, string> }[] = [{ status: 200, body: "ok" }]) {
  const calls: Call[] = [];
  let i = 0;
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, headers: init.headers, body: init.body ?? "", redirect: init.redirect });
    const r = responses[Math.min(i++, responses.length - 1)]!;
    return { status: r.status, headers: { get: (n: string) => r.headers?.[n.toLowerCase()] ?? null }, text: async () => r.body ?? "" };
  };
  return { fetch, calls };
}

function f(over: Partial<Finding> = {}): Finding {
  return { id: "exposed-secrets:stripe:app.js:3", check: "exposed-secrets", title: "Stripe secret key (live)", severity: "critical", state: "proven",
    location: "dist/app.js:3", description: "d", remediation: "Rotate the key.", proof: { method: "regex", replay: "curl -H 'Authorization: Bearer TOPSECRETTOKEN' x", evidence: "sk_live_…" }, ...over };
}

function config(integrations: unknown, scanHosts = ["staging.example.com"]): Config {
  return { project: "acme", projectDir: ".", scope: { allowedHosts: scanHosts, allowActiveTesting: false, allowPrivate: false }, checks: [], options: { integrations: integrations && typeof integrations === "object" && !("locale" in integrations) ? { locale: "en", ...integrations } : integrations } };
}

const tmp = () => mkdtempSync(join(tmpdir(), "crenel-integ-"));

/* ---------------- secrets ---------------- */

test("secrets: written 0600, env var wins, a group-readable file is refused", { skip: process.platform === "win32" }, () => {
  const dir = tmp();
  const s = new SecretStore(dir, {});
  s.set("slack.webhookUrl", SLACK_URL);
  assert.equal(statSync(s.path).mode & 0o777, 0o600);
  assert.match(readFileSync(join(dir, ".gitignore"), "utf8"), /^secrets\.json$/m);
  assert.deepEqual(s.get("slack.webhookUrl", "CRENEL_SLACK_WEBHOOK_URL"), { value: SLACK_URL, source: "file" });
  const withEnv = new SecretStore(dir, { CRENEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/A/B/C" });
  assert.equal(withEnv.get("slack.webhookUrl", "CRENEL_SLACK_WEBHOOK_URL").source, "env");
  chmodSync(s.path, 0o644);
  assert.throws(() => s.get("slack.webhookUrl"), /chmod 600/);
});

test("secrets: a planted link (cloned .crenel/) is never written through nor read", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sec-link-"));
  const victim = join(dir, "victim.txt");
  writeFileSync(victim, "precious\n");
  symlinkSync(victim, join(dir, "secrets.json.tmp"));
  symlinkSync(victim, join(dir, ".gitignore"));
  const s = new SecretStore(dir, {});
  s.set("slack", "https://hooks.slack.com/services/T0/B0/XXXXXXXXXXXX");
  assert.equal(readFileSync(victim, "utf8"), "precious\n", "the link target is untouched");
  assert.ok(!lstatSync(join(dir, "secrets.json")).isSymbolicLink());
  assert.equal((statSync(join(dir, "secrets.json")).mode & 0o777), 0o600);
  const d2 = mkdtempSync(join(tmpdir(), "crenel-sec-link-"));
  chmodSync(victim, 0o600);
  symlinkSync(victim, join(d2, "secrets.json"));
  assert.throws(() => new SecretStore(d2, {}).get("slack"), /symbolic link/);
  assert.throws(() => new SecretStore(d2, {}).set("slack", "x"), /symbolic link/);
  assert.equal(readFileSync(victim, "utf8"), "precious\n");
});

test("redact and maskUrl never print a webhook path or a known secret", () => {
  assert.equal(maskUrl(SLACK_URL), "https://hooks.slack.com/…");
  const msg = redact(`failed POST ${SLACK_URL} with ${HOOK_SECRET}`, [HOOK_SECRET]);
  assert.doesNotMatch(msg, /XXXXXXXX|T0000000/);
  assert.doesNotMatch(msg, /s3cr3t/);
});

/* ---------------- destinations ---------------- */

test("destinations: https only, declared in the integrations allowlist, never a scan target", () => {
  assert.throws(() => checkDestination("http://hooks.example.com/x", ["hooks.example.com"], []), /https required/);
  assert.throws(() => checkDestination("https://evil.example.net/x", ["hooks.example.com"], []), /not in options.integrations.allowedHosts/);
  assert.throws(() => checkDestination("https://staging.example.com/hook", ["staging.example.com"], ["staging.example.com"]), /scan target/);
  assert.throws(() => checkDestination("https://u:p@hooks.example.com/x", ["hooks.example.com"], []), /credentials/);
  assert.equal(checkDestination("http://127.0.0.1:9000/x", ["127.0.0.1"], []).hostname, "127.0.0.1");
});

test("deliver: refused destinations send nothing, redirects are not followed, records carry no URL path", async () => {
  const m = mockFetch([{ status: 302, headers: { location: "https://staging.example.com/" } }]);
  const refused = await deliver({ integration: "webhook:x", event: "test", url: "https://staging.example.com/h", body: "{}", allowedHosts: ["staging.example.com"], scanHosts: ["staging.example.com"], fetch: m.fetch });
  assert.equal(refused.record.ok, false);
  assert.equal(m.calls.length, 0);
  const r = await deliver({ integration: "webhook:x", event: "test", url: "https://hooks.example.com/secret/path", body: "{}", allowedHosts: ["hooks.example.com"], scanHosts: [], fetch: m.fetch });
  assert.equal(m.calls[0]!.redirect, "manual");
  assert.equal(r.record.ok, false);
  assert.equal(r.record.error, "redirect not followed");
  assert.doesNotMatch(JSON.stringify(r.record), /secret\/path/);
});

/* ---------------- Slack ---------------- */

test("slack: Block Kit within the documented limits, mrkdwn escaped, no proof sent", () => {
  const many = Array.from({ length: 14 }, (_, i) => f({ id: `x${i}`, title: `<script> & ${"t".repeat(200)}` }));
  const m = slackFindingsMessage(many, { project: "acme", run: "r-1" });
  assert.ok(m.text && m.blocks.length <= 50);
  const header = m.blocks[0] as { type: string; text: { type: string; text: string } };
  assert.equal(header.type, "header");
  assert.equal(header.text.type, "plain_text");
  assert.ok(header.text.text.length <= 150);
  for (const b of m.blocks as { type: string; text?: { text: string }; fields?: { text: string }[] }[]) {
    if (b.text) assert.ok(b.text.text.length <= 3000);
    if (b.fields) { assert.ok(b.fields.length <= 10); for (const x of b.fields) assert.ok(x.text.length <= 2000); }
  }
  const json = JSON.stringify(m);
  assert.match(json, /&lt;script&gt; &amp;/);
  assert.doesNotMatch(json, /TOPSECRETTOKEN|sk_live/);
  assert.match(json, /and 4 more/);
  assert.equal(escapeMrkdwn("a<b>&c"), "a&lt;b&gt;&amp;c");
});

test("slack: 200 ok succeeds, an error code is journaled, a 429 waits Retry-After once", async () => {
  const base = { event: "test", allowedHosts: ["hooks.slack.com"], scanHosts: [] };
  const ok = mockFetch([{ status: 200, body: "ok" }]);
  const r1 = await sendSlack(SLACK_URL, { text: "t", blocks: [] }, { ...base, fetch: ok.fetch });
  assert.equal(r1.record.ok, true);
  assert.equal(ok.calls[0]!.headers["content-type"], "application/json");
  assert.deepEqual(Object.keys(JSON.parse(ok.calls[0]!.body)), ["text", "blocks"]);

  const bad = mockFetch([{ status: 404, body: "no_service" }]);
  const r2 = await sendSlack(SLACK_URL, { text: "t", blocks: [] }, { ...base, fetch: bad.fetch });
  assert.equal(r2.record.ok, false);
  assert.equal(r2.record.error, "no_service");
  assert.doesNotMatch(JSON.stringify(r2.record), /XXXXXXXX/);

  const limited = mockFetch([{ status: 429, headers: { "retry-after": "2" } }, { status: 200, body: "ok" }]);
  const waits: number[] = [];
  const r3 = await sendSlack(SLACK_URL, { text: "t", blocks: [] }, { ...base, fetch: limited.fetch }, async (ms) => { waits.push(ms); });
  assert.deepEqual(waits, [2000]);
  assert.equal(limited.calls.length, 2);
  assert.equal(r3.record.ok, true);
});

test("slack: only Slack's documented webhook URL shape is accepted", () => {
  assert.equal(isSlackWebhookUrl(SLACK_URL), true);
  assert.equal(isSlackWebhookUrl("https://hooks.slack.com.evil.io/services/T/B/X"), false);
  assert.equal(isSlackWebhookUrl("http://hooks.slack.com/services/T/B/X"), false);
});

/* ---------------- webhooks ---------------- */

test("webhook: signed with HMAC-SHA256 over v1:timestamp:body, verified in constant time, replays rejected", async () => {
  const m = mockFetch([{ status: 204 }]);
  const now = 1_800_000_000;
  const r = await sendWebhook({ name: "ops", url: "https://hooks.example.com/crenel" }, HOOK_SECRET, "finding.proven", { project: "acme", run: "r-1" }, { finding: { id: "x" } },
    { allowedHosts: ["hooks.example.com"], scanHosts: [], fetch: m.fetch }, now);
  assert.equal(r.record.ok, true);
  const { headers, body } = m.calls[0]!;
  assert.equal(headers["x-crenel-event"], "finding.proven");
  assert.equal(headers["x-crenel-timestamp"], String(now));
  assert.match(headers["x-crenel-signature"]!, /^sha256=[0-9a-f]{64}$/);
  assert.equal(headers["x-crenel-signature"], signCrenel(HOOK_SECRET, now, body));
  assert.ok(verifyCrenelSignature(HOOK_SECRET, headers, body, now + 10));
  assert.equal(verifyCrenelSignature(HOOK_SECRET, headers, body.replace("acme", "acmf"), now), false, "tampered body");
  assert.equal(verifyCrenelSignature("another-secret-another-secret-12345", headers, body, now), false, "wrong secret");
  assert.equal(verifyCrenelSignature(HOOK_SECRET, headers, body, now + 301), false, "replayed after 5 minutes");
  assert.equal(JSON.parse(body).delivery, headers["x-crenel-delivery"]);
  assert.doesNotMatch(JSON.stringify(r.record), /s3cr3t/);
});

/* ---------------- notify ---------------- */

test("notify: only new proven findings at the threshold, marked once delivered, leads never sent", async () => {
  const dir = tmp();
  new SecretStore(dir, {}).set("slack.webhookUrl", SLACK_URL);
  new SecretStore(dir, {}).set("webhooks.ops.secret", HOOK_SECRET);
  const cfg = config({
    allowedHosts: ["hooks.slack.com", "hooks.example.com"],
    slack: { enabled: true },
    webhooks: [{ name: "ops", url: "https://hooks.example.com/crenel", events: ["finding.proven", "run.completed"], minSeverity: "medium" }],
  });
  const findings = [
    f({ id: "crit" }), f({ id: "high", severity: "high" }), f({ id: "med", severity: "medium" }),
    f({ id: "lead", state: "unproven", severity: "critical" }),
  ];
  const m = mockFetch([{ status: 200, body: "ok" }]);
  const first = await notify({ config: cfg, stateDir: dir, findings, run: "r-1", fetch: m.fetch, env: {} });
  const slack = m.calls.filter((c) => c.url.startsWith("https://hooks.slack.com"));
  assert.equal(slack.length, 1);
  assert.match(slack[0]!.body, /2 new proven findings/);
  assert.equal(JSON.parse(slack[0]!.body).text, "Crenel: 2 new proven findings (1 critical, 1 high) on acme");
  assert.doesNotMatch(slack[0]!.body, /"med"|lead/);
  const hooks = m.calls.filter((c) => c.url.startsWith("https://hooks.example.com"));
  assert.deepEqual(hooks.map((c) => c.headers["x-crenel-event"]), ["finding.proven", "finding.proven", "finding.proven", "run.completed"]);
  assert.ok(hooks.every((c) => !c.body.includes('"lead"')));
  assert.equal(first.records.length, 5);
  assert.ok(first.records.every((r) => r.kind === "integration" && r.ok && r.run === "r-1"));
  assert.doesNotMatch(JSON.stringify(first.records), /XXXXXXXX|s3cr3t/);

  // Second run, same findings: nothing new, only run.completed.
  const m2 = mockFetch([{ status: 200, body: "ok" }]);
  await notify({ config: cfg, stateDir: dir, findings, run: "r-2", fetch: m2.fetch, env: {} });
  assert.deepEqual(m2.calls.map((c) => c.headers["x-crenel-event"] ?? "slack"), ["run.completed"]);
  assert.deepEqual(JSON.parse(m2.calls[0]!.body).newProven, []);
});

test("notify: a failed delivery stays pending and is retried on the next run", async () => {
  const dir = tmp();
  new SecretStore(dir, {}).set("slack.webhookUrl", SLACK_URL);
  const cfg = config({ allowedHosts: ["hooks.slack.com"], slack: { enabled: true } });
  const down = mockFetch([{ status: 500, body: "" }]);
  const r = await notify({ config: cfg, stateDir: dir, findings: [f()], fetch: down.fetch, env: {} });
  assert.equal(r.records[0]!.ok, false);
  const up = mockFetch([{ status: 200, body: "ok" }]);
  await notify({ config: cfg, stateDir: dir, findings: [f()], fetch: up.fetch, env: {} });
  assert.equal(up.calls.length, 1);
});

test("notify: a destination missing from the integrations allowlist is refused and journaled, nothing sent", async () => {
  const dir = tmp();
  new SecretStore(dir, {}).set("slack.webhookUrl", SLACK_URL);
  const m = mockFetch();
  const r = await notify({ config: config({ allowedHosts: [], slack: { enabled: true } }), stateDir: dir, findings: [f()], fetch: m.fetch, env: {} });
  assert.equal(m.calls.length, 0);
  assert.match(r.records[0]!.error ?? "", /not in options.integrations.allowedHosts/);
});

test("notify: nothing configured, nothing sent; a missing secret is reported, not guessed", async () => {
  const dir = tmp();
  const m = mockFetch();
  assert.deepEqual(await notify({ config: config({}), stateDir: dir, findings: [f()], fetch: m.fetch, env: {} }), { records: [], skipped: [] });
  const r = await notify({ config: config({ allowedHosts: ["hooks.example.com"], webhooks: [{ name: "ops", url: "https://hooks.example.com/x" }] }), stateDir: dir, findings: [f()], fetch: m.fetch, env: {} });
  assert.equal(m.calls.length, 0);
  assert.match(r.skipped[0]!, /CRENEL_WEBHOOK_SECRET_OPS/);
});

/* ---------------- CLI ---------------- */

test("cli: set-secret from stdin, test journals host and status only, status shows no secret", async () => {
  const dir = tmp();
  const configPath = join(dir, "crenel.config.yaml");
  writeFileSync(configPath, "project: acme\n");
  const cfg = config({ allowedHosts: ["hooks.slack.com"], slack: { enabled: true } });
  const out: string[] = [];
  const io = { config: cfg, configPath, out: (s: string) => out.push(s), err: (s: string) => out.push(s), env: {} };
  assert.equal(await integrationsCommand({ ...io, sub: "set-secret", arg: "slack", stdin: async () => "https://example.com/not-slack" }), 2);
  assert.equal(await integrationsCommand({ ...io, sub: "set-secret", arg: "slack", stdin: async () => SLACK_URL + "\n" }), 0);
  const m = mockFetch([{ status: 200, body: "ok" }]);
  assert.equal(await integrationsCommand({ ...io, sub: "test", arg: "slack", fetch: m.fetch }), 0);
  assert.equal(m.calls[0]!.url, SLACK_URL);
  const audit = readFileSync(join(dir, ".crenel", "audit.jsonl"), "utf8");
  assert.match(audit, /"kind":"integration","integration":"slack","event":"test","host":"hooks.slack.com","ms":\d+,"ok":true,"status":200}/);
  assert.doesNotMatch(audit + out.join(""), /XXXXXXXX|T0000000/);
  const st = integrationsStatus(cfg, join(dir, ".crenel"), {});
  assert.equal(st.slack.configured, true);
  assert.equal(st.slack.destination, "https://hooks.slack.com/…");
  assert.doesNotMatch(JSON.stringify(st), /XXXXXXXX/);
});

/* ---------------- language ---------------- */


test("locale: explicit wins, auto reads CRENEL_LOCALE then the POSIX locale (C means English), then English", () => {
  assert.equal(resolveLocale("fr", {}), "fr");
  assert.equal(resolveLocale("de", {}), "en", "unknown language falls back to English");
  assert.equal(resolveLocale("auto", { CRENEL_LOCALE: "fr" }), "fr");
  assert.equal(resolveLocale("auto", { LANG: "fr_FR.UTF-8" }, () => "en-US"), "fr");
  assert.equal(resolveLocale("auto", { LC_ALL: "C.UTF-8", LANG: "fr_FR.UTF-8" }, () => "fr-FR"), "en", "LC_ALL wins, even C");
  assert.equal(resolveLocale(undefined, {}, () => "fr-CA"), "fr");
  assert.equal(resolveLocale("auto", {}, () => undefined), "en");
  assert.equal(localeFromTag("POSIX"), null);
});

test("every language has every message (no missing key falls back silently)", () => {
  const keys = (o: object) => Object.keys(o).sort();
  for (const l of LOCALES) {
    assert.deepEqual(keys(msgs(l)), keys(msgs("en")), l);
    assert.deepEqual(keys(msgs(l).severity), keys(msgs("en").severity), l);
  }
});

test("Slack and webhooks speak the configured language; machine fields stay English", async () => {
  const fr = slackFindingsMessage([f(), f({ id: "h", severity: "high" })], { project: "acme", locale: "fr" });
  assert.equal(fr.text, "Crenel : 2 nouvelles failles prouvées (1 critique, 1 haute) sur acme");
  assert.match(JSON.stringify(fr.blocks), /\*Sévérité\*\\nCritique/);
  const dir = tmp();
  new SecretStore(dir, {}).set("webhooks.ops.secret", HOOK_SECRET);
  const m = mockFetch([{ status: 204 }]);
  await notify({ config: config({ locale: "fr", allowedHosts: ["hooks.example.com"], webhooks: [{ name: "ops", url: "https://hooks.example.com/x" }] }), stateDir: dir, findings: [f()], fetch: m.fetch, env: {} });
  const [finding, run] = m.calls.map((c) => JSON.parse(c.body));
  assert.equal(finding.locale, "fr");
  assert.equal(finding.summary, "Nouvelle faille prouvée (critique) sur acme : Stripe secret key (live)");
  assert.equal(finding.finding.severity, "critical");
  assert.equal(run.summary, "Tâche Crenel terminée sur acme : 1 prouvée (1 nouvelle), 0 piste.");
});
