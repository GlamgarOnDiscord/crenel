# Integrations

Crenel sends only **proven** findings out, never leads. Everything runs on your machine or in your own CI: there is no Crenel server, no account, nothing to pay. Each integration below follows the provider's official documentation, cited where it applies.

| Integration | Where it runs | What it sends | Secret |
|---|---|---|---|
| GitHub code scanning | your workflow (`action.yml`) | SARIF 2.1.0, proven findings as alerts, leads as notes | the workflow's `GITHUB_TOKEN` (used by GitHub's own `upload-sarif`) |
| GitHub PR comment | your workflow, `pr-comment: "true"` | one comment per PR, edited on each push | `GITHUB_TOKEN`, `pull-requests: write` |
| Slack | `crenel serve` runs, `crenel scan --notify` | one Block Kit message per run: new proven critical/high findings | Incoming Webhook URL |
| Webhooks | `crenel serve` runs, `crenel scan --notify` | one signed JSON POST per new proven finding, one per finished run | HMAC-SHA256 signing secret |

## Destinations are not targets

Notifications are not probes. They go only to hosts you list in `options.integrations.allowedHosts`, a list separate from `scope.allowedHosts`:

- a host that is also a scan target is refused as a destination (and the console refuses to add it);
- `https://` only (plain `http://` only to `localhost`, `127.0.0.1` or `[::1]`, for a local receiver);
- no credentials in the URL, redirects are never followed (a `3xx` is a failed delivery), 10 s timeout;
- every attempt, sent or refused, is journaled: in the run's journal (`.crenel/runs/<id>.jsonl`, event `integration`) for console runs, and in `.crenel/audit.jsonl` always. A record holds the destination host, the event, the HTTP status and a short error (Slack's error code, for instance), never the URL path, the body or a secret.

```yaml
options:
  integrations:
    allowedHosts: [hooks.slack.com, hooks.example.com]
    slack:
      enabled: true
      minSeverity: high          # critical | high
      # webhookUrlEnv: CRENEL_SLACK_WEBHOOK_URL   (default)
    webhooks:
      - name: ops
        url: https://hooks.example.com/crenel
        events: [finding.proven, run.completed]
        minSeverity: low
        # secretEnv: CRENEL_WEBHOOK_SECRET_OPS     (default: CRENEL_WEBHOOK_SECRET_<NAME>)
```

## Secrets

A secret is read from its environment variable first, else from `.crenel/secrets.json`:

- the file is written with mode `0600` through a temp file and a rename; Crenel refuses to read it when group or others can (`chmod 600` fixes it). On Windows the mode bits do not exist: the file relies on your profile's ACLs;
- Crenel writes `.crenel/.gitignore` listing `secrets.json`, so it stays out of git even if your own `.gitignore` does not list `.crenel/`;
- set it from the console (Integrations page), or `crenel integrations set-secret slack` / `set-secret webhook:<name>` with the value on **stdin** (never on the command line, it would land in your shell history);
- a secret never appears in the config, the journal, the audit log, an API response or the terminal. The console shows `https://hooks.slack.com/…` and where the secret comes from (environment or file). A new webhook's generated secret is returned once, when you create it.

## GitHub code scanning (SARIF)

Reference: [SARIF support for code scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning), [upload-sarif inputs](https://github.com/github/codeql-action/blob/main/upload-sarif/action.yml).

The Action runs `crenel scan --sarif` and uploads with `github/codeql-action/upload-sarif`, pinned by commit SHA (v4.39.3), `category: crenel`. The job needs `security-events: write`. What Crenel's SARIF does to match GitHub's page:

- each rule has `id`, `shortDescription`, `fullDescription` (both at most 1,024 characters), `help.text` and `help.markdown`, `defaultConfiguration.level`, `properties.tags`, `properties.precision`;
- a proven result's rule carries `properties.security-severity` (critical 9.5, high 8.0, medium 5.5, low 2.0), which GitHub uses to rank the alert. A lead goes under its own rule `<check>/lead`, level `note`, with no security severity: it never shows as a critical alert. When a lead becomes proven it moves to the proven rule (a new alert, on purpose);
- every result has one location, a path relative to the repository root, and a `region.startLine`. GitHub rejects a file that mixes URI schemes and only shows results located in repository files, so a finding about a URL, a host, a config option or a directory is anchored to the config file, line 1, and keeps its real location in the message and in `properties.location`. Columns are not reported: Crenel does not know them;
- `partialFingerprints.primaryLocationLineHash` (the only key GitHub reads) is derived from the finding's stable id, so an alert keeps its identity between runs even when several findings share the config-file anchor;
- fixed findings are left out: their absence closes the alert;
- the documented limits are enforced: at most 25,000 results and 25,000 rules per run, 20 tags per rule, and 10 MB gzipped for the file (over it, leads are dropped first, then the lowest severities, and the run says so in `toolExecutionNotifications`);
- `executionSuccessful` is false when a check failed, so a partial run is not read as a clean one.

### Checked before upload

`src/report/sarif-validate.ts` checks a SARIF file against the official [OASIS SARIF 2.1.0 JSON schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json) (vendored in `src/report/schemas/`) and against every requirement and limit of GitHub's page listed above (required rule fields, one location with a repository-relative uri and a start line, a single uri scheme, `primaryLocationLineHash`, counts, 10 MB gzipped). The test suite runs it on a real scan of the bundled example, and the `security` workflow runs it on the file it is about to upload:

```bash
npx tsx scripts/validate-sarif.ts crenel.sarif
```

### Where code scanning is available

Code scanning accepts uploads on public repositories, and on private ones only with GitHub Code Security. Crenel's own repository is private without it, so its `security` workflow validates the SARIF, keeps it as the `crenel-sarif` workflow artifact, and lets the upload step fail (`continue-on-error`) instead of the job. The job also grants `actions: read`, which `upload-sarif` needs on a private repository to read its workflow run. **The real upload to code scanning is therefore verified only once the repository is public or has Code Security.** To check it then, after a `security` run:

```bash
gh api repos/GlamgarOnDiscord/crenel/code-scanning/analyses --jq '.[] | select(.tool.name == "Crenel") | {created_at, category, results_count, rules_count, warning}'
gh api 'repos/GlamgarOnDiscord/crenel/code-scanning/alerts?tool_name=Crenel&per_page=5' --jq '.[] | {rule: .rule.id, severity: .rule.security_severity_level, path: .most_recent_instance.location.path}'
```

Until then the same API answers `403 Code scanning is not enabled for this repository`.

`upload-sarif` also recomputes `primaryLocationLineHash` from the file contents and warns ("found existing inconsistent fingerprint value") where it differs from Crenel's id-based value; it keeps Crenel's value, which is the point: findings anchored to the same config line keep separate identities.

## GitHub pull request comment

References: [REST issue comments](https://docs.github.com/en/rest/issues/comments) (a pull request is an issue for comments), [permissions for these endpoints](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens), [`permissions` in workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax), [GITHUB_TOKEN least privilege](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication).

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write
steps:
  - uses: actions/checkout@<sha>
  - uses: GlamgarOnDiscord/crenel@<sha>
    with:
      config: crenel.config.yaml
      pr-comment: "true"
```

On `pull_request` events, `crenel github-comment --report crenel.json` lists the proven findings (severity, check, title, location; never a proof's replay or evidence) and counts the leads. It finds its earlier comment (a bot comment starting with `<!-- crenel:pr-summary -->`) with `GET /repos/{owner}/{repo}/issues/{n}/comments` and edits it (`PATCH /repos/{owner}/{repo}/issues/comments/{id}`), or creates one (`POST /repos/{owner}/{repo}/issues/{n}/comments`), with `Accept: application/vnd.github+json` and `X-GitHub-Api-Version: 2026-03-10`. `pull-requests: write` covers the three calls. No proven finding and no earlier comment: nothing is posted.

On a pull request from a fork the token is read-only, so the comment is skipped with a warning annotation and the job does not fail. Crenel never needs `pull_request_target`. The API host is the runner's `GITHUB_API_URL` (https only). Calls are journaled in `.crenel/audit.jsonl` next to the config.

## Slack

References: [Sending messages using incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/), [Block Kit blocks](https://docs.slack.dev/reference/block-kit/blocks/), [header block](https://docs.slack.dev/reference/block-kit/blocks/header-block/), [section block](https://docs.slack.dev/reference/block-kit/blocks/section-block/), [formatting text](https://docs.slack.dev/messaging/formatting-message-text/), [rate limits](https://docs.slack.dev/apis/web-api/rate-limits/).

1. Create a Slack app, turn on Incoming Webhooks, add one to a channel, copy its URL (`https://hooks.slack.com/services/…`). Slack's page warns the URL contains a secret.
2. Paste it on the console's Integrations page, or `echo "$URL" | crenel integrations set-secret slack`, or export `CRENEL_SLACK_WEBHOOK_URL`.
3. *Tester* (or `crenel integrations test slack`) sends a test message.

After a run, Crenel posts one message listing the **new** proven findings at or above `minSeverity` (critical or high): a `header` block, one `section` per finding (title, fix, and fields for severity, check, location), at most 10 findings then "…and N more", and a `context` line. The top-level `text` is the notification fallback (mobile notifications use only it). Limits respected: at most 50 blocks, header text 150 characters, section text 3,000, at most 10 fields of 2,000. `&`, `<`, `>` are escaped as the formatting page asks. Success is HTTP 200 with the body `ok`; anything else is journaled with Slack's error code (`invalid_payload`, `no_service`, …). Incoming webhooks allow about one message per second: Crenel sends one per run, and on a `429` waits `Retry-After` once (at most 30 s).

"New" is per destination: `.crenel/integrations.json` keeps the finding ids each destination received, and an id is recorded only after a successful delivery, so a failed one is retried after the next run. In console runs, a finding that is fixed and then proven again is sent again.

## Webhooks

The signing scheme follows GitHub's [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries) (a `sha256=` prefixed hex HMAC, a high-entropy secret, a constant-time comparison) and Slack's [Verifying requests from Slack](https://docs.slack.dev/authentication/verifying-requests-from-slack) (the timestamp is part of the signed string, and a request more than five minutes old is rejected).

Each delivery is `POST` with `Content-Type: application/json` and:

| Header | Value |
|---|---|
| `X-Crenel-Event` | `finding.proven`, `run.completed` or `test` |
| `X-Crenel-Delivery` | random id, also in the body as `delivery` |
| `X-Crenel-Timestamp` | Unix seconds at signing time |
| `X-Crenel-Signature` | `sha256=` + hex HMAC-SHA256 of `v1:<timestamp>:<raw body>` with your secret |

Bodies:

```json
{ "event": "finding.proven", "delivery": "…", "sentAt": "…", "project": "acme", "run": "r-…",
  "finding": { "id": "…", "check": "exposed-secrets", "title": "…", "severity": "critical", "state": "proven",
               "location": "dist/app.js:3", "description": "…", "remediation": "…", "proofMethod": "…" } }
{ "event": "run.completed", "delivery": "…", "sentAt": "…", "project": "acme", "run": "r-…",
  "proven": 6, "leads": 21, "fixed": 0, "newProven": ["…"] }
```

The proof's replay command and evidence are never sent (they can carry a token). At most 50 `finding.proven` deliveries per run per webhook; the rest stay pending for the next run. A `2xx` is a success.

Verification on the receiver (Node.js; compute the HMAC over the **raw** body, before any JSON parsing):

```js
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyCrenel(secret, headers, rawBody, now = Math.floor(Date.now() / 1000)) {
  const ts = Number(headers["x-crenel-timestamp"]);
  if (!Number.isInteger(ts) || Math.abs(now - ts) > 300) return false; // replay window: 5 minutes
  const expected = Buffer.from("sha256=" + createHmac("sha256", secret).update(`v1:${ts}:${rawBody}`).digest("hex"));
  const given = Buffer.from(String(headers["x-crenel-signature"] ?? ""));
  return expected.length === given.length && timingSafeEqual(expected, given);
}
```

Store `X-Crenel-Delivery` ids for five minutes as well if you need to drop a duplicate inside the window. The same function ships as `verifyCrenelSignature` in `src/integrations/webhook.ts`.

## Commands

```bash
crenel scan --notify                                # after the scan, send new proven findings
crenel integrations status [--json]                 # destinations, where each secret comes from
crenel integrations test slack | webhook:<name>     # a test message, journaled
crenel integrations set-secret slack | webhook:<name>   # value on stdin, saved 0600
crenel github-comment --report crenel.json          # in a GitHub Action, see above
```

Console API (`crenel serve`, token-protected like the rest): `GET /api/integrations`, `PUT|DELETE /api/integrations/slack`, `POST /api/integrations/webhooks`, `DELETE /api/integrations/webhooks/:name`, `POST /api/integrations/slack/test`, `POST /api/integrations/webhooks/:name/test`.

## Not included

- **Jira, Linear, other trackers**: no free, local-first way to open tickets without an account and a token per tool; a signed webhook can feed your own automation instead.
- **Slack apps with OAuth** (`chat.postMessage`, threads, editing a message): they need a bot token and scopes; Incoming Webhooks are enough to post.
- **GitHub checks API / annotations**: code scanning already annotates the diff from the SARIF, with nothing more to grant.
