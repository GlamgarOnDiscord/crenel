# Usage

## Commands

| Command | |
| --- | --- |
| `crenel scan` | Run the checks. `--json`, `--out`, `--sarif` (SARIF 2.1.0), `--junit` (JUnit XML), `--fail-on critical\|high\|medium\|low` (default `high`, proven findings only), `--audit` (JSONL), `--baseline`, `--update-baseline`, `--notify` (send new proven findings to Slack and webhooks, [`INTEGRATIONS.md`](INTEGRATIONS.md)), `--verbose`. |
| `crenel serve` | The web console and its local API. `--config`, `--port` (4100), `--open`, `--llm` (opt-in: use the local `claude -p`, which spends your subscription). See [CONSOLE.md](CONSOLE.md). |
| `crenel generate-tests` | One regression test per finding. |
| `crenel triage` | Experimental: ask the local Claude CLI for advice on leads. Advice only, never proof. |
| `crenel list` · `crenel init` | List checks · write a starter config. |

Every output keeps the two kinds apart: **proven** findings (a validator replayed the proof) and **leads** (no proof, so no report and no failed build). The `replay` commands in reports are written in POSIX shell syntax (`curl`, `grep`); Crenel itself never runs them, and runs natively on Windows, macOS and Linux.

As a GitHub Action, `uses: <owner>/crenel@<sha>` with `config` and `fail-on` (see [`action.yml`](action.yml)) scans, uploads SARIF to code scanning and fails only on a proven finding; `pr-comment: "true"` also keeps one PR comment of the proven findings ([`INTEGRATIONS.md`](INTEGRATIONS.md)).

## Configuration

```yaml
project: my-saas
projectDir: ./dist            # what gets scanned for secrets
scope:
  allowedHosts: [staging.example.com]
  allowActiveTesting: false   # must be true for live authz probes
  stagingUrl: https://staging.example.com
checks: []                    # empty = every read-only check
options:
  authz-matrix:
    resources:
      - { name: project, path: /api/projects/:id, methods: [GET] }
    accounts:
      a: { token: "<staging token for account A>" }
      b: { owns: { project: ["<id owned by B>"] } }
```

Older setups with `bastion.config.yaml` still work.

### Pacing and request budget

`scope.ratePerSec` paces every live request of a run (e.g. `2` for two per second) and `scope.maxRequests` refuses any request past the cap (refusals are journaled like any other scope refusal). Both apply to every check that goes through Crenel's scoped client; the toolbox has its own `options.toolbox.ratePerSec` and `maxRequests`.

### Hosts behind Cloudflare Access

A host protected by [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) answers an anonymous request with its login flow, not with your app: a `302` to `<team>.cloudflareaccess.com/cdn-cgi/access/login/<host>`, a `WWW-Authenticate: Cloudflare-Access` header, a `CF_AppSession` cookie, or a `401`/`403` Access page. Crenel recognises each of these in its scoped client. A live check that gets one treats the host as **not reached**: never a pass, never a fail of the app (no "missing CSP" about Cloudflare's redirect, no "open redirect" to your Access team domain). When the whole host is gated, nothing more is sent to it after the first answer. The run reports **one info lead per host**: `<host> protected by Cloudflare Access: live checks see only the login page; provide a service token`.

To scan through Access, use a [service token](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/): create one in Zero Trust (Access, Service credentials), add a policy with the **Service Auth** action for it on the application, then name the two environment variables that hold it:

```yaml
scope:
  allowedHosts: [app.example.com, staging.example.com]
  stagingUrl: https://staging.example.com
  access:
    staging.example.com:
      clientIdEnv: CRENEL_CF_ACCESS_ID         # holds the Client ID (….access)
      clientSecretEnv: CRENEL_CF_ACCESS_SECRET # holds the Client Secret
```

Crenel then sends Cloudflare's documented headers `CF-Access-Client-Id` and `CF-Access-Client-Secret` (the same as `curl -H "CF-Access-Client-Id: <CLIENT_ID>" -H "CF-Access-Client-Secret: <CLIENT_SECRET>" https://app.example.com` in Cloudflare's docs). The rules:

- The values come **only from the environment**. The config takes variable names (upper case, validated), so a Client ID or secret pasted in the file fails validation instead of being used. A host in `access` must be in `allowedHosts`.
- The headers go **only to the exact host** they are declared for, **only over https**, recomputed on every redirect hop: a redirect to another host, even a declared one, or a plain `http://` request carries nothing.
- Both values are registered for redaction: a response that echoes them is masked (`first 4 characters…[redacted]`) in findings, the console, JSON, SARIF and the run journal. Request headers are never journaled.
- An unset variable sends nothing and the lead says which variable is missing; a token Access rejects gives the lead `service token rejected`.
- The toolbox (nuclei, katana, httpx) goes through the egress proxy, which cannot add headers inside TLS: it does not carry the token, and a gated host stays out of its reach.

Cloudflare's single-header variant (a token in one custom header such as `Authorization`, configured on the application) is not supported yet.
