<p align="center"><img src="brand/readme-banner.png" alt="Crenel" width="800"></p>

<p align="center"><b>Attack your own app before anyone else does.</b><br>
Crenel finds exposed secrets and cross-account authorization bugs, proves each one with a replayable request, then turns it into a regression test so it never comes back.</p>

<p align="center">Free · local · no account · open source (MIT)</p>

<p align="center"><img src="brand/cli-output.png" alt="crenel scan output" width="760"></p>

## Why

New SaaS apps, especially the ones built fast with AI, keep shipping the same few bugs: a server secret in the client bundle, and one account able to read another account's data. Crenel looks for exactly those, separates what is **proven** from what is only a **lead**, and gives you a test that keeps the fix in place.

- **Proof over noise.** Every finding is either `proven` (a deterministic match or a replayable request) or a `lead`. Only proven high and critical findings fail CI, so you can gate a pipeline on it without flaky alarms.
- **Deterministic where it counts.** LLMs are near-blind to authorization bugs spread across files. Crenel's authorization check is a declarative matrix you can read, run and keep in CI.
- **Scope lives in code, not in a prompt.** Crenel only touches hosts you declare you own. Active probes are off by default and nothing destructive is ever sent.

## Quick start

Crenel is not published to npm yet. From a clone:

```bash
pnpm install
pnpm demo                     # scans the bundled, intentionally vulnerable example, offline
```

The demo exits non-zero on purpose: a proven high or critical finding is a CI gate, not a crash.

On your own project:

```bash
pnpm crenel init              # writes crenel.config.yaml
# point projectDir at your built bundle, list the hosts you own
pnpm crenel scan
pnpm crenel scan --sarif crenel.sarif --out crenel-report.json   # for CI and code scanning
```

## The 15 checks

| Check | Catches |
| --- | --- |
| `exposed-secrets` | Server keys and private keys in client code (Stripe, AWS, Google, OpenAI, Anthropic, GitHub, Slack, npm, SendGrid, Supabase `service_role` and `sb_secret_`, PEM). |
| `baas-exposure` | A Supabase or Firebase public key in the bundle: a lead to check RLS; with active testing on a declared host, proves which tables answer a one-row read without signing in. |
| `dependency-risk` | A locked package whose exact version is known malware (OSV denylist), plus install hooks and non-registry deps. |
| `authz-matrix` | One account reaching another account's objects. Generates the CI test; with a staging URL and two test accounts (opt-in), proves it live. |
| `public-env` | A secret behind a client-exposed prefix (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`…). |
| `committed-env` | A committed `.env` file. |
| `committed-credentials` | Committed `.npmrc`, `.pypirc`, `.netrc`, Docker or git credential files that carry a secret. |
| `sourcemaps` | Source maps shipped with the client bundle. |
| `jwt-config` | JWT setups that accept `alg: none` or verify with an empty secret. |
| `tls-verification` | Code that turns off TLS certificate checks. |
| `headers` | Missing security headers and weak cookie flags on your staging response. |
| `ci-hardening` | Risky GitHub Actions: `pull_request_target`, unpinned actions, installs without `--ignore-scripts`. |
| `dockerfile` | Root containers, unpinned base images, baked secrets, `curl \| sh`. |
| `mcp-surface` | Committed agent and MCP configs that run local commands or hold secrets. |
| `cloudflare-audit` | Normalises the findings of Cloudflare's security-audit skill into the same model. |

Details, examples and fixes for each: [`docs/CHECKS.md`](docs/CHECKS.md).

## Keep fixes fixed

```bash
pnpm crenel scan --update-baseline --baseline crenel-baseline.json   # record today
pnpm crenel scan --baseline crenel-baseline.json                     # in CI: new, fixed, persisting
pnpm crenel generate-tests --out crenel.regression.test.ts           # one test per finding
```

A new proven high or critical finding breaks the build; known, accepted leads do not.

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

## Safety

The scope guard (`src/core/scope.ts`) refuses any host outside `allowedHosts` and any active check you did not opt into. Every outbound request goes through a scoped client (`src/core/net.ts`) that also refuses private and loopback addresses, re-validates each redirect hop and caps response size. Only point Crenel at systems you own or are explicitly authorised to test. It is a hardening tool, not an attack tool. See [`SECURITY.md`](SECURITY.md).

## Commands

| Command | |
| --- | --- |
| `crenel scan` | Run the checks. `--json`, `--out`, `--sarif` (SARIF 2.1.0), `--junit` (JUnit XML), `--fail-on critical\|high\|medium\|low` (default `high`, proven findings only), `--audit` (JSONL), `--baseline`, `--update-baseline`, `--verbose`. |
| `crenel serve` | The web console and its local API. `--config`, `--port` (4100), `--open`, `--no-llm`. See below. |
| `crenel generate-tests` | One regression test per finding. |
| `crenel triage` | Experimental: ask the local Claude CLI for advice on leads. Advice only, never proof. |
| `crenel list` · `crenel init` | List checks · write a starter config. |

Every output keeps the two kinds apart: **proven** findings (a validator replayed the proof) and **leads** (no proof, so no report and no failed build). The `replay` commands in reports are written in POSIX shell syntax (`curl`, `grep`); Crenel itself never runs them, and runs natively on Windows, macOS and Linux.

As a GitHub Action, `uses: <owner>/crenel@<sha>` with `config` and `fail-on` (see [`action.yml`](action.yml)) scans, uploads SARIF to code scanning and fails only on a proven finding.

## Web console

```bash
pnpm build && (cd web && pnpm install && pnpm build)
node dist/cli.js serve --config crenel.config.yaml --open
```

`crenel serve` starts a local server on `127.0.0.1:4100` that serves the console from `web/dist` and a JSON API, and prints a link with a random token. Opening the link trades the token for an HttpOnly, SameSite=Strict cookie; the API refuses any call without it, any unexpected `Host` header (DNS rebinding) and any cross-origin write. `--host` can bind elsewhere, with a warning: the token is then the only lock.

What is real in the console:

- **Agent**: each task is a real run. A deterministic plan of tools (secrets, repo, dependencies, BaaS keys, staging headers, the authorization matrix, validation, tests) streams step by step over server-sent events.
- **Permissions**: *Demander avant chaque sonde* pauses before any request with *Autoriser une fois / Toujours pour cet hôte / Refuser*; *Lecture seule* sends nothing; *Bypass all permissions* never asks but keeps the perimeter (declared hosts, GET/HEAD/OPTIONS only, no private address unless `allowPrivate`, `allowActiveTesting` for crafted probes), and writes every request it sent to the audit log. *Interrompre* aborts the requests and model calls in flight.
- **Proof**: nothing is marked proven by the agent or a model. Every finding becomes a claim that a deterministic validator replays itself (authorization: the owner's own response, the attacker's, and a negative control on an id that does not exist; Supabase: a one-row read; headers: a re-read; offline checks: a fresh run). No validator for a class means it stays a lead.
- **Goals**: like `/goal`, pick an objective in the composer (no proven critical, isolation proven on every declared resource, every proven flaw has its regression test) or type `/goal <text>`. The agent loops until the objective holds (checked by code), a budget runs out (iterations, requests, time, tokens), nothing changes anymore (a fix is needed on your side), or you stop it. A free-text goal can only be judged by a model and is shown as *not verified*.
- **State** lives in `.crenel/` next to the config: one append-only, hash-chained JSONL journal per run (replayed after a restart), findings with their verdicts, the last authorization matrix, generated tests (`.crenel/regression.test.ts`, nothing is written in your project) and the audit log.
- **Model**: optional. When the `claude` CLI is installed, `claude -p` writes summaries and chat answers and may propose claims, from tool output fenced as untrusted data. Without it, everything above still works. Other models in the menu are not wired.

Still demo-only in the console: integrations (GitHub, CI, Slack), key liveness and revocation on the Secrets page, the "guarded in CI" status (Crenel cannot see your CI), the context-window gauge, and opening pull requests. Without `crenel serve` (static build, `pnpm dev`), the console shows the demo data.

Live demo against a deliberately vulnerable app on loopback:

```bash
node examples/vulnerable-app/server.mjs &
node dist/cli.js serve --config examples/crenel.live.config.yaml --open
```

## Brand

Mascot, logo, typography and usage rules live in [`brand/`](brand/).

## Roadmap

Not done yet, in rough order:

- **Authorization**: import routes from an OpenAPI file or the JS bundle to fill the matrix; replay ids leaked in responses (UUIDs, GraphQL global ids); an admin role with an expected "allow"; old and new objects per resource in generated tests. Action-level BOLA (update or delete someone else's object) stays off by default: later, only with declared test accounts, a throwaway object Crenel creates, and a separate opt-in.
- **Secrets**: liveness checks with a read-only provider call (e.g. Stripe `GET /v1/balance`), strictly opt-in with the provider host declared, giving active / revoked / unknown; rotation paths.
- **BaaS**: anonymous writes on Supabase (a separate opt-in, on a throwaway row Crenel creates), Firestore rules (needs a POST, never sent today).
- **New static checks**: unsigned webhook handlers (Stripe, GitHub, Clerk without `constructEvent` / verify / `timingSafeEqual`), simple SSRF (`fetch` or `axios` on a URL taken from the request without an allowlist).
- **Dependencies**: an age and publisher signal against slopsquatting and maintainer takeovers.
- **Agent harness** (research backlog P1+): repetition detector, context editing and file memory, plan/execute split with hypothesis forcing, multi-run voting as a precision filter, an eval harness with pass^k; a model judge wired into the gate (the interface exists, it can only harden).
- **Network containment outside the process**: an optional Docker "toolbox" image (nuclei, trufflehog) whose only network exit is Crenel's scoped proxy, usable on Windows through Docker Desktop. External tools stay out until then: they would bypass the scoped client.
- Repo-relative finding paths, so generated tests resolve from the repo root.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Engine: `pnpm test` (153 tests). Console: `cd web && pnpm test` (18 tests).

## License

MIT. See [LICENSE](LICENSE).
