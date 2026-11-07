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
| `crenel scan` | Run the checks. `--json`, `--out`, `--sarif` (SARIF 2.1.0), `--audit` (JSONL), `--baseline`, `--update-baseline`, `--verbose`. |
| `crenel generate-tests` | One regression test per finding. |
| `crenel triage` | Experimental: ask the local Claude CLI for advice on leads. Advice only, never proof. |
| `crenel list` · `crenel init` | List checks · write a starter config. |

## Web console

A React app in [`web/`](web/) renders the same model as the CLI: a Codex-style launch screen, an agent run you can follow step by step, findings with their proof, the authorization matrix and the generated tests. It is being redesigned. Run it with `cd web && pnpm install && pnpm dev`.

## Brand

Mascot, logo, typography and usage rules live in [`brand/`](brand/).

## Roadmap

- Compare the two tenants' response bodies in `authz-matrix`, so a `200` that returns someone else's data is itself proof.
- An age and publisher signal in `dependency-risk` against slopsquatting and maintainer takeovers.
- Liveness checks and rotation paths for found secrets.
- Repo-relative finding paths, so generated tests resolve from the repo root.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Engine: `pnpm test` (107 tests). Console: `cd web && pnpm test`.

## License

MIT. See [LICENSE](LICENSE).
