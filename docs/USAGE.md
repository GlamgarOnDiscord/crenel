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
