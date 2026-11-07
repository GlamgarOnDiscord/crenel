# Web console

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
