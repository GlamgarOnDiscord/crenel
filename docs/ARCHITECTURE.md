# Architecture

Crenel is two parts in one repo: a small, auditable engine, and a web console.

```
src/            the engine (CLI + library)
  core/         scope, config, net, runner, registry, baseline, audit, types
  checks/       one file per check (deterministic, read-only)
  agent/        experimental LLM triage via the local Claude CLI
  report/       text, JSON, SARIF
  generate/     regression tests from findings
web/            the Crenel console (Vite + React + react-router + lucide)
examples/       a deliberately vulnerable app the demo scans
docs/           identity, design notes, this file
```

## The engine

A run turns a **config** into a list of **findings**. The pieces:

- **Scope** (`core/scope.ts`) is the safety core. Checks never reach the network
  directly; the allowlist, the active-testing gate and the "no destructive
  action" rule live in code, not in a prompt. This is deliberate: research shows
  agents drift out of a scope that is only an instruction.
- **Scoped HTTP client** (`core/net.ts`) is the only way out. It enforces the
  allowlist, refuses hosts that resolve to private/loopback addresses (SSRF and
  DNS-rebinding), re-validates every redirect hop, and caps the body.
- **Checks** (`core/types.ts` `Check`) are deterministic and read-only. Each
  returns findings that are either `proven` (a deterministic match or a
  replayable probe) or `unproven` (a lead). The registry (`core/registry.ts`)
  lists them explicitly, so a build never runs an unreviewed check.
- **Runner** (`core/runner.ts`) builds the scope, runs each check in isolation
  (one failing check never sinks the run), and returns the result.
- **Baseline** (`core/baseline.ts`) diffs a run against a saved snapshot:
  new / fixed / persisting. A new proven high or critical is a regression and
  fails CI; known leads do not.
- **Audit** (`core/audit.ts`) appends one JSON line per run: a durable,
  greppable record of what ran and what it saw.

## Proof discipline

A finding is only `proven` by a deterministic check or a replayable probe. The
LLM triage (`agent/triage.ts`) can advise on a lead but can never set `proven`.
This is the core rule behind every design choice: the tool is trustworthy
because its verdicts do not come from a model.

## From finding to "stays fixed"

`generate/tests.ts` turns each finding into a regression test. Once that test is
in CI, the issue cannot come back without breaking the build. That loop, proof to
regression, is the product.

## The console

`web/` is a static SPA. It renders the same model the engine produces
(findings, severity, state, proof) with a design system in `web/src/styles`.
The agent page mirrors a Claude-Code-style run; in production the console talks
to a backend, in this repo it renders scripted mock data.

## Adding a check

Create `src/checks/<name>.ts` exporting a `Check`, add it to the registry, add a
unit test, and (if it needs the network) route every request through
`safeFetch`. Keep it deterministic; prefer a `proven` finding with a `replay`
string over a guess.
