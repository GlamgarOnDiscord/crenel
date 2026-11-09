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

## Free exploration

Beyond the deterministic checks, `crenel explore` (or an agent run with `explore:
assist|full` in the config) lets a model choose its own requests and reads inside
the declared perimeter. The model only **claims**: it submits a `claim.submit` with
a class and a `detail`, and a validator in `agent/validators.ts` replays it. Any
`state` or `proven` the model writes is ignored; at most 12 claims per exploration.
Budgets (`maxCalls`, `maxRequests`, `maxTokens`, `maxMs`, `maxToolRuns`) live in
`options.explore`.

Every finding is proven by a **generic oracle**, never a target-specific
signature: a differential, a reflection, a computation, an out-of-band callback,
real execution or a file signature. Each oracle also has guards against false
positives: a parameter the server ignores gives no differential, no reflection and
no callback, so it is never proven (at best a lead, which never gates CI).

| Claim class | What it proves | Oracle |
|---|---|---|
| `explore.injection` | SQL injection (boolean and error), reflected XSS, template/expression injection, OS command injection, NoSQL operator injection ($ne/$eq) in one parameter. REST query or form body, JSON-body operators, or GraphQL with `__INJECT__` inside a string argument | differential (TRUE matches the baseline, FALSE diverges, or a database/parse error), reflection (unescaped markup only), computation (`7*7` returned as `49` next to a nonce) |
| `explore.ssrf` | The server fetches a URL taken from a parameter (REST or GraphQL) | out-of-band: Crenel starts a listener and injects a callback URL with a nonce; a hit proves it |
| `explore.stored-xss` | Markup sent through a store request is served unescaped by another request | reflection, on the retrieve response |
| `explore.dom-xss` | The page's own script runs the injected payload | real execution in headless Chromium: `alert(nonce)` must fire |
| `explore.lfi` | Path traversal reading a system file | file signature (`/etc/passwd` or `win.ini` content) over several traversal encodings |
| `explore.jwt-none` | A forged unsigned `alg:none` token is accepted | differential: accepted where the anonymous request is denied |
| `explore.mass-assignment` | A body field the client should not set is accepted and persisted | differential: the actor's own re-read shows the injected value; a control update without the field leaves it unchanged (active mode) |
| `explore.cors` | CORS reflects any origin with credentials | differential: two distinct attacker origins are both reflected into `Access-Control-Allow-Origin` with `Allow-Credentials: true` (a wildcard is only a lead) |
| `explore.reuse` | A single-use artifact (coupon, credit, invite) applied more than once | differential: the same application succeeds twice while an invalid artifact is rejected (active mode) |
| `explore.redirect` | A parameter whose value becomes the redirect target (open redirect) | differential: two distinct unguessable sentinel hosts under `.invalid` are both reflected into the redirect (3xx `Location` or a meta-refresh), read without following; a route that always redirects to one fixed place, or an allowlist that permits only one guess, is never proven (read-only) |
| `explore.graphql` | GraphQL field suggestions enabled, or query batching with no rate limit | suggestions: a near-miss of common fields returns "Did you mean" (read-only); batching: a batch of N queries runs as N results (active mode) |
| `explore.jwt-forge` | JWT signature bypass: alg:none (+ case variants), RS256→HS256 algorithm confusion (server public key as HMAC secret), weak HMAC secret | a forged token is accepted while the same token with a corrupted signature is rejected (public keys fetched from the usual JWKS paths) |

The older classes (`explore.replay`, `explore.cross-actor`, `explore.secret`,
`explore.file-match`) replay a request, compare two actors, check a secret in a
response and match a line in a file.

Options for the classes above, under `options.explore`:

- `ssrfCallbackHost`: an address the **target** can reach back (default
  `127.0.0.1`, which only works when the target runs on the same host).
  `ssrfCallbackPort` fixes the callback port (default: an ephemeral one, which
  fits single-URL SSRF only).
- `domXssPlaywright` and `domXssBrowser`: path to Playwright's entry and to a
  Chromium executable. The environment variables `CRENEL_PLAYWRIGHT` and
  `CRENEL_BROWSER` work too.

**The browser is an optional dependency.** Playwright is imported dynamically.
Without it, `explore.dom-xss` stays a lead ("no browser") and everything else
works. A DOM-XSS claim takes `{url, param}` (payload in the query, or in the
fragment of an SPA hash route) or a `url` containing `__INJECT__`, for sinks in a
hash or path (e.g. `http://app/#/search?q=__INJECT__`).

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
