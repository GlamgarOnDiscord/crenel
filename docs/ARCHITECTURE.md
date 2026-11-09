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
| `explore.injection` | SQL injection (boolean, error, and time-based blind with `timing:true`), reflected XSS, template/expression injection, OS command injection, NoSQL operator injection ($ne against $eq to a fresh nonce, or $in: [] in JSON) in one parameter, or a JSON `bodyTemplate` with `"__INJECT__"` at the field. REST query or form body, JSON-body operators, or GraphQL with `__INJECT__` inside a string argument | differential (TRUE matches the baseline, FALSE diverges, or a database/parse error), reflection (unescaped markup only), computation (`7*7` returned as `49` next to a nonce); time-based proves on a matched fast/slow sleep pair with clean separation (every slow sample above every fast one) |
| `explore.ssrf` | The server fetches a URL taken from a parameter (REST or GraphQL) | out-of-band: Crenel starts a listener and injects a callback URL with a nonce; a hit proves it |
| `explore.stored-xss` | Markup sent through a store request is served unescaped by another request | reflection, on the retrieve response |
| `explore.dom-xss` | The page's own script runs the injected payload | real execution in headless Chromium: `alert(nonce)` must fire |
| `explore.lfi` | Path traversal reading a system file | file signature (`/etc/passwd` or `win.ini` content) over several traversal encodings |
| `explore.jwt-none` | A forged unsigned `alg:none` token is accepted | differential: accepted where the anonymous request is denied |
| `explore.mass-assignment` | A body field is accepted and persisted by the update (whether the client should be able to set it is the model's reading) | differential on the actor's own object (its marker in the read, not what anonymous gets), writes only to the staging origin with POST/PUT/PATCH: the re-read shows the injected value, a control update without the field leaves it exactly unchanged; the field is restored afterwards. Create mode (`mode: "create"`): an object created with the field reads back the injected value while one created without it reads back the default (active mode) |
| `explore.cross-actor-write` | Account A deletes or changes an object of account B | the owner creates the object in the proof (it is B's by construction) and reads it; an anonymous write (control) leaves it unchanged; after A's DELETE the owner gets 404/410, or after A's PUT/PATCH the owner's re-read shows exactly A's value; an anonymous write that already succeeds is reported as worse; the owner deletes a leftover test object (active mode) |
| `explore.user-enum` | A login or sign-up endpoint reveals whether an account exists | the request is sent with a known username and with two fresh non-existing ones; the two non-existing answers must be identical (control) and the existing one must differ in a stable way (status or a body phrase, after the submitted username is stripped). A POST login is an auth attempt, so it needs active mode |
| `explore.priv-escalation` | An account gains access it did not have by writing its own object (self role/plan change) | a gate endpoint is stably denied for the account (two reads) and refused to anonymous; after the account's own write it answers the account; the field is restored (active mode) |
| `explore.data-exposure` | An endpoint returns several accounts' data to one caller (unfiltered list, admin view) | reading as the account, the body carries the markers of at least two DIFFERENT other accounts (not echoed from the request); an anonymous read is denied or lacks them (otherwise public, reported worse). Distinct from cross-actor, which is one named object |
| `explore.bfla` | A normal account reaches a function meant for a privileged one | the privileged account (declared `accounts.<x>.privileged`) and the normal account both call the function; proven iff the privileged account succeeds, anonymous is denied (a boundary), a nonsense variant as the normal account is denied, and the normal account succeeds the same way (for a read, the same view). A write needs active mode |
| `explore.cors` | CORS reflects any origin with credentials | differential: two distinct attacker origins are both reflected into `Access-Control-Allow-Origin` with the exact `Allow-Credentials: true`, or `Access-Control-Allow-Origin: null` with credentials on both (a sandboxed iframe); a wildcard or a single reflected origin is only a lead |
| `explore.reuse` | A single-use artifact (coupon, credit, invite) applied more than once | differential: the same application succeeds twice while an invalid artifact is rejected (active mode) |
| `explore.redirect` | A parameter whose value becomes the redirect target (open redirect) | differential: two distinct unguessable sentinel hosts under `.invalid` are both reflected into the redirect (3xx `Location` or a meta-refresh), read without following; a route that always redirects to one fixed place, or an allowlist that permits only one guess, is never proven (read-only) |
| `explore.graphql` | GraphQL field suggestions enabled, or query batching with no rate limit | suggestions: a near-miss of common fields returns "Did you mean" (read-only); batching: a batch of N queries runs as N results (active mode) |
| `explore.jwt-forge` | JWT signature bypass: alg:none (+ case variants), RS256→HS256 algorithm confusion (server public key as HMAC secret), weak HMAC secret | a forged token is accepted while the same token with a corrupted signature is rejected (public keys fetched from the usual JWKS paths) |

The older classes (`explore.replay`, `explore.cross-actor`, `explore.secret`,
`explore.file-match`) replay a request, compare two actors, check a secret in a
response and match a line in a file.

**Account markers.** `explore.replay` and `explore.cross-actor` prove a
cross-account read by an account's marker in the body. When an account has a
token but no declared `marker`, the exploration first reads an identity endpoint
(`options.authz-matrix.whoami` first, then common identity paths —
`/api/me`, `/me`, `/api/users/me`, `/api/whoami`, …) as each account and as anonymous, and keeps an identity field
(email, username, id, …) that only that account's read carries: 6+ characters
with a letter or 8+ digits, absent from every other account's read and from the
anonymous one (`src/agent/markers.ts`). It is read-only and gated, and a
declared marker always wins. Without either, those claims stay leads.

**Ownership without a marker.** `explore.cross-actor` with no marker rests on "the
attacker gets the owner's own body". That proves a cross-account read only for a
URL that names one object (a collection or a "my …" route gives every caller their
own scope) and for an object shown to be the owner's: an owner field (`UserId`,
`owner_id`, `createdBy`, …) holding the owner's id from its token, or the owner's
own account record. An object every account may read (a catalog behind login)
stays a lead.

**Funnel.** `explore.end` reports, per claim class, how many claims were
submitted and proven and where the rest stopped (`scope`, `budget`, `gate`,
`write-mode`, `detail`, or the `validator`'s own verdict), plus the leads noted
without a claim and the model's requests per account. A low recall shows there
where it is lost.

A claim whose validator writes (mass-assignment, reuse, stored XSS, an injection
or SSRF in a body) is gated as a write with its real method: only in `full`
exploration, with `allowActiveTesting`, and the gate asks every time.

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
