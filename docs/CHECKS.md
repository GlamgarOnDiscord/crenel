# Checks

Crenel runs eleven checks. Each is deterministic and read-only, and marks every
finding `proven` (a replayable match or request) or `unproven` (a lead to
review). Only a **proven high or critical** gates CI. Checks read the directory
you point `projectDir` at and, where noted, a `stagingUrl` you declared you own.

Run a subset with `checks: [exposed-secrets, authz-matrix]` in the config; an
empty list runs every read-only check.

| Check | What it flags | Can be proven? | Needs network? |
|---|---|---|---|
| exposed-secrets | Secret/key shapes in the scanned files | yes (regex match) | no |
| dependency-risk | Malicious locked versions, install scripts, non-registry deps, no lockfile | yes (denylist) | no |
| ci-hardening | `pull_request_target`, unpinned actions, install without `--ignore-scripts` | no (leads) | no |
| headers | Missing security headers and cookie flags | yes (live response) | yes (stagingUrl) |
| cloudflare-audit | Normalised output of Cloudflare's security-audit-skill | passes its verdict through | no |
| mcp-surface | Committed agent/MCP config and the servers it declares | no (leads) | no |
| dockerfile | Container hardening in your Dockerfile(s) | no (leads) | no |
| committed-env | Committed `.env` files | no (leads) | no |
| sourcemaps | Source maps shipped with the client bundle | no (leads) | no |
| public-env | A secret behind a client-exposed env prefix | no (leads) | no |
| authz-matrix | Cross-tenant object authorization | yes (live probe, opt-in) | yes + active gate |

## exposed-secrets

Scans text files under `projectDir` for distinctive secret shapes: Stripe
(`sk_live_`/`rk_live_` critical, test keys a low note), AWS access key, Google
API key and OAuth client secret, OpenAI (incl. `sk-proj-`), Anthropic, GitHub
(classic, fine-grained, OAuth family), Slack, npm, SendGrid, Supabase
service-role JWT, and PEM private-key blocks. A match is **proven** with a
`grep` you can replay. Fix: rotate the key and move it server-side; client code
holds only publishable keys.

## dependency-risk

Four offline signals: a locked `name@version` on the bundled OSV malware
denylist (**proven critical**); an install hook (`preinstall`/`postinstall`/…)
that runs code on install (lead); a dependency pulled from git/http/file instead
of the registry (lead); and no lockfile at all (lead). Refresh the denylist with
`pnpm sync-denylist`.

## ci-hardening

Reads `.github/workflows/*.yml`. Flags `pull_request_target` (runs with your
secrets on fork code), an action pinned to a tag/branch instead of a commit SHA,
and `install` without `--ignore-scripts`. Leads: these are the entry points the
2026 supply-chain incidents used.

## headers

With a `stagingUrl` you own, does a plain GET and checks for Content-Security-
Policy, HSTS, X-Content-Type-Options, X-Frame-Options (satisfied by a restrictive
CSP `frame-ancestors`), Referrer-Policy, and the Secure/HttpOnly/SameSite cookie
flags, plus a dangerous CORS combination (Access-Control-Allow-Credentials: true
with an Allow-Origin of `*` or `null`). Proven against the live response. Without
a `stagingUrl` it emits one lead asking you to set one.

## cloudflare-audit

Ingests the `findings.json` produced by
[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill):
`confirmed` becomes proven, `needs_validation` a lead, `rejected` is dropped.
Point `options.cloudflare-audit.report` at the file.

## mcp-surface

Looks at known agent/MCP config locations (`.mcp.json`, `claude_desktop_config.json`,
`.cursor/mcp.json`, …). Reports the declared servers as a lead, and raises to
medium when a server runs a local `command` (arbitrary execution if the config is
tampered with). Secret *values* inside are the exposed-secrets check's job.

## dockerfile

Reads your `Dockerfile`(s). Flags running as root (no `USER`), an unpinned or
`:latest` base image, a secret-looking `ENV`/`ARG` baked into a layer, `ADD`
from a URL, and a remote script piped to a shell. Leads.

## committed-env

Flags committed `.env` files (excluding `.env.example`/`.sample`/`.template`). A
`.env` conventionally holds secrets that no key-shape scanner would catch, so the
committed file itself is the signal. Fix: gitignore it, rotate what it held,
commit only an example.

## authz-matrix

The cross-tenant check, and deliberately **not** an LLM (research shows LLMs are
near-blind to authorization spread across files). You declare resources and two
test accounts; offline it emits a runnable isolation test matrix (a lead to wire
into CI). With a `stagingUrl`, two tokens, and active testing enabled for an
owned host, it replays each cross-tenant request and reports any that did not
return 401/403/404 as a **proven** broken-authorization finding.

## sourcemaps

Looks under `projectDir` for `.map` files and for `sourceMappingURL` comments
that point at an external (non-`data:`) map. A shipped source map hands anyone
the original, unminified source. Leads (some teams ship maps for error tracking).
Fix: upload maps to your error tracker at build time and strip them from the
public bundle.

## public-env

Flags an env var that carries a framework "public" prefix (`NEXT_PUBLIC_`,
`VITE_`, `REACT_APP_`, `PUBLIC_`, `EXPO_PUBLIC_`, `GATSBY_`, `VUE_APP_`,
`NUXT_PUBLIC_`) and is named like a secret (`...SECRET`, `...TOKEN`, `...KEY`,
`...PASSWORD`). Those prefixes are inlined into the client bundle by design, so
such a var leaks its value to the browser whatever its shape. Fix: drop the
public prefix and read the secret server-side only.

