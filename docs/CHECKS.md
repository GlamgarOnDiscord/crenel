# Checks

Crenel runs fifteen checks. Each is deterministic and read-only, and marks every
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
| tls-verification | Code/config disabling TLS cert verification | no (leads) | no |
| jwt-config | JWT config that defeats signature verification | no (leads) | no |
| committed-credentials | Committed .npmrc/.pypirc/.netrc/... credentials | yes (file+field) | no |
| baas-exposure | Supabase/Firebase public key in the bundle, tables readable without RLS | yes (one-row read, opt-in) | static no; live read yes + active gate |
| webhook-signature | Webhook handler acting on an unverified payload | no (leads) | no |
| ssrf | Server fetching a URL taken from the request | no (leads) | no |
| live-bundle | Server keys, BaaS keys and public source maps in the JS the deployed site serves | yes (key shape in a served file, map answering 200) | GETs of public assets on declared hosts |
| exposed-files | .env, .git, dumps, debug pages served by the deployed site | yes (content signature + negative control) | GETs on the declared host |
| graphql | Introspection answered without credentials | yes (__schema in the response) | one GET query per usual path |
| open-redirect | Redirect to any URL named by a parameter | yes (Location points at the sentinel) | GETs on the declared host, redirect not followed |
| next-middleware | Next.js middleware skipped with x-middleware-subrequest (CVE-2025-29927) | yes (denied without, served with) | GETs on the declared host |
| subdomain-takeover | Declared host with a CNAME to a hosting service where nothing is deployed | yes (CNAME + service's not-found page) | DNS + one GET per declared host |
| email-dns | Missing or permissive SPF and DMARC on the mail domain | yes (DNS records) | DNS only |
| transport | Plain HTTP served instead of redirected, certificate close to expiry | yes | one GET over http://, one TLS handshake |
| git-history | Keys removed from the code but still in past commits | yes (detector match on an added line) | no (local git log) |
| storage-buckets | S3, R2, GCS buckets the app points at, listable by anyone | yes (anonymous listing, declared host) | static; one GET per declared bucket |
| authz-matrix | Cross-tenant object authorization | yes (live probe, opt-in) | yes + active gate |

## exposed-secrets

Scans text files under `projectDir` for distinctive secret shapes: Stripe
(`sk_live_`/`rk_live_` critical, test keys a low note), AWS access key, Google
API key and OAuth client secret, OpenAI (incl. `sk-proj-`), Anthropic, GitHub
(classic, fine-grained, OAuth family), Slack, npm, SendGrid, Supabase
service-role JWT (the payload is decoded: only `role: service_role` counts) and
`sb_secret_` keys, and PEM private-key blocks. A Google key inside a Firebase
web config is public by design and left to `baas-exposure`. A match is **proven** with a
`grep` you can replay. Fix: rotate the key and move it server-side; client code
holds only publishable keys.


**Does the key still work? (opt-in, network).** With
`options.exposed-secrets.verify: true`, each key that has a verifier (Stripe,
OpenAI, Anthropic, GitHub, Slack, SendGrid, npm) gets one read-only "who am I"
call to its own provider, only if that provider's API host is in
`scope.allowedHosts` (e.g. `api.stripe.com`). The title then says *key works
right now* or *revoked* (downgraded to low). The key travels only in the auth
header and never appears in reports.

## dependency-risk

Four offline signals: a locked `name@version` on the bundled OSV malware
denylist (**proven critical**); an install hook (`preinstall`/`postinstall`/…)
that runs code on install (lead); a dependency pulled from git/http/file instead
of the registry (lead); and no lockfile at all (lead). Refresh the denylist with
`pnpm sync-denylist`.


**Registry signals (opt-in, network).** With `options.dependency-risk.registry:
true` (or a registry URL) and its host in `scope.allowedHosts`, each direct
dependency is looked up: a package first published less than 30 days ago
(slopsquatting and typosquatting shape), a locked version published less than 7
days ago (the window of a maintainer takeover), and a name the registry does not
know (an invented name anyone could register later). All leads.

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

## baas-exposure

Apps built fast on Supabase or Firebase ship the project URL and the public key
to the browser. That is by design: the anon (or `sb_publishable_`) key is
public, and row-level security is what stops a visitor from reading every row.
This check finds the pair (`https://<ref>.supabase.co` with an anon JWT whose
`ref` matches, `createClient(url, key)` for self-hosted, a Firebase web config,
and Appwrite, PocketBase or Convex endpoints) and reports a **lead**: check RLS
on every table.

With `allowActiveTesting: true` **and** the BaaS host in `allowedHosts`, it
proves it, through the scoped HTTP client: it reads the PostgREST OpenAPI
schema (`GET /rest/v1/`) with the public key, then asks each table for one row
(`GET /rest/v1/<table>?select=*&limit=1`). GET only, never more than one row,
never an RPC call, and the row is dropped at once: the finding keeps the table
name, the column count and "rows are readable without signing in". A table
that answers is **proven**, critical when its column names look personal or
secret (email, phone, token, password...), high otherwise. Firebase Realtime
Database gets the same treatment with a shallow read of the root
(`/.json?shallow=true`, keys only). Firestore needs a POST to list collections,
which Crenel never sends, so it stays a lead. The generated regression test
asserts that the table returns no row with the anon key.

Secret keys (`service_role`, `sb_secret_`) are `exposed-secrets` findings,
critical and proven on their own.

## authz-matrix

The cross-tenant check, and deliberately **not** an LLM (research shows LLMs are
near-blind to authorization spread across files). You declare resources and two
test accounts; offline it emits a runnable isolation test matrix (a lead to wire
into CI). With a `stagingUrl`, two tokens, and active testing enabled for an
owned host, it replays each cross-tenant request and reports any that did not
return 401/403/404 as a **proven** broken-authorization finding.


**From an OpenAPI file.** `options.authz-matrix.openapi: api.yaml` (path relative
to the config) adds every GET route with exactly one path parameter as a
resource (`/projects/{projectId}` becomes `/projects/:id`, with the server's
path prefix). An operation with `security: []` is imported as public by design
and never probed. Hand-declared resources win on a name clash. You still list
the ids account B owns: the matrix never guesses objects.

**Ids found in B's own responses.** With `accounts.b.token` set, ids shaped like
B's declared ones (same prefix, or UUIDs) that appear in B's responses are
replayed too, up to 25. Since ownership is inferred, a discovered id counts only
if B can read it and an anonymous caller does not get the same object.

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

## tls-verification

Flags code or config that turns off TLS certificate verification:
`NODE_TLS_REJECT_UNAUTHORIZED=0` (process-wide), `rejectUnauthorized: false`, or
`strictSSL: false`. Any of these accept a forged certificate, so a network
attacker can read and alter "HTTPS" traffic. Leads. Fix: remove them and trust
the proper CA.

## jwt-config

Flags JWT configuration that defeats signature verification: `algorithm: "none"`,
`"none"` in an `algorithms` list, or verifying with a null/empty secret. Any of
these accepts an unsigned token, a classic authentication bypass. Leads. Fix: pin
a strong algorithm (RS256/ES256/HS256), never `none`, and verify with the real key.

## committed-credentials

Flags committed package-manager / registry credential files that carry a secret:
`.npmrc` (`_authToken`), `.pypirc`, `.netrc`, `.git-credentials`, a Docker
`config.json`/`.dockercfg` `auth`. The file name plus a credential field is a
**proven** match (these hold tokens no key-shape scanner sees). Fix: remove from
the repo and history, rotate, and gitignore credential files.

## webhook-signature

Flags a source file that looks like a webhook handler (a quoted Stripe, GitHub,
Clerk/Svix or Lemon Squeezy event name or signature header, or `webhook` in the
path), reads the request body, and contains no verification call at all
(`constructEvent`, `webhooks.verify`, `new Webhook`, `timingSafeEqual`,
`createHmac`, `verify…`). Anyone who knows the URL can then forge a paid event.
High lead, not proof: a verification done in a shared middleware is invisible
from the handler file.

Fix: verify the provider's signature on the raw body before acting, reject on
failure. Test: POST a forged unsigned event and expect 400/401 with no effect.

## ssrf

Flags server code where a value taken from the request (`searchParams.get`,
`req.query`, `req.params`, `req.body`, Hono's `c.req.query/param/json`) flows
into `fetch`, `axios`, `got` or `http(s).get` in the same file, when the file
shows no host allowlist (`ALLOWED…`, `allowedHosts`, a `.hostname` comparison).
High lead: the taint tracking is a same-file heuristic, not a data-flow
analysis.

Fix: require https, allow an explicit list of hosts, resolve the host and refuse
private, loopback and link-local addresses, do not follow cross-host redirects.

## live-bundle

Scans what the deployed site actually serves, without the repo. From
`scope.stagingUrl` it follows `<script src>`, modulepreload links, inline
scripts, `import()` and static imports, Next.js `static/chunks/` paths and
`sourceMappingURL` comments, downloading each file with GET through the scoped
client (declared hosts only: a chunk on an undeclared CDN is logged and
skipped; up to 150 files, 40 MB, 2 MB per response). The `exposed-secrets`
detectors then run on those files, Supabase public keys become RLS leads, and a
source map that answers 200 is reported.

## bundle-review (`crenel review-bundle`, needs `claude -p`)

Not a check: a command. It hands the model every chunk `live-bundle` collects,
whole, in windows of about 120 KB, fenced as untrusted data, and asks for what
no regex sees: admin or internal endpoints, authorization done only in the
browser, hidden routes and flags, debug code, keys of unknown formats, internal
hosts. Each item must quote an excerpt that exists verbatim in the served file,
or it is dropped. Everything it returns is a lead labelled *IA, non vérifié*;
endpoints are listed so the authorization matrix can replay them.

## exposed-files

Requests a short list of paths on `scope.stagingUrl` (`/.env`,
`/.env.production`, `/.git/config`, `/.git/HEAD`, SQL dumps, `/.DS_Store`,
`/server-status`, `/actuator/env`, `/.vscode/sftp.json`, `/phpinfo.php`), the
method of nuclei's exposure templates. A hit needs a 200, a body that matches
the file's own signature (`KEY=value` lines for a .env, `[core]` for a Git
config, `CREATE TABLE` for a dump), and a body different from what a random
path returns, so a single-page app that answers everything with index.html is
never reported.

## graphql

Sends the smallest read-only introspection query with GET (`?query=`) to
`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql` on the declared
host (or `options.graphql.paths`). A response carrying `__schema` proves
introspection is open: the whole API map, admin mutations included, is public.
Servers that accept GraphQL over POST only are not tested (Crenel never sends
POST), and the log says so.

## open-redirect

Requests `/`, `/login`, `/signin`, `/logout`, `/auth/callback`, `/redirect` with
the usual parameters (`redirect`, `redirect_uri`, `next`, `returnTo`,
`callbackUrl`, `continue`, `url`…) set to a sentinel URL under `.invalid` (a TLD
that never resolves), reads the redirect without following it, and proves the
flaw when `Location` (or a meta refresh) points at the sentinel. Override the
lists with `options.open-redirect.paths` and `.params`.

## next-middleware

CVE-2025-29927: Next.js before 12.3.5, 13.5.9, 14.2.25 and 15.2.3 skips the
middleware for a request that carries `x-middleware-subrequest`. Apps that check
auth in middleware then serve protected pages to anyone. `/dashboard`, `/admin`,
`/settings`, `/app`, `/account`, `/api/admin` (or `options.next-middleware.paths`)
are requested without and with the header; denied or redirected without it and
served (200, a different page) with it is the proof.

## subdomain-takeover

For each host in `scope.allowedHosts`: if its CNAME points at Heroku, GitHub
Pages, Netlify, Vercel, S3, Azure, Shopify, Fastly, Render or Fly.io, and the
host answers with that service's own "nothing deployed here" page, anyone can
claim the name on the service and serve content on your subdomain. Nothing is
ever claimed.

## email-dns

TXT lookups for the mail domain (`options.email-dns.domain`, else the staging
host without a leading `www`/`app`/`staging` label): no SPF, SPF ending in
`+all`/`?all`, several SPF records, no DMARC, or DMARC `p=none`. Without an
enforcing DMARC, a forged password-reset mail can carry your exact From address.

## transport

On an https staging URL: GET over plain `http://` (redirect read, not followed)
must not serve the page, and a TLS handshake reads the certificate's expiry
(under 21 days is reported, under 7 is high).

## git-history

Reads the lines added in the repository's history (`git log --all -p`, last 500
commits, `options.git-history.maxCommits`) with the `exposed-secrets`
detectors, and reports keys that are no longer in the current tree: deleting a
key from the code does not remove it from clones, so it must be rotated. The key
itself never appears in the report.

## storage-buckets

Lists the S3, R2 and Google Cloud Storage bucket URLs found in the scanned code
(leads). When a bucket's host is in `scope.allowedHosts`, one anonymous GET on
its listing endpoint (first key only) proves whether anyone can enumerate its
files.
