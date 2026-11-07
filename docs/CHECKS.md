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
| graphql | Introspection answered without credentials | yes (__schema in the response) | one GET query per usual path, then the same query as a POST |
| open-redirect | Redirect to any URL named by a parameter | yes (Location points at the sentinel) | GETs on the declared host, redirect not followed |
| next-middleware | Next.js middleware skipped with x-middleware-subrequest (CVE-2025-29927) | yes (denied without, served with) | GETs on the declared host |
| subdomain-takeover | Declared host with a CNAME to a hosting service where nothing is deployed | yes (CNAME + service's not-found page) | DNS + one GET per declared host |
| email-dns | Missing or permissive SPF and DMARC on the mail domain | yes (DNS records) | DNS only |
| transport | Plain HTTP served instead of redirected, certificate close to expiry | yes | one GET over http://, one TLS handshake |
| git-history | Keys removed from the code but still in past commits | yes (detector match on an added line) | no (local git log) |
| storage-buckets | S3, R2, GCS buckets the app points at, listable by anyone | yes (anonymous listing, declared host) | static; one GET per declared bucket |
| dev-server | Vite, webpack or Next.js dev server reachable on the deployed host | yes (dev runtime signature) | GETs on the declared host |
| ai-infra | Ollama, OpenAI-compatible model APIs, Qdrant, Chroma, Weaviate, Flowise, Langflow, MCP servers open without auth | yes (anonymous inventory) | GETs, plus the MCP handshake and tools/list by POST, on declared bases |
| vercel-preview | Vercel deployments served without the Vercel login wall | yes (200 without the wall) | one GET per declared *.vercel.app |
| cache-deception | Private responses cached under a static-looking URL | yes (anonymous GET returns B's object) | GETs, needs allowActiveTesting and B's token |
| auth-config | Supabase open sign-up without email confirmation, Better Auth OpenAPI published | yes (public settings) | GETs |
| auth-variants | Protected route served through another spelling (.rsc, ?_rsc=, /_next/data, //, case) | yes (canonical refused, variant served) | GETs |
| next-image | Next.js image optimizer fetching any host (remotePatterns `**`) | yes (Next's own answer to a control URL) | GETs on the declared host; the target fetches one control URL |
| api-docs | OpenAPI or Swagger definition served by the deployed API | yes (the body parses as a spec) | GETs on declared bases |
| supabase-rpc | Postgres functions the client calls (`.rpc("x")`) returning data to the anon role | yes (GET with the public key, refused without it) | static; GETs on the Supabase host + active gate |
| cache-poisoning | Unkeyed header (X-Forwarded-Host/Proto) reflected and stored by the cache | yes (sentinel served without the header) | GETs, needs allowActiveTesting and `options.cache-poisoning.enabled` |
| business-logic | Client code that sends an amount, a plan or a role, admin/invite/credits routes | no (hypotheses, never proven) | no |
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
OpenAI, Anthropic, GitHub, Slack, SendGrid, npm, Google) gets one read-only "who am I"
call to its own provider, only if that provider's API host is in
`scope.allowedHosts` (e.g. `api.stripe.com`). The title then says *key works
right now* or *revoked* (downgraded to low). The key travels only in the auth
header and never appears in reports. A Google key is checked by listing
Gemini models (`generativelanguage.googleapis.com`, free, key in the
`x-goog-api-key` header): 200 is reported as *no referrer restriction observed*,
never as "unrestricted"; a 403 (referrer, IP or API restriction, service
disabled) leaves the verdict unknown.

## dependency-risk

Four offline signals: a locked `name@version` on the bundled OSV malware
denylist (**proven critical**); an install hook (`preinstall`/`postinstall`/…)
that runs code on install (lead); a dependency pulled from git/http/file instead
of the registry (lead); and no lockfile at all (lead). Refresh the denylist with
`pnpm sync-denylist`.


**Known advisories from OSV (opt-in, network).** With
`options.dependency-risk.osv: true` and `api.osv.dev` in `scope.allowedHosts`,
every locked npm package and version is sent to OSV (the database behind
osv-scanner and GitHub's advisories), and each advisory whose range covers the
locked version is a lead with the advisory's severity: affected, exploitability
not proven. Only package names and versions leave the machine.

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
never an RPC call here (functions are `supabase-rpc`), and the row is dropped at once: the finding keeps the table
name, the column count and "rows are readable without signing in". A table
that answers is **proven**, critical when its column names look personal or
secret (email, phone, token, password...), high otherwise. Firebase Realtime
Database gets the same treatment with a shallow read of the root
(`/.json?shallow=true`, keys only). When no `databaseURL` is in the config, the default
instance `https://<projectId>-default-rtdb.firebaseio.com` is tried if declared.
**Cloud Storage for Firebase**: with `firebasestorage.googleapis.com` declared,
one anonymous `GET /v0/b/<bucket>/o?maxResults=1` (the config's `storageBucket`,
else `<projectId>.appspot.com` and `<projectId>.firebasestorage.app`): an object
or folder name coming back proves the bucket is listable by anyone (high); the
name is not kept. Firestore needs a POST to list collections,
which Crenel never sends, so it stays a lead. The generated regression test
asserts that the table returns no row with the anon key.

Secret keys (`service_role`, `sb_secret_`) are `exposed-secrets` findings,
critical and proven on their own.


**Firestore.** With `firestore.googleapis.com` declared and active testing on,
each collection the client code names (`collection(db, "x")`, `doc(db, "x", …)`,
`.collection("x")`) is read with one anonymous GET on the Firestore REST API
(`pageSize=1`). A document coming back proves the rules allow public reads; the
document is not kept. Listing all collections would need a POST, which Crenel
never sends.

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


It also reads the Next.js version the site serves (`window.next = { version }`)
and, when `dependency-risk.osv` is on and `api.osv.dev` declared, reports that
version's OSV advisories as leads, so a deployed site gets checked even without
its lockfile.

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
When GET gives nothing, the same query goes out as a JSON POST: the HTTP
client lets that POST through only because its body is a single query with no
mutation or subscription (see "What goes out" below).

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

## dev-server

`/@vite/client`, `/_next/webpack-hmr`, `/webpack-dev-server`, `/sockjs-node/info`
on the staging host. A hit needs the dev runtime in the body (`createHotContext`,
an HMR event stream…) and a body different from a random path's.

## ai-infra

Inventory endpoints of AI services, anonymous GETs only: Ollama `/api/tags`, an
OpenAI-compatible `/v1/models`, Qdrant `/collections`, Chroma's collection list,
Weaviate `/v1/schema`, Flowise `/api/v1/chatflows`, Langflow `/api/v1/flows/`, and MCP
servers over SSE (`/sse` answering `event: endpoint` without credentials; only
the first 32 bytes are read) or over Streamable HTTP (`/mcp`, `/api/mcp`: an
anonymous `initialize` by POST that returns a protocolVersion, then `tools/list`
to count the tools; no tool is ever called).
Bases: the staging URL plus `options.ai-infra.urls` (e.g. a model server on its
own port), declared hosts only. Only counts and service names are reported.

## vercel-preview

Every `*.vercel.app` host declared in scope or found in the code: a declared one
that serves the app to an anonymous visitor, without the Vercel login wall, is
public (list your production alias in `options.vercel-preview.production`).
Undeclared ones found in the code are listed as leads, never requested.

## cache-deception

With `allowActiveTesting` and account B's token: for each declared resource,
B's object is requested at a static-looking URL (`/x/<nonce>.css`, `;<nonce>.css`,
`.css?…`), then the same URL is requested anonymously. B's object coming back to
the anonymous caller, while the canonical URL refuses it, proves the cache
stores private pages. Each URL carries a unique nonce, so real users never get it.

## auth-config

Supabase `/auth/v1/settings` read with the bundle's public key: open sign-up with
email (or phone) auto-confirm means anyone can create a working account, which
opens every RLS policy that only checks "signed in". Better Auth's OpenAPI
reference (`/api/auth/reference`) answering in production publishes every auth
route.

## auth-variants

For each usual protected route that refuses an anonymous visitor, a few
spellings the framework routes to the same page: `.rsc` and `?_rsc=` with the
RSC header, `/_next/data/<buildId>/<route>.json` (build id read from the page),
a doubled or trailing slash, an upper-case letter, an encoded slash. A variant
served with a real page, where the canonical path redirected or refused, is the
proof. A canonical redirect *to* the variant (URL normalization) is ignored.

## next-image

Next.js's image optimizer (`/_next/image`) only downloads URLs that match
`images.remotePatterns`. A `**` hostname turns it into an open proxy: anyone
makes your server fetch the URL of their choice (SSRF, internal addresses too
before Next.js 16) on your bandwidth.

Crenel's own client still talks only to the declared host. It first requests
`/_next/image` with no parameter, which must answer Next's own
`"url" parameter is required` (negative control: a soft-200 page or another
framework is never read as the optimizer). It then asks the optimizer for a
control URL, `GET /_next/image?url=<control>&w=64&q=75` (width retried with 640
then 1080 if `64` is not in your `imageSizes`). Next's answer decides:
`"url" parameter is not allowed` means remotePatterns refused it (fine);
`The requested resource isn't a valid image`, `"url" parameter is valid but
upstream response ...` or an image coming back means the server fetched it
(**proven**, high).

**The target server makes one outbound request** to the control URL. Crenel
never contacts it. The default is `https://example.com/`, a domain IANA reserves
for examples: public, free, stable. Change it with
`options.next-image.controlUrl` (http or https only) and the endpoint with
`options.next-image.path`.

## api-docs

Requests the frameworks' default definition paths (`/openapi.json`,
`/openapi.yaml`, `/swagger.json`, `/swagger.yaml`, `/api/openapi.json`,
`/api/swagger.json`, `/api-docs`, `/api-docs.json`, `/v3/api-docs`,
`/v2/api-docs`, `/swagger/v1/swagger.json`, `/docs/openapi.json`; override with
`options.api-docs.paths`) on the staging URL and `options.api-docs.urls`. A hit
needs a 200 whose body parses as JSON or YAML with an `openapi`/`swagger`
version and a `paths` object, so an SPA shell or a status JSON never counts. One
finding per base: low, medium when the spec lists admin, internal or debug
routes. A public API may publish its spec on purpose; the finding then mainly
says which object routes belong in the authorization matrix
(`options.authz-matrix.openapi` imports the same file).

## supabase-rpc

Lists the Postgres functions the client code calls through PostgREST
(`supabase.rpc("name")`). A `SECURITY DEFINER` function runs with its owner's
rights, so RLS on the tables it reads does not apply: a search or stats helper
can hand every user's rows to a visitor. Offline, the list is a lead.

With `allowActiveTesting` and the Supabase host in `allowedHosts` (the same
opt-ins as the table reads), each function is called once with
`GET /rest/v1/rpc/<name>` and the bundle's public key, no arguments. PostgREST
runs every GET and HEAD in a **read-only transaction** whatever the function's
volatility, so the call cannot modify the database; a function that tries is
refused with 405 (SQLSTATE 25006), reported as *undetermined* (the anon role
reaches a function that writes; Crenel never sends the POST that would run it).
Function names that announce a side effect outside the database (`send`,
`delete`, `pay`, `invite`, `http`...) are never called. Data coming back is
**proven** only when the same GET without the key is refused (401/403), so the
data came through the anon role. Critical when the fields look personal or
secret, medium for other rows (it may be a public listing by design: confirm),
low for a single value. A 404 or 400 (function missing or needing arguments)
and an empty answer conclude nothing. The response is never kept.

## cache-poisoning

Off by default: it writes one entry into your shared cache, so it needs both
`allowActiveTesting` and `options.cache-poisoning.enabled: true`. For each path
(`options.cache-poisoning.paths`, default `/`) and header
(`options.cache-poisoning.headers`, default `X-Forwarded-Host` and
`X-Forwarded-Proto`):

1. a GET with the header set to a sentinel (a host under `.invalid`, which never
   resolves) must reflect it, in the body or a header;
2. the same URL requested without the header returning the sentinel proves the
   cache stored the poisoned response (**proven**, high);
3. a URL with another cache key, never sent with the header, must show nothing
   (negative control).

Every request carries a unique `?crenel=<nonce>` that no visitor asks for. Before
any poisoning request, a fresh nonce must not come back as a cache hit; when it
does, the cache ignores the query string and a test entry could reach the real
page, so the path is skipped. Redirects are read, never followed.

## business-logic

Hypotheses, never proofs: the flaws behind "paid without paying" and "made
myself admin" need writes to prove, which Crenel never sends. Offline, in client
code (server folders such as `api/`, `server/`, `functions/` and route handlers
are skipped), it flags:

- **payment**: a request to the app's own route (relative URL) whose body
  carries `amount`, `unit_amount`, `total`, `totalPrice` or `price` (a Stripe
  `price_…` id is the right pattern and is ignored; third-party hosts too);
- **privilege**: a request body, or a Supabase `.update/.insert/.upsert`, that
  carries `role`, `plan`, `tier`, `credits`, `isAdmin`, `isPro`,
  `subscription_status`, `permissions`;
- **routes**: `/api/admin…`, `/api/invite(s)…`, `/api/credits…`,
  `/api/impersonate…` named in the client (one low lead).

Each is `unproven`, medium (routes: low), and carries a regression test written
out for the team to run on staging; Crenel does not run it, because it writes.

## What goes out

Every check uses one HTTP client (`src/core/net.ts`), which refuses any method
other than GET and HEAD unless `scope.allowActiveTesting` is true. One
exception, decided on the exact bytes about to be sent: a POST whose body is
provably a read.

| Body | Allowed when |
|---|---|
| GraphQL | a single `{query, variables?, operationName?}` object whose document starts as a query and contains no `mutation` or `subscription` |
| MCP JSON-RPC | `initialize`, `notifications/initialized`, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` (never `tools/call`) |
| OSV | `api.osv.dev/v1/querybatch`, a public advisory lookup |

Batched GraphQL or JSON-RPC arrays are refused. A refused request is written to
the journal like any other.
