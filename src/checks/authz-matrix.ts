// authz-matrix: the check that matters most for a multi-tenant SaaS.
//
// Research finding that drives this: LLM-based scanners are near-blind to broken
// object-level authorization when the ownership check is spread across files or
// lives in middleware (0 real bugs found, in Semgrep's IDOR study). So this is
// NOT an LLM check. It is a declarative, deterministic matrix: you list your
// resources and two test accounts, and Crenel asserts that account A can never
// read or mutate account B's objects.
//
// Two modes:
//   - offline (always): generate the test matrix and emit a runnable test file.
//     No network, no scope needed. This alone encodes the invariant in your CI.
//   - live (opt-in): if a staging URL and two accounts are configured AND active
//     testing is enabled for an owned host, replay each cross-tenant request and
//     report any that did not return 401/403/404 as PROVEN broken authorization.

import { resolveAccounts, type LoginSpec } from "./session.js";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { randomBytes } from "node:crypto";
import { safeFetch } from "../core/net.js";
import { authzOracle, ownerValue } from "../agent/validators.js";

interface ResourceSpec {
  /** e.g. "project" */
  name: string;
  /** URL path template with :id, e.g. "/api/projects/:id" */
  path: string;
  /** HTTP methods to test for isolation. GET only by default (read-only). */
  methods?: string[];
  /** Public by design (a trust boundary): never probed, never reported. */
  public?: boolean;
  /** Owner-id field in the object body (e.g. "UserId", "owner_id"). Enables the
   * owner-id differential: proves a cross-tenant read without B's token/marker. */
  ownerField?: string;
  /** Ids belonging to OTHER tenants (not account A), to attempt as A for the
   * owner-id differential. No ownership is claimed about them; the proof reads
   * the owner-id field out of the response itself. Needs `ownerField` and an id
   * of this resource under accounts.a.owns (A's own object, the baseline). */
  probeIds?: string[];
  /** GraphQL transport for the owner-id differential: a query string with :id,
   * e.g. `{ paste(id: :id) { ownerId } }`. When set, the resource is read by POST
   * to `path` (the GraphQL endpoint) and the owner field is taken from the object
   * under `data`. Lets the same validated oracle cover a GraphQL API. */
  gql?: string;
}

interface AccountSpec {
  label: string;
  /** Bearer token for this test account (staging only). */
  token?: string;
  /** Session-cookie auth: the raw Cookie header value, for apps that authenticate
   * by cookie session (Flask-Login, Django, Rails, PHP) rather than a bearer. */
  cookie?: string;
  /** Any other auth headers this account needs (a custom scheme, an API key header). */
  headers?: Record<string, string>;
  /** Resource ids that belong to this account, keyed by resource name. */
  owns?: Record<string, string[]>;
  /** A string only B's objects contain (an email, an org id): proof the body is B's. */
  marker?: string;
  /** A login flow run at the start of the check instead of a pre-obtained token or cookie (src/checks/session.ts). */
  login?: LoginSpec;
}

interface AuthzOptions {
  resources?: ResourceSpec[];
  accounts?: { a?: AccountSpec; b?: AccountSpec; c?: AccountSpec };
}

/** The request headers that carry this account's identity, from any of the three
 * generic auth shapes (bearer token, session cookie, custom headers). Empty for
 * an anonymous caller. No target specifics: the values are operator config. */
type Auth = { token?: string; cookie?: string; headers?: Record<string, string> };
const authHeaders = (a?: Auth): Record<string, string> =>
  a ? { ...(a.token ? { authorization: `Bearer ${a.token}` } : {}), ...(a.cookie ? { cookie: a.cookie } : {}), ...(a.headers ?? {}) } : {};
const hasAuth = (a?: Auth): boolean => !!(a && (a.token || a.cookie || (a.headers && Object.keys(a.headers).length > 0)));
/** Two accounts carry the SAME custom auth headers (same non-empty key/value set):
 * then A and B are one identity, so a "cross-tenant" read is just B reading its own
 * object and proves nothing. Mirrors the token/cookie same-identity guard. */
const sameCustomHeaders = (a?: Record<string, string>, b?: Record<string, string>): boolean => {
  if (!a || !b) return false;
  const ak = Object.keys(a), bk = Object.keys(b);
  return ak.length > 0 && ak.length === bk.length && ak.every((k) => a[k] === b[k]);
};
/** A redacted curl snippet for the replay hint, matching the auth shape used. */
const replayAuth = (a: Auth | undefined, key: string): string =>
  a?.token ? ` -H 'authorization: Bearer <${key.toUpperCase()}_TOKEN>'` : a?.cookie ? ` -H 'cookie: <${key.toUpperCase()}_SESSION>'` : hasAuth(a) ? ` -H '<${key.toUpperCase()}_AUTH>'` : "";


export const authzMatrix: Check = {
  name: "authz-matrix",
  title: "Cross-tenant authorization (an account must never reach another's data)",
  readOnly: true, // matrix generation is read-only; live probes are gated separately
  async run(ctx: CheckContext): Promise<Finding[]> {
    const cfg = { ...((ctx.options["authz-matrix"] ?? {}) as AuthzOptions) };
    const resources = cfg.resources ?? [];
    const findings: Finding[] = [];
    const provenIds = new Set<string>();

    if (resources.length === 0) {
      ctx.log("authz-matrix: no resources declared, nothing to check");
      return findings;
    }
    // Declared login flows: a fresh session per run (short-lived tokens, cookie sessions).
    if (ctx.stagingUrl && cfg.accounts && Object.values(cfg.accounts).some((a) => a?.login)) {
      cfg.accounts = await resolveAccounts(ctx, cfg.accounts, "authz-matrix") as AuthzOptions["accounts"];
    }

    // Build the matrix: account A attempting to touch each id owned by B.
    const b = cfg.accounts?.b;
    const cases: { resource: ResourceSpec; method: string; id: string }[] = [];
    for (const r of resources) {
      if (r.public) continue;
      const methods = r.methods ?? ["GET"];
      const ids = b?.owns?.[r.name] ?? [];
      for (const method of methods) {
        for (const id of ids) cases.push({ resource: r, method, id });
      }
    }

    ctx.log(`authz-matrix: ${resources.length} resource(s), ${cases.length} cross-tenant case(s)`);

    // Owner-id differential work is independent of b.owns cases: it needs only a
    // resource with ownerField + probeIds and A's own id of that resource.
    const ownerFieldResources = resources.filter(
      (r) => !r.public && r.ownerField && (r.probeIds?.length ?? 0) > 0,
    );
    const canProbe = !!ctx.stagingUrl && hasAuth(cfg.accounts?.a) && cases.length > 0;
    const canOwnerField = !!ctx.stagingUrl && ownerFieldResources.length > 0 && (hasAuth(cfg.accounts?.a) || ownerFieldResources.some((r) => r.gql));

    if (!canProbe && !canOwnerField) {
      // Offline: emit one finding that carries the generated test as its proof-of-intent.
      // It is "unproven" because we have not run it; it is a lead to wire into CI.
      findings.push({
        id: "authz-matrix:offline-plan",
        check: "authz-matrix",
        title: "Cross-tenant authorization is not yet asserted in CI",
        severity: "medium",
        state: "unproven",
        location: ctx.projectDir,
        description:
          `Declared ${resources.length} resource(s). No live probe ran (needs a staging URL and ` +
          `a token for test account A). The generated matrix below should become a CI test.`,
        remediation:
          "Add the generated isolation test to your suite and run it on every pull request.",
        proof: {
          method: "generated test matrix",
          replay: "see regressionHint",
          evidence: renderTestFile(resources),
        },
        regressionHint: renderTestFile(resources),
      });
      return findings;
    }

    // Live probes require explicit opt-in: we are sending crafted cross-tenant
    // requests, so even though they are GETs we route them through the active gate.
    ctx.scope.assertActiveAllowed("authz-matrix (live probe)");
    const base = ctx.stagingUrl!.replace(/\/$/, "");
    ctx.scope.assertUrlAllowed(base);
    const accounts = cfg.accounts ?? {};
    const markers = [accounts.b?.marker ?? ""].filter(Boolean);
    // Distinct contexts (Teycir's guard): if A and B are the same account, every
    // "cross-tenant" read is just B reading its own object. Refuse to prove anything.
    const same = sameIdentity(accounts.a?.token, accounts.b?.token)
      || (accounts.a?.cookie && accounts.a.cookie === accounts.b?.cookie ? "use the same session cookie" : null)
      || (sameCustomHeaders(accounts.a?.headers, accounts.b?.headers) ? "use the same custom auth headers" : null);
    if (same) {
      ctx.log(`authz-matrix: accounts A and B are the same identity (${same}), live probe skipped`);
      findings.push({
        id: "authz-matrix:same-identity", check: "authz-matrix", title: "Test accounts A and B are the same identity: the matrix cannot prove anything",
        severity: "medium", state: "unproven", location: "options.authz-matrix.accounts",
        description: `The tokens for A and B ${same}. Use two accounts of two different tenants.`,
        remediation: "Create a second test account in another organization and put its token under accounts.a.",
      });
      return findings;
    }
    const get = (url: string, auth?: Auth) =>
      safeFetch(url, ctx.scope, { method: "GET", headers: authHeaders(auth) })
        .then((r) => ({ status: r.status, body: r.body }));

    // Same oracle as the agent's validator: a 200 is not proof. The attacker's
    // body must be the owner's object, and a negative control (an id that does
    // not exist) must not answer the same way. Each case is tried with A's
    // token, and C's if declared — two *other tenants*. The anonymous caller is
    // handled separately (the public-route guard below): a cross-tenant break is
    // only meaningful on a route that actually refuses an anonymous caller, so a
    // route anyone can read is reported as a lead, never a "proven" BOLA.
    const actors: { key: "a" | "c"; who: string; auth?: Auth }[] = [
      { key: "a", who: "account A's credentials", auth: accounts.a },
      ...(hasAuth(accounts.c) ? [{ key: "c" as const, who: "account C's credentials (another tenant)", auth: accounts.c }] : []),
    ];
    const ownerBodies: string[] = [];
    for (const c of cases) {
      if (c.method !== "GET") { ctx.log(`authz-matrix: ${c.method} ${c.resource.path} skipped, only GET is probed live`); continue; }
      const url = base + c.resource.path.replace(":id", encodeURIComponent(c.id));
      const controlUrl = base + c.resource.path.replace(":id", `crenel-nonexistent-${randomBytes(6).toString("hex")}`);
      ctx.scope.assertUrlAllowed(url);
      try {
        const owner = hasAuth(accounts.b) ? await get(url, accounts.b) : undefined;
        if (owner && owner.status >= 200 && owner.status < 300) ownerBodies.push(owner.body);
        // Public-route guard. Before claiming a cross-tenant break, check that the
        // route refuses an anonymous caller. If an anonymous GET already returns
        // B's object, the route is not access-controlled at all: another account
        // reaching it is NOT broken object-level authorization (everyone can, by
        // design or by a missing auth gate we cannot tell apart from here). Report
        // one lead — never a "proven" BOLA an anonymous request would also satisfy.
        // The anonymous probe never follows redirects: a 302 to /login is a
        // denial, not a leak, and following it can loop. A failure here only skips
        // the guard (treated as "not public"), never the cross-tenant checks below.
        const anonGet = (u: string) => safeFetch(u, ctx.scope, { method: "GET", followRedirects: false }).then((r) => ({ status: r.status, body: r.body })).catch(() => ({ status: 0, body: "" }));
        const anonCtl = await anonGet(controlUrl);
        const anon = await anonGet(url);
        const anonLeak = authzOracle({ attacker: anon, owner, control: anonCtl, ownerMarkers: markers });
        // Skipping the authenticated probes hides a real BOLA if the anonymous read
        // was a one-off (a shared cache entry, a race with B's own request): the
        // route counts as public only when a second anonymous read leaks again.
        const anonAgain = anonLeak.verdict === "leak" ? authzOracle({ attacker: await anonGet(url), owner, control: anonCtl, ownerMarkers: markers }) : anonLeak;
        if (anonLeak.verdict === "leak" && anonAgain.verdict === "leak") {
          findings.push({
            id: `authz-matrix:${c.resource.name}:${c.method}:${c.id}:public`,
            check: "authz-matrix",
            title: `${c.resource.name} is readable without authentication (${c.method} ${anon.status})`,
            severity: "medium", state: "unproven", location: url,
            description: `An anonymous ${c.method} on this ${c.resource.name} returns the object (${anonLeak.reason}). The route is not access-controlled, so another account reaching it is not a broken-authorization proof — anyone can read it. Confirm whether this object is meant to be public; if not, require authentication, then enforce the per-object ownership check.`,
            remediation: `Require authentication on ${c.resource.name}, then enforce the per-object ownership check for every authenticated caller.`,
            proof: {
              method: "live anonymous read on staging: owner baseline, anonymous caller, negative control",
              replay: `curl -i -X ${c.method} '${url}'`,
              evidence: `anonymous HTTP ${anon.status}; control ${anonCtl.status}${owner ? `; owner ${owner.status}` : ""}. ${anonLeak.reason}`,
            },
            regressionHint: renderTestFile([c.resource]),
          });
          continue; // public route: do not assert a cross-tenant authorization break on it
        }
        for (const actor of actors) {
          const attacker = await get(url, actor.auth);
          const control = await get(controlUrl, actor.auth);
          const o = authzOracle({ attacker, owner, control, ownerMarkers: markers });
          if (o.verdict === "denied") continue;
          // A leak must hold on two more replays: a flaky route (a cache, a race)
          // is a lead, not a proof.
          const proven = o.verdict === "leak" && await stableLeak(() => get(url, actor.auth), owner, control, markers);
          const auth = replayAuth(actor.auth, actor.key);
          findings.push({
            id: `authz-matrix:${c.resource.name}:${c.method}:${c.id}${actor.key === "a" ? "" : `:${actor.key}`}`,
            check: "authz-matrix",
            title: proven
              ? `Account ${actor.key.toUpperCase()} reached account B's ${c.resource.name} (${c.method} ${attacker.status})`
              : `Possible cross-tenant access to ${c.resource.name} (${c.method} ${attacker.status}), not proven`,
            severity: proven ? "critical" : "medium",
            state: proven ? "proven" : "unproven",
            location: url,
            description: proven
              ? `With ${actor.who}, a ${c.method} on a ${c.resource.name} owned by account B returned B's object: ${o.reason}. This is broken object-level authorization.`
              : `With ${actor.who}, the server answered ${attacker.status} instead of denying, but the oracle could not prove the body is B's: ${o.reason}.`,
            remediation:
              `Enforce the ownership check at the data layer for ${c.resource.name}, for every caller including unauthenticated ones, ` +
              `and add the generated regression test so it can never return.`,
            proof: {
              method: "live cross-tenant replay on staging: owner baseline, attacker, negative control",
              replay: `curl -i -X ${c.method}${auth} '${url}'`,
              evidence: `HTTP ${attacker.status}; control ${control.status}${owner ? `; owner ${owner.status}` : ""}. ${o.reason}`,
            },
            regressionHint: renderTestFile([c.resource]),
          });
          if (proven) { provenIds.add(`${c.resource.name}:${c.id}`); break; } // one proof per object is enough
        }
      } catch (err) {
        ctx.log(`authz-matrix: ${c.method} ${url} failed: ${(err as Error).message}`);
      }
    }

    // Owner-id differential: when a resource carries an owner-id field and account
    // A owns an id of it, prove a cross-tenant read without B's token or a marker.
    // A reads a target id (another tenant's) and its OWN id; if the owner field
    // differs and a control does not answer the same way, A read an object it does
    // not own. Covers objects whose body names its owner (UserId, owner_id, ...).
    const aOwns = accounts.a?.owns ?? {};
    const field = (r: ResourceSpec) => r.ownerField!;
    const aAuth = hasAuth(accounts.a) ? accounts.a : undefined;
    // Read a resource by id over its transport: a GraphQL POST (object taken from
    // under `data`) when `gql` is set, else a REST GET. The attacker is A when a
    // token is configured, otherwise anonymous (unauthenticated APIs like DVGA).
    const readOwner = async (r: ResourceSpec, idOrRaw: string, raw = false): Promise<{ status: number; body: string }> => {
      if (r.gql) {
        const q = r.gql.replace(/:id/g, raw ? idOrRaw : JSON.stringify(idOrRaw).slice(1, -1));
        const res = await safeFetch(base + r.path, ctx.scope, { method: "POST", headers: { "content-type": "application/json", ...authHeaders(aAuth) }, body: JSON.stringify({ query: q }) }).then((x) => ({ status: x.status, body: x.body }));
        try { const j = JSON.parse(res.body); const obj = j?.data && typeof j.data === "object" ? Object.values(j.data)[0] : undefined; return { status: obj == null ? 404 : res.status, body: JSON.stringify(obj ?? null) }; } catch { return res; }
      }
      return get(base + r.path.replace(":id", raw ? idOrRaw : encodeURIComponent(idOrRaw)), aAuth);
    };
    for (const r of ownerFieldResources) {
      const targetIds = (r.probeIds ?? []).filter((id) => !provenIds.has(`${r.name}:${id}`));
      if (!targetIds.length) continue;
      try {
        const control = await readOwner(r, `crenel-nonexistent-${randomBytes(6).toString("hex")}`, true);
        // The attacker's own object (if declared) gives A's own owner-id, so a
        // target whose owner-id differs is provably not A's.
        let selfVal: string | undefined;
        const selfId = (aOwns[r.name] ?? [])[0];
        if (selfId !== undefined) selfVal = ownerValue((await readOwner(r, selfId)).body, field(r));
        // Read each target, keep the ones that return a 2xx carrying an owner-id.
        const seen: { id: string; url: string; status: number; val: string }[] = [];
        for (const id of targetIds) {
          const url = r.gql ? `${base}${r.path} ${r.name}(${id})` : base + r.path.replace(":id", encodeURIComponent(id));
          const res = await readOwner(r, id);
          if (res.status < 200 || res.status >= 300) continue;
          if (control.status >= 200 && control.status < 300 && control.body === res.body) continue; // generic page
          const val = ownerValue(res.body, field(r));
          if (val !== undefined) seen.push({ id, url, status: res.status, val });
        }
        const caller = aAuth ? "account A" : "an unauthenticated caller";
        const verb = r.gql ? "a GraphQL query" : "a GET";
        const prove = (id: string, url: string, status: number, reason: string) => {
          provenIds.add(`${r.name}:${id}`);
          findings.push({
            id: `authz-matrix:${r.name}:owner-field:${id}`, check: "authz-matrix",
            title: `${caller[0]!.toUpperCase() + caller.slice(1)} read a ${r.name} it does not own (${status}, owner-id ${field(r)})`,
            severity: "critical", state: "proven", location: url,
            description: `With ${caller}, ${verb} on ${r.name} ${id} returned an object whose ${field(r)} is not the caller's: ${reason}. This is broken object-level authorization (IDOR/BOLA).`,
            remediation: `Enforce the ownership check at the data layer for ${r.name}, comparing ${field(r)} to the caller's identity, and add the generated regression test.`,
            proof: {
              method: `live owner-id differential on staging: targets read as ${caller} over ${r.gql ? "GraphQL" : "REST"}, their owner-id field, negative control` + (selfVal !== undefined ? ", the attacker's own object" : ""),
              replay: r.gql ? `POST ${base}${r.path} with query ${r.gql.replace(":id", id)}` : `curl -i${replayAuth(aAuth, "a")} '${url}'`,
              evidence: `HTTP ${status}; control ${control.status}. ${reason}`,
            },
            regressionHint: renderTestFile([r]),
          });
        };
        if (selfVal !== undefined) {
          for (const s of seen) if (String(s.val) !== String(selfVal)) prove(s.id, s.url, s.status, `${field(r)}=${s.val}, while A's own object carries ${field(r)}=${selfVal}`);
        } else {
          // No self baseline: if A reads objects with >=2 distinct owner-ids, one
          // account cannot own them all, so at least one is a cross-tenant read.
          const distinct = [...new Set(seen.map((s) => s.val))];
          if (distinct.length >= 2) {
            const s = seen[0]!, other = seen.find((x) => x.val !== s.val)!;
            prove(s.id, s.url, s.status, `the caller also reads ${r.name} ${other.id} with ${field(r)}=${other.val}; one owner cannot hold both ${field(r)}=${s.val} and ${field(r)}=${other.val}, so at least one is read across owners`);
          }
        }
      } catch (err) {
        ctx.log(`authz-matrix: owner-field ${r.name} failed: ${(err as Error).message}`);
      }
    }

    // Ids that leak in B's own responses (XBOW's method): a project names its
    // renders, an invoice its customer. They are B's objects nobody declared, so
    // they are replayed too, under stricter conditions since ownership is
    // inferred: B must read it, an anonymous caller must not get the same body
    // (otherwise it is public), and the oracle must still see B's object in A's
    // response.
    if (accounts.b?.token && ownerBodies.length) {
      const declared = new Set(cases.map((c) => `${c.resource.name}:${c.id}`));
      const found = discoverIds(ownerBodies.join("\n"), resources.filter((r) => !r.public), b?.owns ?? {})
        .filter((d) => !declared.has(`${d.resource.name}:${d.id}`))
        .slice(0, MAX_DISCOVERED);
      if (found.length) ctx.log(`authz-matrix: ${found.length} id(s) of B discovered in B's responses, replayed`);
      for (const d of found) {
        const url = base + d.resource.path.replace(":id", encodeURIComponent(d.id));
        const controlUrl = base + d.resource.path.replace(":id", `crenel-nonexistent-${randomBytes(6).toString("hex")}`);
        try {
          ctx.scope.assertUrlAllowed(url);
          const owner = await get(url, accounts.b);
          if (owner.status < 200 || owner.status >= 300) continue; // not readable by B: not provably B's
          const anon = await get(url);
          if (anon.status >= 200 && anon.status < 300 && anon.body === owner.body) continue; // public object
          for (const actor of actors) {
            const attacker = await get(url, actor.auth);
            const control = await get(controlUrl, actor.auth);
            const o = authzOracle({ attacker, owner, control, ownerMarkers: markers });
            if (o.verdict !== "leak" || !(await stableLeak(() => get(url, actor.auth), owner, control, markers))) continue;
            findings.push({
              id: `authz-matrix:${d.resource.name}:GET:${d.id}${actor.key === "a" ? "" : `:${actor.key}`}:discovered`,
              check: "authz-matrix",
              title: `Account ${actor.key.toUpperCase()} reached account B's ${d.resource.name} (GET ${attacker.status}), id found in B's own data`,
              severity: "critical",
              state: "proven",
              location: url,
              description: `The id ${d.id} appeared in a response account B received, B can read it, an anonymous caller cannot, and with ${actor.who} the server returned B's object: ${o.reason}.`,
              remediation: `Enforce the ownership check on ${d.resource.name}, and declare ${d.id} (or ids like it) under accounts.b.owns so the regression test covers it.`,
              proof: {
                method: "live cross-tenant replay of an id discovered in the owner's response: owner baseline, anonymous check, attacker, negative control",
                replay: `curl -i${replayAuth(actor.auth, actor.key)} '${url}'`,
                evidence: `HTTP ${attacker.status}; owner ${owner.status}; anonymous ${anon.status}; control ${control.status}. ${o.reason}`,
              },
              regressionHint: renderTestFile([d.resource]),
            });
            break;
          }
        } catch (err) {
          ctx.log(`authz-matrix: GET ${url} failed: ${(err as Error).message}`);
        }
      }
    }

    ctx.log(`authz-matrix: ${findings.length} broken-authorization case(s) proven`);
    return findings;
  },
};

const MAX_DISCOVERED = 25;

/** Two more attacker replays must also be leaks for the finding to be proven. */
async function stableLeak(replay: () => Promise<{ status: number; body: string }>, owner: { status: number; body: string } | undefined, control: { status: number; body: string }, markers: string[]): Promise<boolean> {
  for (let i = 0; i < 2; i++) {
    if (authzOracle({ attacker: await replay(), owner, control, ownerMarkers: markers }).verdict !== "leak") return false;
  }
  return true;
}

/** Why two bearer tokens are the same identity (same string, or JWTs with the same sub), or null. */
export function sameIdentity(a?: string, b?: string): string | null {
  if (!a || !b) return null;
  if (a === b) return "are identical";
  const sub = (t: string) => { try { return (JSON.parse(Buffer.from(t.split(".")[1] ?? "", "base64url").toString("utf8")) as { sub?: string }).sub ?? null; } catch { return null; } };
  const sa = sub(a), sb = sub(b);
  return sa && sa === sb ? `carry the same subject (sub=${sa})` : null;
}
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;

/**
 * Ids in `text` that have the shape of a resource's declared ids: a UUID when B's
 * declared ids are UUIDs, the same prefix otherwise ("proj_" for "proj_b_1"). A
 * resource with no declared id has no known shape and is left out.
 */
export function discoverIds(text: string, resources: ResourceSpec[], owns: Record<string, string[]>): { resource: ResourceSpec; id: string }[] {
  const out: { resource: ResourceSpec; id: string }[] = [];
  const seen = new Set<string>();
  for (const r of resources) {
    const sample = owns[r.name]?.[0];
    if (!sample) continue;
    let re: RegExp | null = null;
    if (new RegExp(`^${UUID.source}$`, "i").test(sample)) re = new RegExp(UUID.source, "gi");
    else {
      const prefix = /^([A-Za-z]{2,12}[_-])/.exec(sample)?.[1];
      if (prefix) re = new RegExp(`\\b${prefix.replace(/[-]/g, "\\-")}[A-Za-z0-9_-]{2,64}\\b`, "g");
    }
    if (!re) continue;
    for (const m of text.matchAll(re)) {
      const key = `${r.name}:${m[0]}`;
      if (!seen.has(key)) { seen.add(key); out.push({ resource: r, id: m[0] }); }
    }
  }
  return out;
}

// Emit a framework-agnostic test skeleton the team can drop into its suite.
function renderTestFile(resources: ResourceSpec[]): string {
  const lines: string[] = [
    "// Generated by Crenel. Cross-tenant isolation invariant.",
    "// Fill in BASE_URL and two test accounts, then run in CI on every PR.",
    "import { test, expect } from 'vitest';",
    "",
    "const BASE_URL = process.env.STAGING_URL!;",
    "const A = process.env.TEST_TOKEN_A!; // account A's bearer token",
    "const B_OWNS = {",
  ];
  for (const r of resources) lines.push(`  ${JSON.stringify(r.name)}: [/* ids owned by B */],`);
  lines.push("};", "");
  for (const r of resources) {
    const methods = r.methods ?? ["GET"];
    for (const method of methods) {
      lines.push(
        `test('A cannot ${method} another account\\'s ${r.name}', async () => {`,
        `  for (const id of B_OWNS[${JSON.stringify(r.name)}] ?? []) {`,
        `    const res = await fetch(BASE_URL + ${JSON.stringify(r.path)}.replace(':id', id), {`,
        `      method: ${JSON.stringify(method)},`,
        "      headers: { authorization: `Bearer ${A}` },",
        "    });",
        "    expect([401, 403, 404]).toContain(res.status);",
        "  }",
        "});",
        "",
      );
    }
  }
  return lines.join("\n");
}
