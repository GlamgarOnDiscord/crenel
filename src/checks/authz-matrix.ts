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

import type { Check, CheckContext, Finding } from "../core/types.js";
import { randomBytes } from "node:crypto";
import { safeFetch } from "../core/net.js";
import { authzOracle } from "../agent/validators.js";

interface ResourceSpec {
  /** e.g. "project" */
  name: string;
  /** URL path template with :id, e.g. "/api/projects/:id" */
  path: string;
  /** HTTP methods to test for isolation. GET only by default (read-only). */
  methods?: string[];
  /** Public by design (a trust boundary): never probed, never reported. */
  public?: boolean;
}

interface AccountSpec {
  label: string;
  /** Bearer token for this test account (staging only). */
  token?: string;
  /** Resource ids that belong to this account, keyed by resource name. */
  owns?: Record<string, string[]>;
  /** A string only B's objects contain (an email, an org id): proof the body is B's. */
  marker?: string;
}

interface AuthzOptions {
  resources?: ResourceSpec[];
  accounts?: { a?: AccountSpec; b?: AccountSpec; c?: AccountSpec };
}


export const authzMatrix: Check = {
  name: "authz-matrix",
  title: "Cross-tenant authorization (an account must never reach another's data)",
  readOnly: true, // matrix generation is read-only; live probes are gated separately
  async run(ctx: CheckContext): Promise<Finding[]> {
    const cfg = (ctx.options["authz-matrix"] ?? {}) as AuthzOptions;
    const resources = cfg.resources ?? [];
    const findings: Finding[] = [];

    if (resources.length === 0) {
      ctx.log("authz-matrix: no resources declared, nothing to check");
      return findings;
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

    const canProbe =
      !!ctx.stagingUrl && !!cfg.accounts?.a?.token && cases.length > 0;

    if (!canProbe) {
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
    const accounts = cfg.accounts!;
    const markers = [accounts.b?.marker ?? ""].filter(Boolean);
    // Distinct contexts (Teycir's guard): if A and B are the same account, every
    // "cross-tenant" read is just B reading its own object. Refuse to prove anything.
    const same = sameIdentity(accounts.a?.token, accounts.b?.token);
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
    const get = (url: string, token?: string) =>
      safeFetch(url, ctx.scope, { method: "GET", headers: token ? { authorization: `Bearer ${token}` } : {} })
        .then((r) => ({ status: r.status, body: r.body }));

    // Same oracle as the agent's validator: a 200 is not proof. The attacker's
    // body must be the owner's object, and a negative control (an id that does
    // not exist) must not answer the same way. Each case is tried with A's
    // token, C's if declared, then with no token at all: a route can refuse a
    // wrong token and still serve an anonymous caller.
    const actors: { key: "a" | "c" | "anon"; who: string; token?: string }[] = [
      { key: "a", who: "account A's token", token: accounts.a!.token },
      ...(accounts.c?.token ? [{ key: "c" as const, who: "account C's token (another tenant)", token: accounts.c.token }] : []),
      { key: "anon", who: "no token at all" },
    ];
    const ownerBodies: string[] = [];
    for (const c of cases) {
      if (c.method !== "GET") { ctx.log(`authz-matrix: ${c.method} ${c.resource.path} skipped, only GET is probed live`); continue; }
      const url = base + c.resource.path.replace(":id", encodeURIComponent(c.id));
      const controlUrl = base + c.resource.path.replace(":id", `crenel-nonexistent-${randomBytes(6).toString("hex")}`);
      ctx.scope.assertUrlAllowed(url);
      try {
        const owner = accounts.b?.token ? await get(url, accounts.b.token) : undefined;
        if (owner && owner.status >= 200 && owner.status < 300) ownerBodies.push(owner.body);
        for (const actor of actors) {
          const attacker = await get(url, actor.token);
          const control = await get(controlUrl, actor.token);
          const o = authzOracle({ attacker, owner, control, ownerMarkers: markers });
          if (o.verdict === "denied") continue;
          // A leak must hold on two more replays: a flaky route (a cache, a race)
          // is a lead, not a proof.
          const proven = o.verdict === "leak" && await stableLeak(() => get(url, actor.token), owner, control, markers);
          const auth = actor.token ? ` -H 'authorization: Bearer <${actor.key.toUpperCase()}_TOKEN>'` : "";
          findings.push({
            id: `authz-matrix:${c.resource.name}:${c.method}:${c.id}${actor.key === "a" ? "" : `:${actor.key}`}`,
            check: "authz-matrix",
            title: proven
              ? `${actor.key === "anon" ? "An anonymous caller" : `Account ${actor.key.toUpperCase()}`} reached account B's ${c.resource.name} (${c.method} ${attacker.status})`
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
          if (proven) break; // one proof per object is enough
        }
      } catch (err) {
        ctx.log(`authz-matrix: ${c.method} ${url} failed: ${(err as Error).message}`);
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
          const owner = await get(url, accounts.b.token);
          if (owner.status < 200 || owner.status >= 300) continue; // not readable by B: not provably B's
          const anon = await get(url);
          if (anon.status >= 200 && anon.status < 300 && anon.body === owner.body) continue; // public object
          for (const actor of actors.filter((x) => x.key !== "anon")) {
            const attacker = await get(url, actor.token);
            const control = await get(controlUrl, actor.token);
            const o = authzOracle({ attacker, owner, control, ownerMarkers: markers });
            if (o.verdict !== "leak" || !(await stableLeak(() => get(url, actor.token), owner, control, markers))) continue;
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
                replay: `curl -i -H 'authorization: Bearer <${actor.key.toUpperCase()}_TOKEN>' '${url}'`,
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
