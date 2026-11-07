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
    for (const c of cases) {
      if (c.method !== "GET") { ctx.log(`authz-matrix: ${c.method} ${c.resource.path} skipped, only GET is probed live`); continue; }
      const url = base + c.resource.path.replace(":id", encodeURIComponent(c.id));
      const controlUrl = base + c.resource.path.replace(":id", `crenel-nonexistent-${randomBytes(6).toString("hex")}`);
      ctx.scope.assertUrlAllowed(url);
      try {
        const owner = accounts.b?.token ? await get(url, accounts.b.token) : undefined;
        for (const actor of actors) {
          const attacker = await get(url, actor.token);
          const control = await get(controlUrl, actor.token);
          const o = authzOracle({ attacker, owner, control, ownerMarkers: markers });
          if (o.verdict === "denied") continue;
          const proven = o.verdict === "leak";
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

    ctx.log(`authz-matrix: ${findings.length} broken-authorization case(s) proven`);
    return findings;
  },
};

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
