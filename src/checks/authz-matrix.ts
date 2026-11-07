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
import { safeFetch } from "../core/net.js";

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
}

interface AuthzOptions {
  resources?: ResourceSpec[];
  accounts?: { a?: AccountSpec; b?: AccountSpec };
}

const DENY = new Set([401, 403, 404]);

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
    const tokenA = cfg.accounts!.a!.token!;

    for (const c of cases) {
      const url = base + c.resource.path.replace(":id", encodeURIComponent(c.id));
      ctx.scope.assertUrlAllowed(url);
      let status = 0;
      try {
        const res = await safeFetch(url, ctx.scope, {
          method: c.method,
          headers: { authorization: `Bearer ${tokenA}` },
        });
        status = res.status;
      } catch (err) {
        ctx.log(`authz-matrix: ${c.method} ${url} failed: ${(err as Error).message}`);
        continue;
      }
      const proven = !DENY.has(status) && status < 500;
      if (proven) {
        findings.push({
          id: `authz-matrix:${c.resource.name}:${c.method}:${c.id}`,
          check: "authz-matrix",
          title: `Account A reached account B's ${c.resource.name} (${c.method} ${status})`,
          severity: "critical",
          state: "proven",
          location: url,
          description:
            `Test account A used its own token to ${c.method} a ${c.resource.name} owned by ` +
            `account B and the server answered ${status} instead of denying (401/403/404). ` +
            `This is broken object-level authorization.`,
          remediation:
            `Enforce the ownership check at the data layer for ${c.resource.name}, not only in the UI, ` +
            `and add the generated regression test so it can never return.`,
          proof: {
            method: "live cross-tenant request on staging with account A's token",
            replay: `curl -i -X ${c.method} -H 'authorization: Bearer <A_TOKEN>' '${url}'`,
            evidence: `HTTP ${status} (expected 401/403/404)`,
          },
          regressionHint: renderTestFile([c.resource]),
        });
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
