// auth-injection: a login / lookup endpoint whose declared field is injectable
// with a SQL or NoSQL authentication bypass. The classic break: a tautology in
// the username/email field (' OR 1=1-- , or a {"$ne":null} operator) turns a
// failed login into a success. This is a deterministic, reproducible floor check
// (no model): the operator declares the endpoint, the field to inject and a body
// template for the other fields; the check sends a benign baseline, a TRUE
// tautology and a FALSE tautology, and the generic oracles in inject.ts decide
// (TRUE accepted where the literal value and the FALSE tautology are denied, or a
// new database / document-store error). No target signature; the payloads are
// generic and the proof is the differential with a control.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { sqliOracle, nosqlOracle, nonce } from "../agent/inject.js";

interface AuthInjectEndpoint {
  /** Path or absolute URL of the auth/lookup endpoint. */
  url: string;
  /** The field to inject (e.g. "email", "username"). */
  field: string;
  /** Other body fields to send unchanged (e.g. {password:"x"}). */
  template?: Record<string, unknown>;
  /** HTTP method. Default POST. */
  method?: string;
  /** Also try NoSQL operator injection ({field:{$ne:...}}). Default true. */
  nosql?: boolean;
}

// Generic SQL tautology pairs (TRUE / FALSE), tried in order. The FALSE member is
// the control: it must be denied for the TRUE one to prove anything.
const SQL_PAIRS: [string, string][] = [
  ["' OR 1=1-- ", "' AND 1=2-- "],
  ["' OR '1'='1", "' AND '1'='2"],
  ["') OR ('1'='1", "') AND ('1'='2"],
  ['" OR "1"="1', '" AND "1"="2'],
];

export const authInjection: Check = {
  name: "auth-injection",
  title: "Authentication bypass by SQL / NoSQL injection on a login field",
  readOnly: false, // sends crafted auth attempts: gated by active mode
  async run(ctx: CheckContext): Promise<Finding[]> {
    const cfg = (ctx.options["auth-injection"] ?? {}) as { endpoints?: AuthInjectEndpoint[] };
    const endpoints = cfg.endpoints ?? [];
    if (!ctx.stagingUrl || endpoints.length === 0) {
      if (endpoints.length) ctx.log("auth-injection: no staging URL");
      return [];
    }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertActiveAllowed("auth-injection (crafted login attempts)");
    const findings: Finding[] = [];
    for (const ep of endpoints) {
      const url = ep.url.startsWith("http") ? ep.url : base + ep.url;
      if (!ctx.scope.isHostAllowed(url)) continue;
      const method = ep.method ?? "POST";
      const send = async (fieldVal: unknown, extra?: Record<string, unknown>) => {
        const body = JSON.stringify({ ...(ep.template ?? {}), ...extra, [ep.field]: fieldVal });
        const r = await safeFetch(url, ctx.scope, { method, headers: { "content-type": "application/json" }, body, maxBytes: 256 * 1024 });
        return { status: r.status, body: r.body };
      };
      try {
        const benign = "crenel-" + nonce();
        const baseline = await send(benign);
        let proof: { kind: string; reason: string } | null = null;
        for (const [t, f] of SQL_PAIRS) {
          const truthy = await send(benign + t);
          const falsy = await send(benign + f);
          const v = sqliOracle({ baseline, truthy, falsy });
          if (v.verdict === "proven") { proof = v; break; }
        }
        if (!proof && ep.nosql !== false) {
          const truthy = await send({ $ne: benign });
          const falsy = await send({ $eq: benign });
          const v = nosqlOracle({ baseline, truthy, falsy });
          if (v.verdict === "proven") proof = v;
        }
        if (!proof) { ctx.log(`auth-injection: ${ep.field} at ${ep.url} not injectable`); continue; }
        findings.push({
          id: `auth-injection:${ep.field}:${ep.url}`,
          check: "auth-injection",
          title: `SQL/NoSQL injection in ${ep.field} at ${ep.url} (${proof.kind})`,
          severity: "critical",
          state: "proven",
          location: url,
          description: `The ${ep.field} field of ${ep.url} is injectable: ${proof.reason}. An attacker bypasses authentication or the lookup filter. SQL injection / broken authentication.`,
          remediation: `Use parameterized queries for ${ep.field}; never build the auth query by string concatenation, and reject operator objects where a scalar is expected.`,
          proof: {
            method: "live differential on staging: benign baseline, TRUE tautology, FALSE tautology (control)",
            replay: `curl -i -X ${method} -H 'content-type: application/json' --data '{"${ep.field}":"<benign>\\' OR 1=1-- "}' '${url}'`,
            evidence: `baseline HTTP ${baseline.status}; ${proof.reason}`,
          },
          regressionHint: `After deploy, a tautology in ${ep.field} at ${ep.url} must not be accepted where a benign value is denied.`,
        });
      } catch (err) {
        ctx.log(`auth-injection: ${ep.url} failed: ${(err as Error).message}`);
      }
    }
    return findings;
  },
};
