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
  /** The field to inject (e.g. "email", "username"). Ignored when `gql` is set. */
  field?: string;
  /** GraphQL sink: a query string with __INJECT__ where the value goes, e.g.
   * `{ pastes(filter: "__INJECT__") { id } }`. The payload is injected into the
   * string argument; the same SQL oracle decides (error-based or bypass). NoSQL
   * operator objects do not apply to a string argument, so they are skipped. */
  gql?: string;
  /** Other body fields to send unchanged (e.g. {password:"x"}). */
  template?: Record<string, unknown>;
  /** HTTP method. Default POST. */
  method?: string;
  /** Also try NoSQL operator injection ({field:{$ne:...}}). Default true. */
  nosql?: boolean;
  /** Send this account's bearer token (from options.authz-matrix.accounts[as].token)
   * when the endpoint is behind auth, e.g. an authenticated coupon/lookup API. */
  as?: string;
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
      const accounts = ((ctx.options["authz-matrix"] ?? {}) as { accounts?: Record<string, { token?: string }> }).accounts ?? {};
      const token = ep.as ? accounts[ep.as]?.token : undefined;
      const authHeader: Record<string, string> = token ? { authorization: `Bearer ${token}` } : {};
      const sink = ep.gql ? "gql-arg" : ep.field;
      if (!sink) { ctx.log(`auth-injection: ${ep.url} needs a field or a gql sink`); continue; }
      const send = async (fieldVal: unknown, extra?: Record<string, unknown>) => {
        const body = ep.gql
          ? JSON.stringify({ query: ep.gql.replace(/__INJECT__/g, String(fieldVal).replace(/"/g, '\\"')) })
          : JSON.stringify({ ...(ep.template ?? {}), ...extra, [ep.field!]: fieldVal });
        const r = await safeFetch(url, ctx.scope, { method, headers: { "content-type": "application/json", ...authHeader }, body, maxBytes: 256 * 1024 });
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
        // NoSQL operator objects only make sense for a JSON field, not a string arg.
        if (!proof && !ep.gql && ep.nosql !== false) {
          const truthy = await send({ $ne: benign });
          const falsy = await send({ $eq: benign });
          const v = nosqlOracle({ baseline, truthy, falsy });
          if (v.verdict === "proven") proof = v;
        }
        if (!proof) { ctx.log(`auth-injection: ${sink} at ${ep.url} not injectable`); continue; }
        // Name the flaw by the proof's actual kind so a NoSQL finding never reads
        // as "SQL injection" (and vice-versa): the two are distinct weaknesses.
        const kind = proof.kind.toLowerCase().startsWith("nosql") ? "NoSQL injection" : "SQL injection";
        const where = ep.gql ? `the GraphQL argument of ${ep.url}` : `the ${sink} field of ${ep.url}`;
        findings.push({
          id: `auth-injection:${sink}:${ep.url}`,
          check: "auth-injection",
          title: `${kind} in ${sink} at ${ep.url} (${proof.kind})`,
          severity: "critical",
          state: "proven",
          location: url,
          description: `${where[0]!.toUpperCase() + where.slice(1)} is injectable (${kind}): ${proof.reason}. An attacker bypasses authentication or the lookup filter.`,
          remediation: `Use parameterized queries for ${sink}; never build the ${kind.startsWith("NoSQL") ? "document-store filter" : "SQL query"} by string concatenation, and reject operator objects where a scalar is expected.`,
          proof: {
            method: "live differential on staging: benign baseline, always-true probe, always-false probe (control)",
            replay: ep.gql
              ? `POST ${url} with query ${ep.gql.replace(/__INJECT__/g, "<benign>' OR '1'='1")}`
              : kind.startsWith("NoSQL")
                ? `curl -i -X ${method} -H 'content-type: application/json' --data '{"${sink}":{"$gt":""}}' '${url}'`
                : `curl -i -X ${method} -H 'content-type: application/json' --data '{"${sink}":"<benign>' OR '1'='1"}' '${url}'`,
            evidence: `baseline HTTP ${baseline.status}; ${proof.reason}`,
          },
          regressionHint: `After deploy, an always-true probe in ${sink} at ${ep.url} must not be accepted where a benign value is denied.`,
        });
      } catch (err) {
        ctx.log(`auth-injection: ${ep.url} failed: ${(err as Error).message}`);
      }
    }
    return findings;
  },
};
