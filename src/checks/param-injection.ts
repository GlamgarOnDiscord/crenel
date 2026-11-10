// param-injection: a GET endpoint whose URL carries the injectable value — a path
// segment (/users/v1/:username, /products/:id) or a query parameter (?q=, ?sort=).
// auth-injection covers a POST body field; a very large class of SQL/NoSQL breaks
// live in the URL instead (the id or lookup term concatenated into the query), and
// a body-oriented probe never reaches them. Same proof as auth-injection: a benign
// baseline, a TRUE tautology and a FALSE tautology placed in the URL value, decided
// by the generic sqliOracle (TRUE behaves like the baseline, FALSE diverges, or a
// new database error surfaces). No target string; the payloads are generic and the
// proof is the differential with a control.
//
// Crafted injection attempts: gated by active mode, like auth-injection.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { sqliOracle } from "../agent/inject.js";

interface ParamEndpoint {
  /** Path or absolute URL. A `:name` placeholder marks a path segment to inject;
   * otherwise the query parameter `param` is injected (added if absent). */
  url: string;
  /** The parameter to inject: the `:name` placeholder in `url`, or a query key. */
  param: string;
  /** A benign value that returns a real object (the payloads are appended to it). */
  baseline: string;
  /** HTTP method. Default GET. */
  method?: string;
  /** Send this account's bearer token (from options.authz-matrix.accounts[as].token). */
  as?: string;
}

// Generic SQL tautology pairs (TRUE / FALSE). The FALSE member is the control: it
// must diverge for the TRUE one to prove anything. Same set as auth-injection.
const SQL_PAIRS: [string, string][] = [
  ["' OR '1'='1", "' AND '1'='2"],
  ["' OR 1=1-- ", "' AND 1=2-- "],
  ['" OR "1"="1', '" AND "1"="2'],
  [") OR ('1'='1", ") AND ('1'='2"],
];

/** Place `value` into `url` at `param`: a `:param` path segment, else query `param`. */
function placeValue(url: string, param: string, value: string): string {
  if (url.includes(`:${param}`)) return url.replace(`:${param}`, encodeURIComponent(value));
  const [path, q = ""] = url.split("?", 2);
  const params = new URLSearchParams(q);
  params.set(param, value);
  return `${path}?${params.toString()}`;
}

export const paramInjection: Check = {
  name: "param-injection",
  title: "SQL / NoSQL injection in a URL path or query parameter (GET lookup)",
  readOnly: false, // sends crafted GETs with injected values: gated by active mode
  async run(ctx: CheckContext): Promise<Finding[]> {
    const cfg = (ctx.options["param-injection"] ?? {}) as { endpoints?: ParamEndpoint[] };
    const endpoints = cfg.endpoints ?? [];
    if (!ctx.stagingUrl || endpoints.length === 0) {
      if (endpoints.length) ctx.log("param-injection: no staging URL");
      return [];
    }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertActiveAllowed("param-injection (crafted URL injection)");
    const accounts = ((ctx.options["authz-matrix"] ?? {}) as { accounts?: Record<string, { token?: string }> }).accounts ?? {};
    const findings: Finding[] = [];
    for (const ep of endpoints) {
      if (!ep.url || !ep.param || ep.baseline === undefined) { ctx.log("param-injection: an endpoint needs url, param and baseline"); continue; }
      const absBase = ep.url.startsWith("http") ? ep.url : base + (ep.url.startsWith("/") ? ep.url : "/" + ep.url);
      const token = ep.as ? accounts[ep.as]?.token : undefined;
      const method = ep.method ?? "GET";
      const headers: Record<string, string> = token ? { authorization: `Bearer ${token}` } : {};
      const send = async (value: string) => {
        const url = placeValue(absBase, ep.param, value);
        if (!ctx.scope.isHostAllowed(url)) throw new Error(`host not allowed: ${url}`);
        const r = await safeFetch(url, ctx.scope, { method, headers, maxBytes: 256 * 1024 });
        return { status: r.status, body: r.body };
      };
      try {
        const baseline = await send(ep.baseline);
        let proof: { kind: string; reason: string } | null = null;
        for (const [t, f] of SQL_PAIRS) {
          const truthy = await send(ep.baseline + t);
          const falsy = await send(ep.baseline + f);
          const v = sqliOracle({ baseline, truthy, falsy });
          if (v.verdict === "proven") { proof = v; break; }
        }
        if (!proof) { ctx.log(`param-injection: ${ep.param} at ${ep.url} not injectable`); continue; }
        findings.push({
          id: `param-injection:${ep.param}:${ep.url}`,
          check: "param-injection",
          title: `SQL injection in the ${ep.param} URL parameter at ${ep.url} (${proof.kind})`,
          severity: "critical",
          state: "proven",
          location: absBase,
          description: `The ${ep.param} value in the URL of ${ep.url} is injectable: ${proof.reason}. The value is concatenated into the query, so an attacker reads or alters data by crafting the ${ep.param} in the URL.`,
          remediation: `Use a parameterized query for ${ep.param}; never concatenate a path segment or query parameter into SQL. Validate the value against its expected type before the lookup.`,
          proof: {
            method: "live differential on staging: benign baseline, always-true probe, always-false probe (control) placed in the URL parameter",
            replay: `curl -i '${placeValue(absBase, ep.param, ep.baseline + "' OR '1'='1")}'`,
            evidence: `baseline HTTP ${baseline.status}; ${proof.reason}`,
          },
          regressionHint: `After deploy, an always-true probe in the ${ep.param} URL parameter at ${ep.url} must not behave like the benign value where an always-false probe diverges.`,
        });
      } catch (err) {
        ctx.log(`param-injection: ${ep.url} failed: ${(err as Error).message}`);
      }
    }
    return findings;
  },
};
