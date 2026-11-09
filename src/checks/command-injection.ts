// command-injection: prove OS-command or template/expression injection on a
// declared sink the deterministic way — by a computation the server could only
// produce if it evaluated the payload. The check injects `<nonce>` next to a
// shell/template arithmetic (7*7) through generic break-outs; proof is the nonce
// immediately followed by the product (49) in the response, which cannot be a
// coincidence. The sink (a GraphQL argument via __INJECT__, or a JSON body field)
// is config; the payloads and the oracle are generic, no target signature.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { templateOracle, nonce } from "../agent/inject.js";

interface CmdEndpoint {
  url: string;
  method?: string;
  /** GraphQL: a query/mutation string with __INJECT__ where the payload goes. */
  gql?: string;
  /** REST: a JSON body with __INJECT__ where the payload goes (whole body string). */
  body?: string;
  /** Account token id (options.authz-matrix.accounts[as].token) if the sink needs auth. */
  as?: string;
}

// Generic break-outs: a shell command separator or a template expression, each
// wrapping the same arithmetic. T is replaced by the nonce, 7*7 evaluates to 49.
const FORMS = [
  "; echo T$((7*7))", "| echo T$((7*7))", "$(echo T$((7*7)))", "`echo T$((7*7))`", "&& echo T$((7*7))",
  "T${7*7}", "T{{7*7}}", "T#{7*7}", "T<%= 7*7 %>",
];

export const commandInjection: Check = {
  name: "command-injection",
  title: "OS-command / template injection on a declared sink (computed proof)",
  readOnly: false, // sends payloads that run on the server: active gate
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["command-injection"] ?? {}) as { enabled?: boolean; endpoints?: CmdEndpoint[] };
    if (o.enabled !== true || !ctx.stagingUrl || !(o.endpoints?.length)) return [];
    ctx.scope.assertActiveAllowed("command-injection (payloads that run on the server)");
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    const accounts = ((ctx.options["authz-matrix"] ?? {}) as { accounts?: Record<string, { token?: string }> }).accounts ?? {};
    const findings: Finding[] = [];
    for (const ep of o.endpoints) {
      const url = ep.url.startsWith("http") ? ep.url : base + ep.url;
      if (!ctx.scope.isHostAllowed(url)) continue;
      const token = ep.as ? accounts[ep.as]?.token : undefined;
      const headers: Record<string, string> = { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) };
      const tmpl = ep.gql ? JSON.stringify({ query: ep.gql }) : (ep.body ?? "");
      if (!tmpl.includes("__INJECT__")) { ctx.log(`command-injection: ${ep.url} has no __INJECT__ marker`); continue; }
      let proof: { reason: string; form: string } | null = null;
      for (const form of FORMS) {
        const t = nonce("cmd");
        const payload = form.replace("T", t).replace(/"/g, '\\"');
        const body = tmpl.replace(/__INJECT__/g, payload);
        try {
          const res = await safeFetch(url, ctx.scope, { method: ep.method ?? "POST", headers, body, maxBytes: 128 * 1024 });
          const r = templateOracle({ token: t, product: "49", body: res.body });
          if (r.verdict === "proven") { proof = { reason: r.reason, form: form.trim() }; break; }
        } catch { /* next form */ }
      }
      if (!proof) { ctx.log(`command-injection: ${ep.url} not injectable`); continue; }
      const os = /\$\(\(|echo|`|\|\||&&|;|\|/.test(proof.form);
      findings.push({
        id: `command-injection:${ep.url}`,
        check: "command-injection",
        title: `${os ? "OS command" : "Template"} injection at ${ep.url} (${proof.form})`,
        severity: "critical",
        state: "proven",
        location: url,
        description: `The sink at ${ep.url} evaluated an injected expression: ${proof.reason}. ${os ? "User input reaches a shell" : "User input reaches a template engine"}, allowing arbitrary code execution.`,
        remediation: `Never pass user input to a shell or template engine; use a fixed command with argument arrays, or a sandboxed template with no expression evaluation.`,
        proof: {
          method: "live computed differential on staging: a nonce placed next to 7*7; the response carries nonce+49, impossible unless the server evaluated it",
          replay: `send ${ep.method ?? "POST"} ${url} with the payload '<nonce>${proof.form}' in the sink`,
          evidence: proof.reason,
        },
        regressionHint: `After deploy, an injected 7*7 next to a nonce at ${ep.url} must not come back as nonce49.`,
      });
    }
    return findings;
  },
};
