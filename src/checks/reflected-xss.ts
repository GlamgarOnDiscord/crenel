// reflected-xss: a request parameter is echoed back into an HTML response without
// escaping, so an attacker's markup runs in the victim's browser. Proven without a
// browser: a unique nonce wrapped in HTML-breaking markup comes back verbatim and
// UNESCAPED in an HTML-content response, while a benign value does not and an
// escaped reflection is only a lead (not proven). Generic — the oracle is the raw
// reflection, no target signature; the control removes pages that always contain
// the markup. Reflected only; stored/DOM XSS need a browser and are out of scope.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { xssOracle, nonce } from "../agent/inject.js";

const PATHS = ["/", "/search", "/q", "/find", "/error", "/result", "/page"];
const PARAMS = ["q", "query", "search", "s", "name", "message", "msg", "redirect", "returnUrl", "lang", "keyword", "term"];

export const reflectedXss: Check = {
  name: "reflected-xss",
  title: "Reflected XSS: a parameter echoed unescaped into an HTML response",
  readOnly: true, // GETs on the declared host
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options["reflected-xss"] ?? {}) as { paths?: string[]; params?: string[] };
    const get = async (p: string) => { try { const r = await safeFetch(base + p, ctx.scope, { headers: { accept: "text/html" }, maxBytes: 128 * 1024 }); return { status: r.status, body: r.body, ct: (r.headers.get("content-type") ?? "").toLowerCase() }; } catch { return { status: 0, body: "", ct: "" }; } };
    const findings: Finding[] = [];
    for (const path of opts.paths ?? PATHS) {
      for (const param of opts.params ?? PARAMS) {
        const t = nonce(param);
        const payload = `<svg/onload=1>${t}`;
        const res = await get(`${path}?${param}=${encodeURIComponent(payload)}`);
        // Only an HTML response can carry reflected markup that executes. XSS runs
        // in an HTML document; a generic XML response is not a browsing context, so
        // it is excluded to avoid a false "executable XSS" on an XML endpoint.
        if (!/html|xhtml/.test(res.ct)) continue;
        const r = xssOracle({ token: t, body: res.body, status: res.status });
        // The oracle's generic raw forms include token-less shapes (a bare
        // `<svg/onload=1>`), so a page that already contains such markup could pass
        // while only an escaped nonce is reflected. Require OUR exact, nonce-bearing
        // payload to come back verbatim and unescaped: that string cannot pre-exist.
        if (r.verdict !== "proven" || !res.body.includes(payload)) continue;
        // Control: a benign value must NOT bring the raw markup back (so the page
        // does not simply always contain it). A failed control proves nothing, so
        // fail closed: only trust a control request that actually answered.
        const clean = await get(`${path}?${param}=crenelbenign`);
        if (!(clean.status >= 200 && clean.status < 300)) continue;
        if (clean.body.includes("<svg/onload=1>")) continue;
        findings.push({
          id: `reflected-xss:${path}:${param}`,
          check: "reflected-xss",
          title: `Reflected XSS on ${path} via ?${param}=`,
          severity: "high",
          state: "proven",
          location: `${base}${path}`,
          description: `The ${param} parameter on ${path} is echoed into the HTML response unescaped (${r.reason}), while a benign value is not. An attacker's script runs in the victim's browser.`,
          remediation: "Context-aware output encoding for any request value placed in HTML; set a Content-Security-Policy that forbids inline script.",
          proof: { method: "live differential on staging: an HTML-breaking nonce reflected unescaped vs a benign value", replay: `curl -s '${base}${path}?${param}=%3Csvg/onload=1%3E'`, evidence: r.reason },
          regressionHint: `After deploy, ?${param}= at ${path} must not reflect HTML markup unescaped.`,
        });
      }
    }
    if (findings.length === 0) ctx.log("reflected-xss: no unescaped reflection found");
    return findings;
  },
};
