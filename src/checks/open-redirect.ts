// open-redirect: a login, logout or callback route that redirects to whatever
// URL a parameter names. On a SaaS it is the phishing link that starts on your
// real domain, and in OAuth flows a way to steal codes and tokens. We request
// the usual routes with the usual parameter names pointing at a sentinel host
// under .invalid (a TLD that never resolves), read the redirect without
// following it, and prove the flaw when Location points at the sentinel.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

const SENTINEL = "https://crenel-redirect-check.invalid/landing";
const PATHS = ["/", "/login", "/signin", "/logout", "/auth/callback", "/redirect"];
const PARAMS = ["redirect", "redirect_uri", "redirectTo", "next", "returnTo", "return_to", "callbackUrl", "continue", "url"];

export const openRedirect: Check = {
  name: "open-redirect",
  title: "Redirect to any URL from a request parameter (open redirect)",
  readOnly: true, // GETs on the declared host; the redirect is read, never followed
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options["open-redirect"] ?? {}) as { paths?: string[]; params?: string[] };
    const findings: Finding[] = [];
    for (const path of opts.paths ?? PATHS) {
      for (const param of opts.params ?? PARAMS) {
        const url = `${base}${path}?${param}=${encodeURIComponent(SENTINEL)}`;
        let res;
        try { res = await safeFetch(url, ctx.scope, { followRedirects: false }); } catch { continue; }
        const loc = res.headers.get("location") ?? "";
        const meta = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)/i.exec(res.body)?.[1] ?? "";
        const target = (res.status >= 300 && res.status < 400 ? loc : "") || meta;
        let host = "";
        try { host = new URL(target, url).hostname; } catch { continue; }
        if (host !== "crenel-redirect-check.invalid") continue;
        findings.push({
          id: `open-redirect:${path}:${param}`,
          check: "open-redirect",
          title: `Open redirect on ${path} via ?${param}=`,
          severity: "medium",
          state: "proven",
          location: `${base}${path}`,
          description: `GET ${path}?${param}=<any URL> answers with a redirect to that URL (${res.status}${meta && !loc ? ", meta refresh" : ""}). A link on your own domain can send users to a phishing page, or leak OAuth codes to another host.`,
          remediation: `Only redirect to relative paths or to an allowlist of your own hosts; reject absolute URLs and protocol-relative ones (//host) in ${param}.`,
          proof: { method: "GET with a sentinel URL under .invalid, redirect read without following it", replay: `curl -sI '${url}' | grep -i '^location'`, evidence: `HTTP ${res.status}, Location: ${target}` },
          regressionHint: `${path}?${param}=https://example.invalid must not redirect off-site.`,
        });
        break; // one parameter per path is enough proof
      }
    }
    ctx.log(`open-redirect: ${findings.length} finding(s)`);
    return findings;
  },
};
