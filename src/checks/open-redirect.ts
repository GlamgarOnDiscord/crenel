// open-redirect: a login, logout or callback route that redirects to whatever
// URL a parameter names. On a SaaS it is the phishing link that starts on your
// real domain, and in OAuth flows a way to steal codes and tokens. We request
// the usual routes with the usual parameter names pointing at a sentinel host
// under .invalid (a TLD that never resolves), read the redirect without
// following it, and prove the flaw when Location points at the sentinel.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { randomBytes } from "node:crypto";

const PATHS = ["/", "/login", "/signin", "/logout", "/auth/callback", "/redirect"];
const PARAMS = ["redirect", "redirect_uri", "redirectTo", "next", "returnTo", "return_to", "callbackUrl", "continue", "url", "to"];

const sentinels = (): [string, string] => [`https://crenel-redirect-${randomBytes(8).toString("hex")}.invalid/landing`, `https://crenel-redirect-${randomBytes(8).toString("hex")}.invalid/landing`];

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
        const [s1, s2] = sentinels();
        const probe = async (sentinel: string) => {
          const url = `${base}${path}?${param}=${encodeURIComponent(sentinel)}`;
          const res = await safeFetch(url, ctx.scope, { followRedirects: false });
          const loc = res.headers.get("location") ?? "";
          const meta = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)/i.exec(res.body)?.[1] ?? "";
          const target = (res.status >= 300 && res.status < 400 ? loc : "") || meta;
          return { url, res, target };
        };
        let a, b;
        try { a = await probe(s1); b = await probe(s2); } catch { continue; }
        if (!a || !b) continue;
        const reflected = (p: typeof a, sentinel: string) => {
          try { return new URL(p.target, p.url).hostname === new URL(sentinel).hostname; } catch { return false; }
        };
        if (!reflected(a, s1) || !reflected(b, s2)) continue;
        findings.push({
          id: `open-redirect:${path}:${param}`,
          check: "open-redirect",
          title: `Open redirect on ${path} via ?${param}=`,
          severity: "medium",
          state: "proven",
          location: `${base}${path}`,
          description: `GET ${path}?${param}=<any URL> answers with a redirect to each of two distinct attacker URLs (${a.res.status}, ${b.res.status}). A link on your own domain can send users to a phishing page, or leak OAuth codes to another host.`,
          remediation: `Only redirect to relative paths or to an allowlist of your own hosts; reject absolute URLs and protocol-relative ones (//host) in ${param}.`,
          proof: { method: "Two GETs with distinct sentinel URLs under .invalid, redirects read without following them", replay: `curl -s -D - -o /dev/null '${a.url}' && curl -s -D - -o /dev/null '${b.url}'  # both Location headers echo the sentinel`, evidence: `HTTP ${a.res.status}, Location: ${a.target}; HTTP ${b.res.status}, Location: ${b.target}` },
          regressionHint: `${path}?${param}=https://example.invalid must not redirect off-site.`,
        });
        break; // one parameter per path is enough proof
      }
    }
    ctx.log(`open-redirect: ${findings.length} finding(s)`);
    return findings;
  },
};
