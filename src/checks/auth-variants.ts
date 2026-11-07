// auth-variants: middleware that guards a path by comparing strings can be
// skipped by another spelling of the same route. Next.js, Auth.js and Clerk
// have all had advisories of that shape in 2025-2026. For each route that
// refuses an anonymous visitor, we ask a few spellings that the framework
// routes to the same page: a trailing .rsc or ?_rsc= (React Server Components),
// /_next/data/<buildId>/<route>.json, a doubled slash, an upper-case letter.
// A variant served (200) with the page's own content, where the canonical path
// redirected or refused, is the proof. GET only, declared host.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

const PATHS = ["/dashboard", "/admin", "/settings", "/account", "/app", "/billing"];
const blocked = (s: number) => s === 401 || s === 403 || (s >= 300 && s < 400);

export function variantsOf(path: string, buildId?: string): { label: string; path: string; headers?: Record<string, string> }[] {
  const out: { label: string; path: string; headers?: Record<string, string> }[] = [
    { label: "trailing .rsc", path: `${path}.rsc`, headers: { rsc: "1" } },
    { label: "?_rsc= with RSC header", path: `${path}?_rsc=crenel`, headers: { rsc: "1" } },
    { label: "doubled slash", path: `/${path}` },
    { label: "trailing slash", path: `${path}/` },
    { label: "upper-case letter", path: path.replace(/^\/(\w)/, (_m, c: string) => `/${c.toUpperCase()}`) },
    { label: "encoded slash", path: path.replace(/^\//, "/%2F") },
  ];
  if (buildId) out.push({ label: "/_next/data JSON", path: `/_next/data/${buildId}${path}.json`, headers: { "x-nextjs-data": "1" } });
  return out;
}

export const authVariants: Check = {
  name: "auth-variants",
  title: "Protected route reachable through another spelling of its URL",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const paths = ((ctx.options["auth-variants"] ?? {}) as { paths?: string[] }).paths ?? PATHS;
    let buildId: string | undefined;
    try { buildId = /"buildId"\s*:\s*"([\w-]{4,64})"/.exec((await safeFetch(base + "/", ctx.scope)).body)?.[1]; } catch { /* no page */ }
    const out: Finding[] = [];
    for (const path of paths) {
      let canonical;
      try { canonical = await safeFetch(base + path, ctx.scope, { followRedirects: false }); } catch { continue; }
      if (!blocked(canonical.status)) continue; // not protected, nothing to bypass
      for (const v of variantsOf(path, buildId)) {
        let res;
        try { res = await safeFetch(base + v.path, ctx.scope, { followRedirects: false, headers: v.headers }); } catch { continue; }
        // Served, not the refusal page, and not an empty shell: a body that differs from the canonical answer.
        if (res.status !== 200 || res.body.length < 64 || res.body === canonical.body) continue;
        // A canonical redirect TO this spelling is URL normalization (/x -> /x/), not a bypass.
        const loc = canonical.headers.get("location");
        if (loc) { try { if (new URL(loc, base + path).pathname === new URL(base + v.path).pathname) continue; } catch { /* odd Location */ } }
        out.push({
          id: `auth-variants:${path}:${v.label}`, check: "auth-variants",
          title: `${path} is protected, but served through ${v.label} (${v.path})`, severity: "high", state: "proven",
          location: base + v.path,
          description: `GET ${path} answers ${canonical.status} to an anonymous visitor, while GET ${v.path} answers 200 with ${res.body.length} bytes. The middleware matches the path as a string and another spelling of the same route skips it.`,
          remediation: "Check authorization in the route or data layer, not only in middleware; normalize paths before matching, and update the framework past its path-matching advisories.",
          proof: { method: "anonymous GET of the canonical path and of a variant spelling", replay: `curl -s -o /dev/null -w '%{http_code}' '${base}${v.path}'`, evidence: `canonical ${canonical.status}; variant HTTP 200, ${res.body.length} bytes` },
          regressionHint: `${v.path} must be refused like ${path}.`,
        });
        break;
      }
    }
    ctx.log(`auth-variants: ${out.length} finding(s)`);
    return out;
  },
};
