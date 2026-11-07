// cache-deception: web cache deception. A CDN caches by extension ("*.css is
// static"), the app ignores the suffix and serves the private page: account B
// opens /api/projects/123/x.css, the CDN stores B's object, and anyone who
// requests the same URL gets it from the cache. GETs only, but the first one
// puts B's test data in your cache, so it runs with allowActiveTesting and the
// authz-matrix accounts. A unique nonce per URL keeps real users unaffected.

import { randomBytes } from "node:crypto";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

interface Opts { resources?: { name: string; path: string; public?: boolean }[]; accounts?: { b?: { token?: string; marker?: string; owns?: Record<string, string[]> } } }

export const cacheDeception: Check = {
  name: "cache-deception",
  title: "Private responses stored by the cache under a static-looking URL (web cache deception)",
  readOnly: true, // GETs; gated by allowActiveTesting below
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["authz-matrix"] ?? {}) as Opts;
    const b = o.accounts?.b;
    if (!ctx.stagingUrl || !b?.token || !ctx.scope.allowActiveTesting) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    const get = (url: string, token?: string) => safeFetch(url, ctx.scope, { headers: token ? { authorization: `Bearer ${token}` } : {} });
    const out: Finding[] = [];
    for (const r of (o.resources ?? []).filter((x) => !x.public)) {
      const id = b.owns?.[r.name]?.[0];
      if (!id) continue;
      const page = base + r.path.replace(":id", encodeURIComponent(id));
      for (const suffix of [`/crenel-${randomBytes(5).toString("hex")}.css`, `;crenel-${randomBytes(5).toString("hex")}.css`, `.css?crenel=${randomBytes(5).toString("hex")}`]) {
        const url = page + suffix;
        try {
          const canonicalAnon = await get(page);
          if (canonicalAnon.status >= 200 && canonicalAnon.status < 300) break; // already public, nothing to deceive
          const owner = await get(url, b.token);
          if (owner.status !== 200) continue;
          const anon = await get(url);
          const leaked = anon.status === 200 && (anon.body === owner.body || (!!b.marker && anon.body.includes(b.marker)));
          if (!leaked) continue;
          const hit = anon.headers.get("cf-cache-status") ?? anon.headers.get("x-cache") ?? anon.headers.get("age") ?? "";
          out.push({
            id: `cache-deception:${r.name}`, check: "cache-deception", title: `B's ${r.name} served from the cache to anyone at a .css URL`, severity: "critical", state: "proven",
            location: page + suffix.replace(/crenel[-=][0-9a-f]+/, "<nonce>"),
            description: `Account B opened ${url}; the app served B's ${r.name} and the cache stored it. An anonymous GET of the same URL then returned B's object${hit ? ` (cache header: ${hit})` : ""}, while ${page} itself refuses anonymous callers (${canonicalAnon.status}).`,
            remediation: "Make the app return 404 for unknown path suffixes, mark private responses Cache-Control: private, no-store, and cache by Content-Type rather than by extension at the CDN.",
            proof: { method: "B's GET on a static-looking URL, then an anonymous GET of the same URL", replay: `curl -s '${url}' # anonymous, after B's request`, evidence: `anonymous HTTP ${anon.status}, body identical to B's${hit ? `, ${hit}` : ""}` },
            regressionHint: `${page}<suffix>.css must never be cached with a private body.`,
          });
          break;
        } catch (err) { ctx.log(`cache-deception: ${url}: ${(err as Error).message}`); }
      }
    }
    ctx.log(`cache-deception: ${out.length} finding(s)`);
    return out;
  },
};
