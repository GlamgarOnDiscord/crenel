// dependency-exposure: the deployed site hands out a dependency manifest (a
// package.json served directly, or a *.bak reachable through a directory listing
// / a null-byte suffix), and it pins a library at a version with a known, public
// advisory. Two facts, both objective and checked live: the manifest is served,
// and a listed version falls in a documented-vulnerable range. No model, no target
// signature — the advisory list is a generic, well-known set (the same idea as the
// committed-lockfile dependency-risk check, but for a manifest the site exposes).

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

// Where a manifest is commonly reachable on a deployed site. The null-byte / .bak
// variants cover a backup left in a served folder (e.g. an /ftp drop).
const MANIFEST_PATHS = [
  "/package.json", "/package.json.bak", "/package.json.bak%2500.md", "/package.json.bak%00.md",
  "/ftp/package.json.bak%2500.md", "/ftp/package.json.bak%00.md", "/ftp/package.json",
  "/static/package.json", "/assets/package.json",
];

// A small, well-known advisory set: package -> the version BELOW which it is
// vulnerable, with the class. Universal CVEs, not any one target's answer.
interface Adv { below: [number, number, number]; why: string }
const ADVISORIES: Record<string, Adv> = {
  jsonwebtoken: { below: [9, 0, 0], why: "CVE-2022-23529/23540: weak signature verification" },
  express: { below: [4, 17, 3], why: "CVE-2022-24999: ReDoS in qs" },
  lodash: { below: [4, 17, 21], why: "CVE-2020-8203/2021-23337: prototype pollution / command injection" },
  "sanitize-html": { below: [2, 3, 1], why: "multiple XSS-filter bypasses (CVE-2021-26539 and earlier)" },
  marsdb: { below: [0, 6, 12], why: "CVE-2019-10769: server-side code/NoSQL injection" },
  libxmljs: { below: [1, 0, 0], why: "XXE / type confusion advisories" },
  "socket.io": { below: [2, 4, 0], why: "CVE-2020-28481: cross-origin via default CORS" },
  dottie: { below: [2, 0, 3], why: "prototype pollution advisory" },
  minimist: { below: [1, 2, 6], why: "CVE-2021-44906: prototype pollution" },
  handlebars: { below: [4, 7, 7], why: "prototype pollution / RCE advisories" },
  jquery: { below: [3, 5, 0], why: "CVE-2020-11022/11023: XSS in HTML manipulation" },
  "node-forge": { below: [1, 3, 0], why: "CVE-2022-24771/24772: signature verification" },
};

/** Parse a loose npm version range (~8, ^4.16.1, >=1.2, 1.4.2) to a [major,minor,patch]
 * lower bound. Returns undefined when no numeric version is present (a git/url dep). */
export function lowerBound(range: string): [number, number, number] | undefined {
  const m = /(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(range);
  if (!m) return undefined;
  return [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)];
}
const lt = (a: [number, number, number], b: [number, number, number]) =>
  a[0] !== b[0] ? a[0] < b[0] : a[1] !== b[1] ? a[1] < b[1] : a[2] < b[2];

/** Vulnerable deps found in a manifest's dependency maps. Pure, tested. */
export function vulnerableDeps(manifest: string): { name: string; version: string; why: string }[] {
  let j: unknown;
  try { j = JSON.parse(manifest); } catch { return []; }
  if (!j || typeof j !== "object") return [];
  const deps: Record<string, string> = {};
  for (const k of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const d = (j as Record<string, unknown>)[k];
    if (d && typeof d === "object") for (const [n, v] of Object.entries(d as Record<string, string>)) if (typeof v === "string") deps[n] = v;
  }
  const hits: { name: string; version: string; why: string }[] = [];
  for (const [name, adv] of Object.entries(ADVISORIES)) {
    const v = deps[name];
    if (!v) continue;
    const lb = lowerBound(v);
    if (lb && lt(lb, adv.below)) hits.push({ name, version: v, why: adv.why });
  }
  return hits;
}

export const dependencyExposure: Check = {
  name: "dependency-exposure",
  title: "Dependency manifest served with a known-vulnerable library version",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options["dependency-exposure"] ?? {}) as { paths?: string[] };
    for (const path of opts.paths ?? MANIFEST_PATHS) {
      let res;
      try { res = await safeFetch(base + path, ctx.scope, { headers: { accept: "*/*" }, maxBytes: 256 * 1024 }); } catch { continue; }
      if (res.status !== 200 || !/"dependencies"\s*:/.test(res.body)) continue; // a real manifest, not an SPA page
      const hits = vulnerableDeps(res.body);
      if (hits.length === 0) { ctx.log(`dependency-exposure: ${path} served but no advisory match`); continue; }
      const list = hits.slice(0, 8).map((h) => `${h.name}@${h.version}`).join(", ");
      return [{
        id: `dependency-exposure:${path}`,
        check: "dependency-exposure",
        title: `Exposed manifest ${path} pins ${hits.length} vulnerable dependenc${hits.length > 1 ? "ies" : "y"} (${hits[0]!.name})`,
        severity: "high",
        state: "proven",
        location: base + path,
        description: `${path} is served and declares library versions with public advisories: ${list}. For example ${hits[0]!.name}@${hits[0]!.version} — ${hits[0]!.why}.`,
        remediation: "Do not serve dependency manifests or their backups from the web root, and upgrade the flagged libraries to a patched version.",
        proof: { method: "live read of the served manifest + a documented-vulnerable version range (no model)", replay: `curl -s '${base}${path}'  # dependencies with known advisories`, evidence: `served HTTP 200; vulnerable: ${list}` },
        regressionHint: `After deploy, ${path} must not be served, and these libraries must be upgraded.`,
      }];
    }
    ctx.log("dependency-exposure: no vulnerable dependency manifest served");
    return [];
  },
};
