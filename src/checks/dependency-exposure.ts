// dependency-exposure: the deployed site hands out a dependency manifest (a
// package.json served directly, or a package-lock.json / a *.bak), and a library
// it pins at an EXACT version has a known, public advisory. Two facts, both
// objective and checked live: the manifest is served, and an exactly-pinned
// version falls below a documented-vulnerable bound. No model, no target
// signature — the advisory list is a generic, well-known set.
//
// Soundness note: a package.json `dependencies` map holds version *ranges*
// (`^4.17.4`, `~1.2`, `>=3`), and the resolved/installed version of a range may
// well be patched. A range therefore proves nothing and is skipped. Only an
// EXACT pin (`4.17.4`), or an exact `version` read from a lockfile (the real
// installed version), can make a vulnerability `proven`.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch, type SafeResponse } from "../core/net.js";
import { isDirectoryListing, listedFiles, LISTING_PATHS, readDirectoryIndex } from "./directory-listing.js";

// Where a manifest or lockfile is commonly reachable on a deployed site. Generic
// conventional names only (no target-specific backup path).
const MANIFEST_PATHS = [
  "/package.json", "/package-lock.json", "/package.json.bak",
  "/static/package.json", "/assets/package.json",
];

// A dependency manifest a directory index might name. Generic filenames, not a
// target's backup path.
const MANIFEST_NAME = /^(?:package\.json|package-lock\.json|npm-shrinkwrap\.json)(?:\.bak)?$/i;
// A file whose extension a static server filters (403/400) can still be read
// through a poison null byte: a NUL terminator before an allowed extension. A
// generic, long-documented technique, tried only on a file a directory index
// already named, and still a read-only GET on the declared host.
const NULLBYTE_SUFFIXES = ["%2500.md", "%2500.txt", "%2500.pdf"];
const MANIFEST_MAX_BYTES = 16 * 1024 * 1024;
const MAX_LISTED_MANIFESTS = 12;

/** POSIX-shell single quoting for copy/paste replay commands. Redirect targets
 * are target-controlled and must never get a chance to expand `$()` or ticks. */
export const shellQuote = (value: string): string => `'${value.replace(/'/g, `'"'"'`)}'`;

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

/** An EXACT semver, or undefined. Rejects ranges (`^ ~ > < = x *`), partial
 * versions, and non-registry specs (git/url/file/workspace/npm: aliases): those
 * do not name a single installed version, so they cannot prove anything. A plain
 * `=`/`v` prefix is tolerated and stripped. Pure, tested. */
export function exactVersion(spec: string): [number, number, number] | undefined {
  const s = spec.trim().replace(/^[v=]+/, "");
  if (!/^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/.test(s)) return undefined;
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(s)!;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}
const lt = (a: [number, number, number], b: [number, number, number]) =>
  a[0] !== b[0] ? a[0] < b[0] : a[1] !== b[1] ? a[1] < b[1] : a[2] < b[2];

/** Map of package name -> its EXACT installed/pinned version, drawn from either a
 * package.json (its dependency maps, exact pins only) or a package-lock.json (the
 * `packages` / `dependencies` trees, whose `version` fields are exact). */
function installedVersions(j: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  // Runtime dependency maps only: a vulnerable package that lives solely in
  // devDependencies is not installed or loaded by a production build, so it does
  // not prove the running server is affected. optionalDependencies are runtime.
  for (const k of ["dependencies", "optionalDependencies"]) {
    const d = j[k];
    if (d && typeof d === "object" && !Array.isArray(d)) {
      for (const [n, v] of Object.entries(d as Record<string, unknown>)) {
        if (typeof v === "string" && exactVersion(v)) out[n] = v;
        // package-lock v1 shape: dependencies[name] = { version, ... }
        else if (v && typeof v === "object" && typeof (v as { version?: unknown }).version === "string") out[n] = (v as { version: string }).version;
      }
    }
  }
  // package-lock v2/v3 shape: packages["node_modules/<name>"] = { version }
  const pkgs = j["packages"];
  if (pkgs && typeof pkgs === "object" && !Array.isArray(pkgs)) {
    for (const [path, meta] of Object.entries(pkgs as Record<string, unknown>)) {
      const name = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(path)?.[1];
      const ver = meta && typeof meta === "object" ? (meta as { version?: unknown }).version : undefined;
      if (name && typeof ver === "string") out[name] = ver;
    }
  }
  return out;
}

/** Vulnerable deps found in a served manifest or lockfile, each at an EXACT
 * version below its advisory bound. Pure, tested. */
export function vulnerableDeps(manifest: string): { name: string; version: string; why: string }[] {
  let j: unknown;
  try { j = JSON.parse(manifest); } catch { return []; }
  if (!j || typeof j !== "object") return [];
  const installed = installedVersions(j as Record<string, unknown>);
  const hits: { name: string; version: string; why: string }[] = [];
  for (const [name, adv] of Object.entries(ADVISORIES)) {
    const v = installed[name];
    if (!v) continue;
    const ev = exactVersion(v);
    if (ev && lt(ev, adv.below)) hits.push({ name, version: v, why: adv.why });
  }
  return hits;
}

/** A body is a dependency manifest/lockfile only if it parses as JSON and carries
 * a recognized dependency structure as an object (not merely the substring). This
 * keeps an SPA page or a JSON soft-404 from being read as a manifest. */
function isManifest(body: string): boolean {
  let j: unknown;
  try { j = JSON.parse(body); } catch { return false; }
  if (!j || typeof j !== "object") return false;
  const o = j as Record<string, unknown>;
  return ["dependencies", "devDependencies", "optionalDependencies", "packages"].some(
    (k) => o[k] && typeof o[k] === "object",
  );
}

interface ManifestRead { response?: SafeResponse; truncated?: SafeResponse }

/** Read a manifest at `url`: a plain GET, then the exact encoded null-byte
 * variants when necessary. The returned response retains the URL that actually
 * served the bytes, so location and replay describe the proof that was observed. */
async function readManifest(ctx: CheckContext, url: string): Promise<ManifestRead> {
  let truncated: SafeResponse | undefined;
  for (const candidate of [url, ...NULLBYTE_SUFFIXES.map((suffix) => url + suffix)]) {
    try {
      const r = await safeFetch(candidate, ctx.scope, { headers: { accept: "*/*" }, maxBytes: MANIFEST_MAX_BYTES });
      if (r.status !== 200) continue;
      if (r.truncated) { truncated ??= r; continue; }
      if (isManifest(r.body)) return { response: r, truncated };
    } catch { /* next exact candidate */ }
  }
  return { truncated };
}

function tooLarge(path: string, response: SafeResponse): Finding {
  return {
    id: `dependency-exposure:${path}:truncated`, check: "dependency-exposure",
    title: `Served dependency manifest ${path} exceeds the safe validation limit`,
    severity: "info", state: "unproven", location: response.url,
    description: `${path} answered HTTP 200 but exceeded the ${MANIFEST_MAX_BYTES / 1024 / 1024} MiB read cap. Crenel did not parse an incomplete lockfile and makes no vulnerability claim from it.`,
    remediation: "Do not publish dependency manifests or lockfiles from the web root. Review this file manually, then remove it from the deployment.",
    proof: { method: "bounded live GET (validation stopped before parsing truncated JSON)", replay: `curl -sS ${shellQuote(response.url)} -o /dev/null`, evidence: `HTTP 200; response exceeded ${MANIFEST_MAX_BYTES / 1024 / 1024} MiB and was truncated` },
  };
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
    const leads: Finding[] = [];
    for (const path of opts.paths ?? MANIFEST_PATHS) {
      const read = await readManifest(ctx, base + path);
      const res = read.response;
      if (!res) { if (read.truncated) leads.push(tooLarge(path, read.truncated)); continue; }
      const hits = vulnerableDeps(res.body);
      if (hits.length === 0) { ctx.log(`dependency-exposure: ${path} served but no exactly-pinned advisory match`); continue; }
      const list = hits.slice(0, 8).map((h) => `${h.name}@${h.version}`).join(", ");
      return [{
        id: `dependency-exposure:${path}`,
        check: "dependency-exposure",
        title: `Exposed manifest ${path} pins ${hits.length} vulnerable dependenc${hits.length > 1 ? "ies" : "y"} (${hits[0]!.name})`,
        severity: "high",
        state: "proven",
        location: res.url,
        description: `${path} is served and pins library versions with public advisories: ${list}. For example ${hits[0]!.name}@${hits[0]!.version} — ${hits[0]!.why}.`,
        remediation: "Do not serve dependency manifests or their backups from the web root, and upgrade the flagged libraries to a patched version.",
        proof: { method: "live read of the served manifest + an exactly-pinned version below a documented-vulnerable bound (no model)", replay: `curl -sS ${shellQuote(res.url)}  # exactly-pinned deps with known advisories`, evidence: `served HTTP ${res.status} from ${res.url}; vulnerable: ${list}` },
        regressionHint: `After deploy, ${path} must not be served, and these libraries must be upgraded.`,
      }];
    }
    // Discovery: a manifest a server actually lists in an open directory index.
    // The listing is a generic misconfiguration (see directory-listing); here we
    // read the manifest it exposes and run the same advisory oracle, so any
    // server that lists a package manifest is covered, never one target's path.
    const seen = new Set<string>();
    for (const lp of LISTING_PATHS) {
      let idx;
      try { idx = await readDirectoryIndex(ctx, base + lp); } catch { continue; }
      if (idx.status !== 200 || !isDirectoryListing(idx.body)) continue;
      for (const name of listedFiles(idx.body).filter((n) => MANIFEST_NAME.test(n)).slice(0, MAX_LISTED_MANIFESTS)) {
        const fileUrl = base + lp + name;
        if (seen.has(fileUrl)) continue;
        seen.add(fileUrl);
        const read = await readManifest(ctx, fileUrl);
        const served = read.response;
        if (!served) { if (read.truncated) leads.push(tooLarge(lp + name, read.truncated)); continue; }
        const hits = vulnerableDeps(served.body);
        if (hits.length === 0) { ctx.log(`dependency-exposure: ${lp}${name} served but no exactly-pinned advisory match`); continue; }
        const list = hits.slice(0, 8).map((h) => `${h.name}@${h.version}`).join(", ");
        return [{
          id: `dependency-exposure:${lp}${name}`,
          check: "dependency-exposure",
          title: `Exposed manifest ${lp}${name} pins ${hits.length} vulnerable dependenc${hits.length > 1 ? "ies" : "y"} (${hits[0]!.name})`,
          severity: "high",
          state: "proven",
          location: served.url,
          description: `An open directory listing at ${lp} exposes ${name}, which pins library versions with public advisories: ${list}. For example ${hits[0]!.name}@${hits[0]!.version} — ${hits[0]!.why}.`,
          remediation: "Disable directory indexing, remove dependency manifests and their backups from the web root, and upgrade the flagged libraries to a patched version.",
          proof: { method: "manifest named in an open directory listing, read live (an encoded null-byte extension bypass where needed) + an exactly-pinned version below a documented-vulnerable bound (no model)", replay: `curl -sS ${shellQuote(served.url)}`, evidence: `manifest served via ${served.url}; vulnerable: ${list}` },
          regressionHint: `After deploy, ${lp} must not list files and ${name} must not be served.`,
        }];
      }
    }
    ctx.log("dependency-exposure: no vulnerable dependency manifest served");
    return leads;
  },
};
