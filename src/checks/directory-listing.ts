// directory-listing: a web server that hands out an auto-generated directory
// index exposes every file in that folder — backups, confidential documents,
// uploads — and is a reconnaissance goldmine. The proof is the listing itself: a
// 200 whose body is a server autoindex page (Apache "Index of /", Express/nginx
// "listing directory"), with links to the files it contains. A single-page app
// that answers index.html for every route never matches (no autoindex markers).
// The probed paths are a conventional recon wordlist of folder names, not a
// signature for any one target; the check reports whatever files the folder
// actually exposes. Read-only GETs on the declared base. Generic.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch, type SafeResponse } from "../core/net.js";
import { lastMatch, tagsOf } from "../core/html.js";

export const LISTING_PATHS = [
  "/ftp/", "/files/", "/uploads/", "/upload/", "/backup/", "/backups/",
  "/static/", "/assets/", "/data/", "/documents/", "/docs/", "/download/",
  "/downloads/", "/public/", "/tmp/", "/logs/", "/images/", "/media/",
];

// Strong autoindex markers (server-generated directory index, not an app page).
const TITLE_MARK = /<title>\s*(index of\s*\/|listing directory\s*\/)/i;
const APACHE_MARK = /<h1>\s*Index of\s*\//i;

/** True when the body is a server directory-index page listing files. */
export function isDirectoryListing(body: string): boolean {
  if (TITLE_MARK.test(body) || APACHE_MARK.test(body)) return true;
  return false;
}

/** File names linked in the listing (excluding parent/self links). */
export function listedFiles(body: string): string[] {
  const names: string[] = [];
  // Was /<a[^>]+href=["']?([^"'>\s]+)["']?[^>]*>/gi: cubic on a body of "<a" repeats (core/html.ts).
  for (const t of tagsOf(body, /<a/i)) {
    const m = t.closed ? lastMatch(t.text.slice(3), /href=["']?([^"'>\s]+)/i) : null;
    if (!m) continue;
    let href = m[1]!;
    try { href = decodeURIComponent(href); } catch { /* keep raw */ }
    href = href.replace(/\/+$/, "");
    const name = href.split("/").filter(Boolean).pop() ?? "";
    if (!name || name === ".." || href === "." || href.startsWith("?") || href.startsWith("#")) continue;
    if (!names.includes(name)) names.push(name);
  }
  return names.slice(0, 40);
}

/** One anonymous directory-index read, shared by every check in the same run. */
export function readDirectoryIndex(ctx: CheckContext, url: string): Promise<SafeResponse> {
  const key = `directory-index:GET:${url}`;
  const prior = ctx.recon?.get(key);
  if (prior) return prior;
  const pending = safeFetch(url, ctx.scope, { headers: { accept: "text/html" }, maxBytes: 256 * 1024 });
  if (ctx.recon) {
    ctx.recon.set(key, pending);
    // A transient network failure must not poison a later check in this run.
    void pending.catch(() => { if (ctx.recon?.get(key) === pending) ctx.recon.delete(key); });
  }
  return pending;
}

const SENSITIVE = /(confidential|secret|backup|\.bak\b|\.sql\b|\.env|password|private|acquisition|coupon|dump|\.key\b|\.pem\b)/i;

export const directoryListing: Check = {
  name: "directory-listing",
  title: "Open directory listing (server autoindex exposing files)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options["directory-listing"] ?? {}) as { paths?: string[] };
    const findings: Finding[] = [];
    for (const path of opts.paths ?? LISTING_PATHS) {
      try {
        const res = await readDirectoryIndex(ctx, base + path);
        if (res.status !== 200 || !isDirectoryListing(res.body)) continue;
        const files = listedFiles(res.body);
        // Only claim a file is "exposed" when it is actually served (fetched 200
        // with content), not merely named in the index. Confirm up to 3 candidates.
        const sensitive: string[] = [];
        for (const f of files.filter((x) => SENSITIVE.test(x)).slice(0, 3)) {
          try {
            const fr = await safeFetch(base + path + f, ctx.scope, { headers: { accept: "*/*" }, maxBytes: 64 * 1024 });
            if (fr.status === 200 && fr.body.trim().length > 0) sensitive.push(f);
          } catch { /* not served: do not claim it */ }
        }
        findings.push({
          id: `directory-listing:${path}`,
          check: "directory-listing",
          title: `Open directory listing at ${path}${sensitive.length ? " (exposes sensitive files)" : ""}`,
          severity: sensitive.length ? "high" : "medium",
          state: "proven",
          location: `${base}${path}`,
          description: `${path} is served as a directory listing, exposing its contents to anyone: ${files.length ? files.slice(0, 12).join(", ") : "(files listed in the index)"}${files.length > 12 ? ", …" : ""}.${sensitive.length ? ` Sensitive/confidential files are among them: ${sensitive.slice(0, 8).join(", ")}.` : ""}`,
          remediation: "Disable directory indexing (Apache `Options -Indexes`, nginx `autoindex off`, remove the static-serve of the folder) and move confidential files out of the web root.",
          proof: { method: "read-only GET, no credentials", replay: `curl -s '${base}${path}'`, evidence: `HTTP 200, server directory-index page listing ${files.length} file(s)` },
          regressionHint: `After deploy, ${path} must not return a directory-index page.`,
        });
      } catch { /* next path */ }
    }
    if (findings.length === 0) ctx.log("directory-listing: no open directory index on the usual paths");
    return findings;
  },
};
