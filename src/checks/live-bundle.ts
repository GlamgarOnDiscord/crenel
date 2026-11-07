// live-bundle: scan the JavaScript the deployed site actually serves, the way a
// visitor (or a bug hunter) gets it, without access to the repo. Starting from
// the declared staging URL it follows <script src>, modulepreload links, dynamic
// import() and static import chunks, Next.js chunk paths and sourceMappingURL
// comments, downloads each file with GET through the scoped client, and runs the
// same secret and BaaS detectors as the offline checks on what came back.
//
// Read-only: the requests are the ones a browser makes when it loads the page.
// Only declared hosts are followed: a chunk on an undeclared CDN is listed in the
// log and skipped, never fetched. Files are kept in a temp dir for the scan and
// deleted after.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { exposedSecrets } from "./exposed-secrets.js";
import { extractBaas } from "./baas-exposure.js";

const MAX_FILES = 150;
const MAX_TOTAL_BYTES = 40 * 1024 * 1024;

/** Asset URLs referenced by an HTML page or a JS/CSS file, resolved against `base`. */
export function extractAssetUrls(body: string, base: string, kind: "html" | "js" | "map"): string[] {
  if (kind === "map") return [];
  const out = new Set<string>();
  const add = (raw: string) => {
    const s = raw.trim();
    if (!s || s.startsWith("data:") || s.startsWith("blob:") || s.startsWith("javascript:")) return;
    try { out.add(new URL(s, base).toString().split("#")[0]!); } catch { /* not a URL */ }
  };
  if (kind === "html") {
    for (const m of body.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) add(m[1]!);
    for (const m of body.matchAll(/<link\b[^>]*\brel\s*=\s*["'](?:modulepreload|preload|prefetch)["'][^>]*>/gi)) {
      const href = /\bhref\s*=\s*["']([^"']+\.m?js(?:\?[^"']*)?)["']/i.exec(m[0]);
      if (href) add(href[1]!);
    }
    // Inline scripts can also import chunks.
    for (const m of body.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) for (const u of extractAssetUrls(m[1]!, base, "js")) out.add(u);
    return [...out];
  }
  // JS: import("./x.js"), import "./x.js", from "./x.js", new URL("./x.js", import.meta.url)
  for (const m of body.matchAll(/\b(?:import\s*\(\s*|import\s+|from\s*)["'`]([^"'`]+\.m?js(?:\?[^"'`]*)?)["'`]/g)) add(m[1]!);
  for (const m of body.matchAll(/new\s+URL\(\s*["'`]([^"'`]+\.m?js)["'`]\s*,\s*import\.meta\.url/g)) add(m[1]!);
  // Next.js and webpack chunk paths written as plain strings.
  for (const m of body.matchAll(/["'`]((?:\/_next\/)?static\/chunks\/[\w\-./[\]]+\.js)["'`]/g)) {
    const p = m[1]!.startsWith("/") ? m[1]! : `/_next/${m[1]!}`;
    add(p);
  }
  // Chunks a visitor never loads (getfrontend's method): the bundler lists them
  // all in its runtime, as an id -> hash table or a dependency array.
  for (const u of runtimeChunkUrls(body, base)) out.add(u);
  const map = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*$/m.exec(body);
  if (map && !map[1]!.startsWith("data:")) add(map[1]!);
  return [...out];
}

/**
 * API routes written in client code (the method of LinkFinder and jsluice): string
 * and template literals that look like "/api/..." or "/v1/...". A template
 * placeholder or an id-shaped segment becomes ":id", so the route can go
 * straight into the authorization matrix. Routes with one placeholder only.
 */
export function extractEndpoints(js: string): string[] {
  const out = new Set<string>();
  const lit = /["'`](\/(?:api|v\d|rest|graphql|trpc|internal|admin)\/[A-Za-z0-9_\-./${}:?=&]{1,160})["'`]/g;
  for (const m of js.matchAll(lit)) {
    let p = m[1]!.split("?")[0]!.replace(/\/+$/, "");
    p = p.replace(/\$\{[^}]*\}/g, ":id").replace(/\/(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27})(?=\/|$)/gi, "/:id").replace(/:\w+/g, ":id");
    if (/[{}$]/.test(p) || (p.match(/:id/g) ?? []).length > 1) continue;
    out.add(p);
  }
  return [...out].sort();
}

/**
 * Every chunk the bundler's runtime knows, loaded or not:
 *  - webpack/Next: "static/chunks/" + ({12:"admin"}[e]||e) + "." + {12:"3f2a"}[e] + ".js",
 *    resolved against the runtime's public path (__webpack_require__.p = "/_next/");
 *  - Vite: the __vite__mapDeps array of "assets/x-hash.js" paths.
 */
export function runtimeChunkUrls(body: string, base: string): string[] {
  const out: string[] = [];
  const origin = (() => { try { return new URL(base).origin; } catch { return ""; } })();
  if (!origin) return out;
  const publicPath = /\.p\s*=\s*"([^"]*)"/.exec(body)?.[1] ?? "/";
  const table = (s: string) => Object.fromEntries([...s.matchAll(/(?:"?)([\w-]+)"?\s*:\s*"([^"]+)"/g)].map((m) => [m[1]!, m[2]!]));
  const re = /"([\w./-]*\/)"\s*\+\s*(?:\(\s*\{([^{}]*)\}\s*\[\s*\w+\s*\]\s*\|\|\s*\w+\s*\)|\w+)\s*\+\s*"\."\s*\+\s*\{([^{}]*)\}\s*\[\s*\w+\s*\]\s*\+\s*"(\.[\w.]*js)"/g;
  for (const m of body.matchAll(re)) {
    const names = m[2] ? table(m[2]) : {};
    const hashes = table(m[3]!);
    for (const [id, hash] of Object.entries(hashes).slice(0, 400)) {
      try { out.push(new URL(`${publicPath}${m[1]}${names[id] ?? id}.${hash}${m[4]}`, origin + "/").toString()); } catch { /* skip */ }
    }
  }
  if (body.includes("__vite__mapDeps")) {
    for (const m of body.matchAll(/["'`]((?:\.\/)?assets\/[\w.-]+\.m?js)["'`]/g)) {
      try { out.push(new URL(m[1]!.replace(/^\.\//, ""), origin + "/").toString()); } catch { /* skip */ }
    }
  }
  return out;
}

const kindOf = (url: string, contentType: string): "html" | "js" | "map" =>
  /\.map(\?|$)/.test(url) ? "map" : /javascript|ecmascript/.test(contentType) || /\.m?js(\?|$)/.test(url) ? "js" : "html";

export interface ServedFile { url: string; kind: "html" | "js" | "map"; body: string; truncated: boolean }

/**
 * Download what the deployed site serves, starting at `start`: the page, its
 * scripts and chunks, and the source maps they point to. GET only, declared
 * hosts only (others are returned in `skipped`, never fetched).
 */
export async function crawlLiveBundle(ctx: Pick<CheckContext, "scope" | "log">, start: string): Promise<{ files: ServedFile[]; skipped: string[]; bytes: number }> {
  const queue: string[] = [start];
  const seen = new Set<string>(queue);
  const skipped = new Set<string>();
  const files: ServedFile[] = [];
  let bytes = 0;
  while (queue.length && files.length < MAX_FILES && bytes < MAX_TOTAL_BYTES) {
    const url = queue.shift()!;
    if (!ctx.scope.isHostAllowed(url)) { skipped.add(new URL(url).host); continue; }
    let res;
    try { res = await safeFetch(url, ctx.scope); } catch (err) { ctx.log(`live-bundle: ${url}: ${(err as Error).message}`); continue; }
    if (res.status !== 200) continue;
    const kind = kindOf(res.url, res.headers.get("content-type") ?? "");
    files.push({ url: res.url, kind, body: res.body, truncated: res.truncated });
    bytes += res.body.length;
    for (const next of extractAssetUrls(res.body, res.url, kind)) {
      if (!seen.has(next)) { seen.add(next); queue.push(next); }
    }
  }
  if (skipped.size) ctx.log(`live-bundle: skipped undeclared host(s): ${[...skipped].join(", ")} (add them to scope.allowedHosts to include them)`);
  const cut = files.filter((f) => f.truncated).length;
  if (cut) ctx.log(`live-bundle: ${cut} file(s) over the 2 MB response cap were read partially`);
  return { files, skipped: [...skipped], bytes };
}

export const liveBundle: Check = {
  name: "live-bundle",
  title: "Secrets and BaaS keys in the JavaScript the deployed site serves",
  readOnly: true, // GETs of public assets on declared hosts, the requests a browser makes
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) {
      ctx.log("live-bundle: no stagingUrl declared, nothing to fetch");
      return [];
    }
    const { files: served, bytes: total } = await crawlLiveBundle(ctx, ctx.stagingUrl);
    const dir = mkdtempSync(join(tmpdir(), "crenel-live-bundle-"));
    try {
      // Mirror host/path on disk so the offline detector reports a readable location.
      const fetched = served.map((f) => {
        const u = new URL(f.url);
        const rel = join(u.host.replace(/[:]/g, "_"), (u.pathname.endsWith("/") ? `${u.pathname}index.html` : u.pathname).replace(/^\/+/, "")).replace(/\.\./g, "_");
        const file = join(dir, f.kind === "html" && !/\.html?$/.test(rel) ? `${rel}.html` : rel);
        mkdirSync(dirname(file), { recursive: true });
        writeFileSync(file, f.body);
        return { ...f, path: file.slice(dir.length + 1).split("\\").join("/") };
      });
      const urlOf = new Map(fetched.map((f) => [f.path, f.url]));

      const findings: Finding[] = [];
      // Secrets: the offline detector, run on what the site served.
      const local = await exposedSecrets.run({ ...ctx, projectDir: dir, log: () => {} });
      for (const f of local) {
        const [path, line] = [f.location.replace(/:\d+$/, ""), f.location.match(/:(\d+)$/)?.[1]];
        const url = urlOf.get(path) ?? path;
        findings.push({
          ...f,
          id: `live-bundle:${f.id.replace(/^exposed-secrets:/, "")}`,
          check: "live-bundle",
          title: f.title.replace(path, url),
          location: line ? `${url}:${line}` : url,
          description: `${f.description.replace(path, url)} The deployed site serves this file to every visitor.`,
          proof: f.proof && { ...f.proof, method: `${f.proof.method}, in a file the live site serves`, replay: `curl -s '${url}' | grep -nE '${(f.proof.replay.match(/grep -nE '(.*)' "/)?.[1] ?? "").replace(/'/g, "'\\''")}'` },
          regressionHint: `CI: after deploy, fetch ${new URL(url).pathname} and fail if a server key pattern appears.`,
        });
      }
      // BaaS public keys: leads that point to the RLS check.
      for (const f of fetched) {
        if (f.kind === "map") continue;
        for (const h of extractBaas(f.body, f.url)) {
          if (h.kind !== "supabase") continue;
          findings.push({
            id: `live-bundle:supabase:${h.url}`,
            check: "live-bundle",
            title: `Supabase public key served by the live site (${h.url})`,
            severity: "medium",
            state: "unproven",
            location: f.url,
            description: `The deployed site ships the Supabase URL and its public key. That is expected, and safe only if every table has row-level security.`,
            remediation: `Run baas-exposure with ${h.url} declared and active testing on to prove which tables are readable without signing in, then enable RLS on them.`,
            proof: { method: "Supabase URL and public key found in a served file", replay: `curl -s '${f.url}' | grep -o '${h.url}'` },
          });
        }
      }
      // Public source maps: the original source, comments included.
      for (const f of fetched.filter((x) => x.kind === "map" && /"sources"\s*:/.test(x.body))) {
        findings.push({
          id: `live-bundle:sourcemap:${f.url}`,
          check: "live-bundle",
          title: `Source map served publicly: ${new URL(f.url).pathname}`,
          severity: "low",
          state: "proven",
          location: f.url,
          description: `${f.url} answers 200 with a source map: anyone can read the original source, comments and file layout.`,
          remediation: "Stop uploading .map files to the public host (keep them for your error tracker only), or block *.map at the edge.",
          proof: { method: "GET of the map referenced by the bundle returned a source map", replay: `curl -sI '${f.url}'`, evidence: "HTTP 200, \"sources\" present" },
          regressionHint: `CI: after deploy, expect ${new URL(f.url).pathname} to return 403 or 404.`,
        });
      }
      // API routes the client code calls: object routes are matrix candidates.
      const routes = [...new Set(fetched.filter((f) => f.kind !== "html").flatMap((f) => extractEndpoints(f.body)))];
      const objectRoutes = routes.filter((r) => r.endsWith(":id") || r.includes(":id/"));
      if (routes.length) {
        findings.push({
          id: `live-bundle:routes:${new URL(ctx.stagingUrl).host}`,
          check: "live-bundle",
          title: `${routes.length} API route(s) in the served JavaScript, ${objectRoutes.length} with an object id`,
          severity: "info",
          state: "unproven",
          location: ctx.stagingUrl,
          description: `Routes the client calls: ${routes.slice(0, 25).join(", ")}${routes.length > 25 ? "…" : ""}. Every route with an object id should be in options.authz-matrix.resources, so Crenel can prove another account cannot reach it.`,
          remediation: "Add the object routes to the authorization matrix: " + objectRoutes.slice(0, 10).map((r) => `{ name: ${r.split("/").filter((s) => s && s !== ":id").pop()}, path: ${r} }`).join("; "),
          proof: { method: "route literals extracted from the served chunks", replay: `curl -s '${ctx.stagingUrl}' # then the chunks it loads` },
        });
      }
      ctx.log(`live-bundle: ${fetched.length} file(s) fetched (${Math.round(total / 1024)} KB), ${findings.length} finding(s)`);
      return findings;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
};
