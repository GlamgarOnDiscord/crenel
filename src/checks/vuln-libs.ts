// vuln-libs: the target serves a front-end JavaScript library at an EXACT version
// that a public advisory (CVE / GHSA) documents as vulnerable. The version is read
// from what a visitor's browser loads, with the retire.js signature repository
// (the industry-standard, generic set: 64 libraries, not any target's answer):
//
//   - content signatures: a banner (/*! jQuery v1.6.1 */) or, in MINIFIED code
//     whose comments are gone, the library's own version assignment next to code
//     only that library has (`l="1.11.1",…m.fn=m.prototype={jquery:l,`);
//   - a SHA-1 of the whole file, for the few releases retire.js lists by hash;
//   - the script URL, when it sits on a public versioned CDN whose paths are
//     immutable per release (cdnjs, code.jquery.com, …): the URL is then the
//     version, without fetching the off-scope host.
//
// What is proven, and what is not (zero false positive is the invariant):
//   - proven: the exact version was read from served content (or a hash, or an
//     immutable CDN URL) AND falls inside a documented vulnerable range;
//   - lead only: a version that appears just in a self-hosted file name or path
//     (`/2.0.0/jquery.js` may be the app's own version directory);
//   - nothing: a patched version, a library with no readable version, a version
//     that is not exact (`3`, `3.4` on a CDN is a range), an advisory with no
//     CVE/GHSA id (end-of-life notices).
//
// Limits, stated plainly: retire.js `func` extractors run JavaScript inside a
// live page and its `ast` queries need a parser, so neither is used here (a
// static scanner must not execute a target's code). A library inlined in a
// bundle is found only when the bundler kept a version literal the content
// signatures know; a tree-shaken module with no version string is not found.
//
// Read-only: GETs of the page and of its scripts on declared hosts. The
// signatures are third-party regexes run on target-controlled text, and a regex
// cannot be interrupted, so they run in a worker thread that is terminated at a
// deadline: one crafted file costs that file's result, never the run.

import { createHash } from "node:crypto";
import { Worker } from "node:worker_threads";
import type { Check, CheckContext, Finding, Severity } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { extractAssetUrls } from "./live-bundle.js";
import { shellQuote } from "./dependency-exposure.js";
// Embedded, trimmed copy of the retire.js repository (~180 KB minified, against
// ~640 KB upstream): see scripts/sync-retire-db.mjs for what is dropped and why.
import retireData from "../data/retire-js.json" with { type: "json" };

export interface Advisory { atOrAbove?: string; below?: string; severity?: string; cve?: string[]; ghsa?: string; summary?: string }
export interface LibEntry { filecontent?: string[]; filecontentreplace?: string[]; filename?: string[]; uri?: string[]; hashes?: Record<string, string>; vulnerabilities: Advisory[] }
export type RetireDb = Record<string, LibEntry>;
export interface Detection { lib: string; version: string; via: "content" | "hash" | "url"; match: string }

export const RETIRE_DB: RetireDb = (retireData as unknown as { libs: RetireDb }).libs;

// retire.js's own expansion of §§version§§, so its patterns behave as written.
const VERSION = "[0-9][0-9.a-z_\\\\-]+";
const MAX_SCRIPTS = 40;
const SCRIPT_MAX_BYTES = 8 * 1024 * 1024;
const MATCH_TIMEOUT_MS = 8000;
// Public CDNs that serve one immutable file per released version: a full x.y.z
// in such a URL names the release. Generic infrastructure, not a target.
const VERSIONED_CDNS = new Set(["cdnjs.cloudflare.com", "ajax.googleapis.com", "code.jquery.com", "cdn.jsdelivr.net", "unpkg.com", "ajax.aspnetcdn.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com"]);
const SEVERITY_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

/** The exact release a raw capture names, or undefined. Dotted digits with at
 * least `minParts` components, plus an optional well-known pre-release tag. A
 * trailing `.min`/`-min` (a file name's, not the version's) is dropped; anything
 * else unusual is rejected: an unreadable version proves nothing. Pure, tested. */
export function exactVersion(raw: string, minParts = 2): string | undefined {
  const s = raw.trim().replace(/[-.]min$/i, "").replace(/[-._]+$/, "");
  const m = /^(\d{1,6}(?:\.\d{1,6}){1,3})(?:[-.]?((?:alpha|beta|rc|next|canary|pre|a|b)(?:[.-]?\d{1,6}){0,4}))?$/i.exec(s);
  if (!m || m[1]!.split(".").length < minParts) return undefined;
  return m[2] ? `${m[1]}-${m[2].toLowerCase()}` : m[1]!;
}

/** Compare two versions: <0, 0, >0. Numeric components first (missing = 0);
 * on a tie a pre-release tag sorts BELOW the plain release, two tags compare
 * piecewise (numbers numerically). */
export function cmpVersion(a: string, b: string): number {
  const split = (v: string) => {
    const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(v.trim());
    return m ? { nums: m[1]!.split(".").map(Number), pre: m[2]!.replace(/^[-.]/, "").toLowerCase() } : { nums: [] as number[], pre: v.toLowerCase() };
  };
  const x = split(a), y = split(b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d !== 0) return d;
  }
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  const px = x.pre.match(/\d+|[a-z]+/g) ?? [], py = y.pre.match(/\d+|[a-z]+/g) ?? [];
  for (let i = 0; i < Math.max(px.length, py.length); i++) {
    const p = px[i], q = py[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    if (p === q) continue;
    const pn = /^\d+$/.test(p), qn = /^\d+$/.test(q);
    if (pn && qn) return Number(p) - Number(q);
    return pn ? -1 : qn ? 1 : p < q ? -1 : 1;
  }
  return 0;
}

/** retire.js range semantics: atOrAbove <= version < below. A range with no
 * upper bound is never matched (nothing says where the fix is). */
export function inRange(version: string, a: Advisory): boolean {
  if (!a.below || !(cmpVersion(version, a.below) < 0)) return false;
  return !a.atOrAbove || cmpVersion(version, a.atOrAbove) >= 0;
}

/** The documented advisories (CVE or GHSA id) whose range holds `version`. */
export function advisoriesFor(entry: LibEntry | undefined, version: string): Advisory[] {
  return (entry?.vulnerabilities ?? []).filter((a) => ((a.cve?.length ?? 0) > 0 || !!a.ghsa) && inRange(version, a));
}

interface Pat { lib: string; src: string; repl?: string }
function contentPatterns(db: RetireDb): Pat[] {
  const out: Pat[] = [];
  for (const [lib, e] of Object.entries(db)) {
    for (const p of e.filecontent ?? []) out.push({ lib, src: p.replace(/§§version§§/g, VERSION) });
    for (const p of e.filecontentreplace ?? []) {
      const m = /^\/(.*[^\\])\/([^/]+)\/$/s.exec(p.replace(/§§version§§/g, VERSION));
      if (m) out.push({ lib, src: m[1]!, repl: m[2]! });
    }
  }
  return out;
}

// Plain CommonJS, evaluated in the worker: the only place a signature regex
// meets target text. First match per pattern, as retire.js does.
const WORKER_SRC = `
const { parentPort, workerData } = require("node:worker_threads");
const out = [];
for (const p of workerData.pats) {
  let re; try { re = new RegExp(p.src); } catch { continue; }
  const m = re.exec(workerData.content);
  if (!m) continue;
  const raw = p.repl === undefined ? m[1] : m[0].replace(re, p.repl);
  if (raw) out.push({ lib: p.lib, raw: String(raw).slice(0, 80), match: m[0].slice(0, 200) });
}
parentPort.postMessage(out);
`;

function matchInWorker(content: string, pats: Pat[], timeoutMs: number): Promise<{ lib: string; raw: string; match: string }[] | null> {
  return new Promise((resolve) => {
    const w = new Worker(WORKER_SRC, { eval: true, workerData: { content, pats } });
    let done = false;
    const finish = (v: { lib: string; raw: string; match: string }[] | null) => { if (done) return; done = true; clearTimeout(timer); void w.terminate(); resolve(v); };
    const timer = setTimeout(() => finish(null), timeoutMs);
    w.once("message", (v) => finish(v as { lib: string; raw: string; match: string }[]));
    w.once("error", () => finish(null));
    w.once("exit", () => finish(null));
  });
}

/** Libraries and exact versions readable from a script's CONTENT: the content
 * signatures (banner or minified code shape) and the whole-file SHA-1. Returns
 * null when the signatures did not finish before the deadline. */
export async function detectContent(db: RetireDb, content: string, timeoutMs = MATCH_TIMEOUT_MS): Promise<Detection[] | null> {
  const out: Detection[] = [];
  const seen = new Set<string>();
  const push = (d: Detection) => { const k = `${d.lib}@${d.version}`; if (!seen.has(k)) { seen.add(k); out.push(d); } };
  const sha1 = createHash("sha1").update(content, "utf8").digest("hex");
  for (const [lib, e] of Object.entries(db)) {
    const raw = e.hashes?.[sha1];
    const version = raw ? exactVersion(raw) : undefined;
    if (version) push({ lib, version, via: "hash", match: `sha1 ${sha1}` });
  }
  const hits = await matchInWorker(content, contentPatterns(db), timeoutMs);
  if (hits === null) return null;
  for (const h of hits) {
    const version = exactVersion(h.raw);
    if (version) push({ lib: h.lib, version, via: "content", match: h.match });
  }
  return out;
}

/** Libraries and versions a script URL names (file name and path patterns).
 * A full x.y.z is required: on a CDN, `jquery@3` or `3.4` is a moving range. */
export function detectUrl(db: RetireDb, url: string): Detection[] {
  const out: Detection[] = [];
  let u: URL;
  try { u = new URL(url); } catch { return out; }
  const full = (u.origin + u.pathname).slice(0, 2000);
  const file = u.pathname.split("/").pop()!.slice(0, 300);
  const first = (pats: string[] | undefined, hay: string): string | undefined => {
    for (const p of pats ?? []) {
      try { const m = new RegExp(p.replace(/§§version§§/g, VERSION)).exec(hay); if (m?.[1]) return m[1]; } catch { /* a malformed pattern never aborts the scan */ }
    }
    return undefined;
  };
  for (const [lib, e] of Object.entries(db)) {
    const raw = first(e.filename, file) ?? first(e.uri, full);
    const version = raw ? exactVersion(raw, 3) : undefined;
    if (version) out.push({ lib, version, via: "url", match: full });
  }
  return out;
}

/** True when the URL sits on a public CDN that serves immutable versioned files. */
export function isVersionedCdn(url: string): boolean {
  try { return VERSIONED_CDNS.has(new URL(url).hostname.toLowerCase()); } catch { return false; }
}

/** HTML with its comments removed (a commented-out <script> is not loaded). Linear. */
function stripHtmlComments(html: string): string {
  let out = "", i = 0;
  for (;;) {
    const a = html.indexOf("<!--", i);
    if (a === -1) return out + html.slice(i);
    out += html.slice(i, a);
    const b = html.indexOf("-->", a + 4);
    if (b === -1) return out;
    i = b + 3;
  }
}

const isScriptUrl = (u: string) => { try { return /\.m?js$/i.test(new URL(u).pathname); } catch { return false; } };

function finding(db: RetireDb, d: Detection, url: string, page: string, proven: boolean): Finding | undefined {
  const hits = advisoriesFor(db[d.lib], d.version);
  if (hits.length === 0) return undefined;
  const ids = [...new Set(hits.flatMap((h) => (h.cve?.length ? h.cve : h.ghsa ? [h.ghsa] : [])))];
  const severity = hits.map((h) => h.severity ?? "medium").sort((a, b) => (SEVERITY_RANK[b] ?? 2) - (SEVERITY_RANK[a] ?? 2))[0]!;
  const worst = hits.find((h) => (h.severity ?? "medium") === severity) ?? hits[0]!;
  const fixed = hits.map((h) => h.below!).sort(cmpVersion).pop()!;
  const shown = ids.slice(0, 8).join(", ") + (ids.length > 8 ? `, +${ids.length - 8} more` : "");
  const needle = d.match.split(/[\r\n]/)[0]!.slice(0, 80);
  const how = d.via === "content" ? { method: "live: the served script's own content states this library and exact version (retire.js content signature); the version is inside the advisory's documented vulnerable range", replay: `curl -s ${shellQuote(url)} | grep -c -F -- ${shellQuote(needle)}` }
    : d.via === "hash" ? { method: "live: the served file's SHA-1 is the one retire.js records for this exact release; the version is inside the advisory's documented vulnerable range", replay: `curl -s ${shellQuote(url)} | sha1sum` }
    : proven ? { method: "live: the page loads this script from a public CDN whose path is immutable per release, so the URL names the exact version; the version is inside the advisory's documented vulnerable range", replay: `curl -s ${shellQuote(page)} | grep -o -F -- ${shellQuote(url)}` }
    : { method: "lead: only the script's file name or path names this version; the content carries no signature confirming it", replay: `curl -s ${shellQuote(url)} | head -c 400` };
  return {
    id: `vuln-libs:${d.lib}:${d.version}`,
    check: "vuln-libs",
    title: `${proven ? "Vulnerable" : "Possibly vulnerable"} front-end library served: ${d.lib} ${d.version} (${ids[0]}${ids.length > 1 ? ` and ${ids.length - 1} more` : ""})`,
    severity: (proven ? severity : "low") as Severity,
    state: proven ? "proven" : "unproven",
    location: url,
    description: `${proven ? "The target serves" : "A script URL suggests the target serves"} ${d.lib} ${d.version}. Public advisories cover this exact version: ${shown}${worst.summary ? ` (${worst.summary})` : ""}. Fixed from ${fixed}. Whether a given advisory is reachable depends on how the application calls the library; the vulnerable code itself is what visitors download.`,
    remediation: `Upgrade ${d.lib} to ${fixed} or later (or remove it), and scan front-end dependencies in CI.`,
    proof: { ...how, evidence: `${d.lib} ${d.version} at ${url} [${d.via}: ${needle}]; ${shown}` },
    regressionHint: `After the upgrade, ${url} must not serve ${d.lib} below ${fixed}.`,
  };
}

export const vulnLibs: Check = {
  name: "vuln-libs",
  title: "A known-vulnerable front-end library is served (exact version read from the bundle)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const opts = (ctx.options["vuln-libs"] ?? {}) as { maxScripts?: number; timeoutMs?: number };
    const db = RETIRE_DB;
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    const pageUrl = base + "/";
    const byId = new Map<string, Finding>();
    const keep = (f: Finding | undefined) => { if (f && (!byId.has(f.id) || (f.state === "proven" && byId.get(f.id)!.state !== "proven"))) byId.set(f.id, f); };
    try {
      ctx.scope.assertUrlAllowed(base);
      const page = await safeFetch(pageUrl, ctx.scope, { method: "GET", maxBytes: 2 * 1024 * 1024 });
      const queue: string[] = [];
      const queued = new Set<string>();
      for (const u of extractAssetUrls(stripHtmlComments(page.body), pageUrl, "html")) {
        if (!/^https?:/.test(u) || queued.has(u)) continue;
        queued.add(u);
        if (ctx.scope.isHostAllowed(u)) { if (isScriptUrl(u)) queue.push(u); continue; }
        // Off-scope script: never fetched. Its URL alone decides, and only an
        // immutable versioned CDN makes that a proof.
        for (const d of detectUrl(db, u)) keep(finding(db, d, u, pageUrl, isVersionedCdn(u)));
      }
      const max = opts.maxScripts ?? MAX_SCRIPTS;
      for (let i = 0; i < queue.length && i < max; i++) {
        const u = queue[i]!;
        let body: string;
        try {
          const r = await safeFetch(u, ctx.scope, { method: "GET", maxBytes: SCRIPT_MAX_BYTES });
          // A 200 text/html here is the SPA fallback page, not a script.
          if (r.status !== 200 || /text\/html/i.test(r.headers.get("content-type") ?? "")) continue;
          body = r.body;
        } catch { continue; }
        const inContent = await detectContent(db, body, opts.timeoutMs ?? MATCH_TIMEOUT_MS);
        if (inContent === null) { ctx.log(`vuln-libs: signatures timed out on ${u}, file skipped`); continue; }
        for (const d of inContent) keep(finding(db, d, u, pageUrl, true));
        // A version only the file name or path states stays a lead, and is
        // dropped when the content names a version of that library itself.
        for (const d of detectUrl(db, u)) if (!inContent.some((c) => c.lib === d.lib)) keep(finding(db, d, u, pageUrl, false));
        for (const c of extractAssetUrls(body, u, "js")) if (!queued.has(c) && isScriptUrl(c) && ctx.scope.isHostAllowed(c)) { queued.add(c); queue.push(c); }
      }
    } catch (err) {
      ctx.log(`vuln-libs: ${(err as Error).message}`);
    }
    const findings = [...byId.values()];
    ctx.log(`vuln-libs: ${findings.filter((f) => f.state === "proven").length} proven, ${findings.filter((f) => f.state !== "proven").length} lead(s)`);
    return findings;
  },
};
