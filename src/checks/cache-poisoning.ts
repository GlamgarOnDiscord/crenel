// cache-poisoning: a response that reflects an unkeyed header (X-Forwarded-Host,
// X-Forwarded-Proto) and is then stored by the cache, so the next visitor gets
// the attacker's value: a script or redirect pointing at their host
// (PortSwigger's "practical web cache poisoning" method).
//
// GETs only, but the test writes one entry into a shared cache, so it runs only
// with allowActiveTesting AND options.cache-poisoning.enabled: true. Every URL
// carries a unique cache key `?crenel=<nonce>` that no real user requests, and
// the sentinel is a host under .invalid, which never resolves. Before any
// poisoning request, a fresh nonce must not come back as a cache hit: a cache
// that ignores the query string would put the entry on the real page, so the
// path is skipped.
//
//   1. GET <path>?crenel=n1 with the header set to the sentinel; the response
//      must reflect it (otherwise nothing to cache);
//   2. GET <path>?crenel=n1 without the header: the sentinel coming back means
//      the cache stored the poisoned response (proven);
//   3. negative control: GET <path>?crenel=n2 without the header shows no
//      sentinel, so the reflection is tied to the cache entry.

import { randomBytes } from "node:crypto";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch, type SafeResponse } from "../core/net.js";

export const DEFAULT_HEADERS = ["x-forwarded-host", "x-forwarded-proto"];
interface Opts { enabled?: boolean; paths?: string[]; headers?: string[] }

const nonce = () => randomBytes(6).toString("hex");

/** True when the response says it came from the cache. */
export function cacheHit(res: Pick<SafeResponse, "headers">): boolean {
  const h = res.headers;
  if (/\bhit\b/i.test(h.get("cf-cache-status") ?? "") || /\bhit\b/i.test(h.get("x-cache") ?? "") || /\bhit\b/i.test(h.get("x-vercel-cache") ?? "")) return true;
  const age = Number(h.get("age") ?? "0");
  return Number.isFinite(age) && age > 0;
}

export function reflects(res: Pick<SafeResponse, "headers" | "body">, sentinel: string): boolean {
  if (res.body.includes(sentinel)) return true;
  for (const [, v] of res.headers) if (v.includes(sentinel)) return true;
  return false;
}

export const cachePoisoning: Check = {
  name: "cache-poisoning",
  title: "Unkeyed header reflected and stored by the cache (web cache poisoning)",
  readOnly: true, // GETs; writes one cache entry under a unique key, so double opt-in below
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["cache-poisoning"] ?? {}) as Opts;
    if (!ctx.stagingUrl || !o.enabled || !ctx.scope.allowActiveTesting) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const out: Finding[] = [];
    for (const path of o.paths ?? ["/"]) {
      const at = (n: string) => `${base}${path}${path.includes("?") ? "&" : "?"}crenel=${n}`;
      try {
        const pre = await safeFetch(at(nonce()), ctx.scope, { followRedirects: false });
        if (cacheHit(pre)) { ctx.log(`cache-poisoning: ${path}: a fresh cache key came back as a hit (the cache ignores the query string), skipped so real visitors are never served a test entry`); continue; }
      } catch (err) { ctx.log(`cache-poisoning: ${path}: ${(err as Error).message}`); continue; }
      for (const header of (o.headers ?? DEFAULT_HEADERS).map((h) => h.toLowerCase())) {
        const n1 = nonce(), sentinel = header === "x-forwarded-proto" ? `crenel${nonce()}` : `crenel-${nonce()}.invalid`;
        const url = at(n1);
        try {
          const poisoned = await safeFetch(url, ctx.scope, { headers: { [header]: sentinel }, followRedirects: false });
          if (!reflects(poisoned, sentinel)) continue;
          const replay = await safeFetch(url, ctx.scope, { followRedirects: false });
          if (!reflects(replay, sentinel)) continue;
          const control = await safeFetch(at(nonce()), ctx.scope, { followRedirects: false });
          if (reflects(control, sentinel)) { ctx.log(`cache-poisoning: ${path}: the sentinel shows on an unrelated key too, not tied to the cache entry`); continue; }
          const hit = replay.headers.get("cf-cache-status") ?? replay.headers.get("x-cache") ?? replay.headers.get("x-vercel-cache") ?? (replay.headers.get("age") ? `age ${replay.headers.get("age")}` : "");
          out.push({
            id: `cache-poisoning:${path}:${header}`, check: "cache-poisoning", severity: "high", state: "proven",
            title: `${header} is reflected on ${path} and the cache serves it to the next visitor`,
            location: `${base}${path}`,
            description: `A GET of ${path} with ${header}: ${sentinel} returned a response containing that value, and the same URL requested without the header then returned it again${hit ? ` (cache: ${hit})` : ""}: the cache stored it. The header is not part of the cache key, so anyone can make the cached page point scripts, links or redirects at their own host for every visitor. A URL with another cache key shows nothing (control).`,
            remediation: `Do not build URLs from ${header} (configure the canonical host or trust it only from your own proxy), or add it to the cache key (Vary) or strip it at the edge.`,
            proof: { method: "poisoning GET with the header under a unique cache key, the same key fetched without it, another key as control", replay: `curl -s -H '${header}: ${sentinel}' '${url.replace(n1, "<nonce>")}' >/dev/null; curl -s '${url.replace(n1, "<nonce>")}' | grep -c '${sentinel.startsWith("crenel-") ? ".invalid" : "crenel"}'`, evidence: `sentinel reflected without the header on the second GET${hit ? `, ${hit}` : ""}; control key clean` },
            regressionHint: `GET ${path} with ${header} set to a foreign host must not change what the next plain GET of the same URL returns.`,
          });
        } catch (err) { ctx.log(`cache-poisoning: ${url}: ${(err as Error).message}`); }
      }
    }
    ctx.log(`cache-poisoning: ${out.length} finding(s)`);
    return out;
  },
};
