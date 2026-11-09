// live-ssrf: prove a server-side request forgery out-of-band, the industry-standard
// way (Burp Collaborator / interactsh). The operator declares a request whose sink
// reaches a URL the caller controls, with the markers __CBHOST__ / __CBPORT__ /
// __NONCE__ where the callback address and a unique token go. The check stands up an
// ephemeral listener, sends the request, and proves SSRF only if the listener is hit
// with that exact nonce (so a shared or guessed path cannot fabricate it). Generic:
// the sink is config, the proof is the out-of-band hit; no target signature.
//
// The listener must be reachable from the target. On a normal deployment that is the
// scanner host (options.live-ssrf.callbackHost = the host the target can reach). When
// the target is a container on a restrictive bridge, run the scan from a sibling
// container and set callbackHost to that container's IP.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { startCallback, ssrfOracle } from "../agent/ssrf.js";
import { nonce } from "../agent/inject.js";

interface SsrfEndpoint {
  /** Path or absolute URL of the request that carries the SSRF sink. */
  url: string;
  /** HTTP method. Default POST. */
  method?: string;
  /** Request-body template with the markers __CBHOST__, __CBPORT__, __NONCE__. For a
   * JSON/GraphQL body, pass the whole body string (it is sent as-is). */
  body?: string;
  /** Extra headers (e.g. content-type). Default content-type: application/json. */
  headers?: Record<string, string>;
}

interface Opts {
  enabled?: boolean;
  /** The callback address the TARGET can reach back (the scanner host, or, for a
   * container target on a closed bridge, a sibling container's IP). */
  callbackHost?: string;
  /** A fixed callback port (so the body template can hard-code __CBPORT__). */
  callbackPort?: number;
  endpoints?: SsrfEndpoint[];
}

export const liveSsrf: Check = {
  name: "live-ssrf",
  title: "Server-side request forgery proven out-of-band (OOB callback)",
  readOnly: false, // sends crafted requests that make the server call out: active gate
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["live-ssrf"] ?? {}) as Opts;
    if (o.enabled !== true || !ctx.stagingUrl || !(o.endpoints?.length)) return [];
    ctx.scope.assertActiveAllowed("live-ssrf (crafted outbound-triggering requests)");
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    const host = o.callbackHost || "127.0.0.1";
    const findings: Finding[] = [];
    for (const ep of o.endpoints) {
      const url = ep.url.startsWith("http") ? ep.url : base + ep.url;
      if (!ctx.scope.isHostAllowed(url)) continue;
      const cb = await startCallback(host, typeof o.callbackPort === "number" ? o.callbackPort : 0);
      try {
        const n = nonce("ssrf");
        const body = (ep.body ?? "").replace(/__CBHOST__/g, host).replace(/__CBPORT__/g, String(cb.port)).replace(/__NONCE__/g, n);
        // Fire the request; the outbound call is what matters, not this response.
        safeFetch(url, ctx.scope, { method: ep.method ?? "POST", headers: ep.headers ?? { "content-type": "application/json" }, body, maxBytes: 64 * 1024 }).catch(() => {});
        for (let i = 0; i < 60 && !cb.hits().includes(n); i++) await new Promise((r) => setTimeout(r, 250));
        const r = ssrfOracle({ nonce: n, hits: cb.hits() });
        if (r.verdict !== "proven") { ctx.log(`live-ssrf: ${ep.url} no callback (host ${host}:${cb.port} reachable from the target?)`); continue; }
        findings.push({
          id: `live-ssrf:${ep.url}`,
          check: "live-ssrf",
          title: `Server-side request forgery (SSRF) at ${ep.url}`,
          severity: "high",
          state: "proven",
          location: url,
          description: `A request to ${ep.url} made the server fetch an attacker-chosen URL: ${r.reason}. The sink reaches arbitrary hosts, so internal services and cloud metadata are exposed.`,
          remediation: `Do not let user input choose the host of a server-side request; use an allowlist of destinations and block link-local / private ranges and redirects.`,
          proof: {
            method: "out-of-band callback on staging: a unique nonce injected into the request arrived at an ephemeral listener",
            replay: `send ${ep.method ?? "POST"} ${url} with the callback URL in the SSRF sink; the listener receives /<nonce>`,
            evidence: `out-of-band hit received for nonce ${n}`,
          },
          regressionHint: `After deploy, a callback URL in ${ep.url} must not produce an out-of-band request.`,
        });
      } catch (err) {
        ctx.log(`live-ssrf: ${ep.url} failed: ${(err as Error).message}`);
      } finally {
        await cb.close();
      }
    }
    return findings;
  },
};
