// next-image: the Next.js image optimizer (/_next/image) fetching any host.
// The optimizer only downloads URLs that match images.remotePatterns; a
// pattern of "**" (or a hostname wildcard) turns it into an open proxy that
// fetches whatever a visitor names: server-side request forgery, and on
// versions before 16 internal addresses too.
//
// Crenel's own client only talks to the declared host. It asks the optimizer
// to fetch a control URL (default https://example.com/, an IANA-reserved
// example domain: public, free, stable) and reads Next's own answer:
//   "url" parameter is not allowed            remotePatterns refused it: fine
//   The requested resource isn't a valid image the server fetched it: proven
//   "url" parameter is valid but upstream ...  the server tried: proven
//   200 with an image content type             the server fetched it: proven
// The target server makes that one outbound request; Crenel never contacts
// the control URL. Negative control: the same endpoint without a url must
// answer Next's '"url" parameter is required', so a soft-200 page or another
// framework that echoes text is never read as the optimizer.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch, type SafeResponse } from "../core/net.js";

export const DEFAULT_CONTROL_URL = "https://example.com/";
const NOT_ALLOWED = /"url" parameter is not allowed/;
const FETCHED = /isn't a valid image|"url" parameter is valid but upstream response/;
const REQUIRED = /"url" parameter is required/;
const WIDTH_REFUSED = /"w" parameter \(width\) of \d+ is not allowed/;

export interface NextImageOptions { controlUrl?: string; path?: string }

/** What the optimizer's answer to the control URL says. */
export function readOptimizerAnswer(res: Pick<SafeResponse, "status" | "body" | "headers">): "fetched" | "refused" | "unknown" {
  if (NOT_ALLOWED.test(res.body)) return "refused";
  if (FETCHED.test(res.body)) return "fetched";
  if (res.status === 200 && /^image\//i.test(res.headers.get("content-type") ?? "")) return "fetched";
  return "unknown";
}

export const nextImage: Check = {
  name: "next-image",
  title: "Next.js image optimizer fetches any host (open remotePatterns)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options["next-image"] ?? {}) as NextImageOptions;
    const control = opts.controlUrl ?? DEFAULT_CONTROL_URL;
    try { if (!/^https?:$/.test(new URL(control).protocol)) throw new Error(); } catch {
      ctx.log(`next-image: controlUrl ${control} is not an http(s) URL, skipped`);
      return [];
    }
    const endpoint = base + (opts.path ?? "/_next/image");

    // Negative control: is this Next's optimizer at all?
    let bare: SafeResponse;
    try { bare = await safeFetch(endpoint, ctx.scope, { maxBytes: 16 * 1024 }); } catch { return []; }
    if (!REQUIRED.test(bare.body)) { ctx.log("next-image: no Next.js image optimizer on the declared host"); return []; }

    let res: SafeResponse | undefined, url = "";
    for (const w of [64, 640, 1080]) {
      url = `${endpoint}?url=${encodeURIComponent(control)}&w=${w}&q=75`;
      try { res = await safeFetch(url, ctx.scope, { maxBytes: 64 * 1024 }); } catch { return []; }
      if (!WIDTH_REFUSED.test(res.body)) break;
    }
    if (!res) return [];
    const answer = readOptimizerAnswer(res);
    ctx.log(`next-image: optimizer answered ${res.status} to the control URL (${answer})`);
    if (answer !== "fetched") return [];
    const host = new URL(base).host;
    return [{
      id: `next-image:${host}`, check: "next-image", severity: "high", state: "proven",
      title: `Next.js image optimizer on ${host} fetches any host it is given`,
      location: url,
      description: `/_next/image downloaded ${control}, a host the app has no reason to allow: images.remotePatterns accepts any hostname. Anyone can make your server fetch URLs of their choice (SSRF; before Next.js 16, internal and cloud-metadata addresses too) and use it as a free image proxy on your bandwidth.`,
      remediation: "List the exact image hosts in images.remotePatterns (protocol, hostname, pathname), never '**' or a bare wildcard; on Next.js 16 keep dangerouslyAllowLocalIP off. Upgrade Next.js for the 2026 image-optimizer advisories.",
      proof: {
        method: "GET of the optimizer with a control URL on an unrelated public host; Next's own answer shows it fetched it (the bare endpoint answering '\"url\" parameter is required' is the control that this is the optimizer). The target server made one outbound request to the control URL; Crenel never contacted it.",
        replay: `curl -s '${url}'`,
        evidence: `HTTP ${res.status}: ${res.body.slice(0, 160).replace(/\s+/g, " ")}`,
      },
      regressionHint: `GET ${new URL(url).pathname}${new URL(url).search} must answer 400 '"url" parameter is not allowed'.`,
    }];
  },
};
