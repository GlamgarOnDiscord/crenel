// header-injection: a request parameter flows into a response header without the
// CR/LF being stripped, so a caller can inject their own headers (CRLF / response
// splitting) — set a cookie, poison a cache, or smuggle a header. Proven by a
// differential: a value carrying `\r\n<header>: <nonce>` makes that exact header
// appear in the response, while a benign value does not. Generic (the oracle is
// "did our injected header appear with our nonce"), no target signature. The
// probe reaches the server through the URL, so Node never sanitises it for us.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { randomBytes } from "node:crypto";

const PATHS = ["/", "/login", "/logout", "/redirect", "/auth/callback", "/set-lang", "/lang"];
const PARAMS = ["redirect", "redirect_uri", "next", "returnTo", "url", "lang", "locale", "page", "ref"];

export const headerInjection: Check = {
  name: "header-injection",
  title: "Request parameter injects a response header (CRLF / response splitting)",
  readOnly: true, // GETs on the declared host; the response is read, never followed
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options["header-injection"] ?? {}) as { paths?: string[]; params?: string[] };
    const findings: Finding[] = [];
    for (const path of opts.paths ?? PATHS) {
      for (const param of opts.params ?? PARAMS) {
        const nonce = randomBytes(5).toString("hex");
        const marker = `x-crenel-ci`;
        // CRLF-encoded injected header after a benign value.
        const payload = `crenel%0d%0a${marker}:%20${nonce}`;
        const url = `${base}${path}?${param}=${payload}`;
        let res;
        try { res = await safeFetch(url, ctx.scope, { followRedirects: false, maxBytes: 4096 }); } catch { continue; }
        if ((res.headers.get(marker) ?? "").trim() !== nonce) continue; // the injected header did not appear
        // Control: a benign value must NOT produce the injected header.
        try {
          const clean = await safeFetch(`${base}${path}?${param}=crenel`, ctx.scope, { followRedirects: false, maxBytes: 4096 });
          if ((clean.headers.get(marker) ?? "").trim() === nonce) continue; // header present even without us: not injected
        } catch { /* control failed: fall through, the positive still stands */ }
        findings.push({
          id: `header-injection:${path}:${param}`,
          check: "header-injection",
          title: `Response header injection on ${path} via ?${param}= (CRLF)`,
          severity: "high",
          state: "proven",
          location: `${base}${path}`,
          description: `A CR/LF in ?${param}= reaches the response headers: our injected ${marker}: ${nonce} appeared, while a benign value did not. An attacker can set cookies, poison caches or split the response.`,
          remediation: `Strip CR and LF (and other control characters) from any value placed in a response header; never build a header from unvalidated input.`,
          proof: { method: "live differential on staging: a CRLF-injected header appears with our nonce, a benign value does not", replay: `curl -i '${url}'  # response carries ${marker}: ${nonce}`, evidence: `injected ${marker}: ${nonce} present with the payload, absent with a benign value` },
          regressionHint: `After deploy, a CRLF in ?${param}= at ${path} must not add a header to the response.`,
        });
      }
    }
    if (findings.length === 0) ctx.log("header-injection: no CRLF reached a response header");
    return findings;
  },
};
