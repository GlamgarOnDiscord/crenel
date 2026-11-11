// Open-redirect oracle for the exploration layer (explore.redirect).
//
// A login, logout or OAuth-callback route that sends the browser to whatever
// URL a parameter names is an open redirect: a phishing link that starts on
// your real domain, and in OAuth flows a way to leak codes and tokens to
// another host. The proof is a differential with its own control, like CORS:
// TWO distinct, unguessable sentinel hosts are injected into the parameter and
// the server redirects to BOTH. A route that always redirects to one fixed
// place reflects neither; a partial allowlist reflects neither of our random
// hosts. So "the target comes from the parameter" is proven, never a guess.
//
// Generic — no target signature. The sentinel hosts are random nonces under the
// .invalid TLD, which never resolves, and the redirect is read, never followed.
// Pure, so it is tested without a network.

import { metaRefreshUrl } from "../core/html.js";

export interface RedirectResp { status: number; location: string | null; body: string }

/** The host a response redirects to: a 3xx Location, else a meta-refresh URL in
 * the body, resolved against the request URL. null when it does not redirect or
 * the target does not parse. */
export function redirectHost(r: RedirectResp, reqUrl: string): string | null {
  const loc = r.status >= 300 && r.status < 400 ? (r.location ?? "").trim() : "";
  const meta = (metaRefreshUrl(r.body) ?? "").trim();
  const target = loc || meta;
  if (!target) return null;
  try { return new URL(target, reqUrl).hostname.toLowerCase(); } catch { return null; }
}

export function redirectOracle(input: {
  reqUrl: string;
  s1: string; r1: RedirectResp;
  s2: string; r2: RedirectResp;
}): { verdict: "proven" | "lead" | "denied"; reason: string; ceiling: "medium" } {
  const { reqUrl, s1, r1, s2, r2 } = input;
  const h1 = redirectHost(r1, reqUrl), h2 = redirectHost(r2, reqUrl);
  const hit1 = h1 === s1.toLowerCase(), hit2 = h2 === s2.toLowerCase();
  const seen = `got ${h1 ?? "no redirect"} and ${h2 ?? "no redirect"}`;
  if (hit1 && hit2) return { verdict: "proven", reason: `the redirect target is taken from the parameter: two distinct attacker hosts (${s1}, ${s2}) were both reflected into the redirect`, ceiling: "medium" };
  if (hit1 || hit2) return { verdict: "lead", reason: `one injected host was reflected into the redirect but not the other (${seen}): partial, review by hand`, ceiling: "medium" };
  return { verdict: "denied", reason: `the redirect target is not taken from the parameter (${seen})`, ceiling: "medium" };
}
