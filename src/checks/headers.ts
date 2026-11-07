// headers: check the security headers and cookie flags of your own staging
// response. Read-only (a plain GET of a host you declared), routed through the
// scoped HTTP client. The header analysis is a pure function so it is unit
// tested without the network.

import type { Check, CheckContext, Finding, Severity } from "../core/types.js";
import { safeFetch } from "../core/net.js";

interface HeaderRule {
  id: string;
  header: string;
  severity: Severity;
  title: string;
  remediation: string;
}

const RULES: HeaderRule[] = [
  { id: "csp", header: "content-security-policy", severity: "medium", title: "Content-Security-Policy missing", remediation: "Add a restrictive CSP, starting with Content-Security-Policy-Report-Only." },
  { id: "hsts", header: "strict-transport-security", severity: "medium", title: "Strict-Transport-Security missing", remediation: "Add HSTS: max-age of at least 6 months, includeSubDomains." },
  { id: "xcto", header: "x-content-type-options", severity: "low", title: "X-Content-Type-Options missing", remediation: "Set X-Content-Type-Options: nosniff." },
  { id: "xfo", header: "x-frame-options", severity: "low", title: "X-Frame-Options missing (or CSP frame-ancestors)", remediation: "Set X-Frame-Options: DENY or a frame-ancestors directive." },
  { id: "refpol", header: "referrer-policy", severity: "low", title: "Referrer-Policy missing", remediation: "Set Referrer-Policy: strict-origin-when-cross-origin." },
];

// True only if the CSP has a frame-ancestors directive with a value that
// actually restricts framing. A bare `*`, or a value made only of scheme
// sources (http:, https:, ws:, wss:), allows any origin to frame the page and
// therefore does not replace X-Frame-Options.
export function cspRestrictsFraming(csp: string): boolean {
  const m = csp.toLowerCase().match(/frame-ancestors([^;]*)/);
  if (!m) return false;
  const tokens = m[1]!.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return false; // empty directive: no restriction
  if (tokens.includes("*")) return false; // wildcard: any origin may frame
  // Only scheme sources (no host) means any host of that scheme may frame.
  if (tokens.every((t) => /^(https?|wss?|data|blob):$/.test(t) || t === "*:")) return false;
  return true;
}

/** Pure: given a response's headers, return the security findings. */
export function analyzeHeaders(headers: Headers, url: string): Finding[] {
  const out: Finding[] = [];
  const csp = (headers.get("content-security-policy") ?? "").toLowerCase();
  for (const r of RULES) {
    // frame-ancestors in the CSP is the modern replacement for X-Frame-Options,
    // but only a RESTRICTIVE value protects against framing. A permissive one
    // (`frame-ancestors *`, or scheme-only sources) gives no protection, so it
    // must not suppress the finding.
    if (r.id === "xfo" && cspRestrictsFraming(csp)) continue;
    if (!headers.get(r.header)) {
      out.push({
        id: `headers:${r.id}:${url}`,
        check: "headers",
        title: r.title,
        severity: r.severity,
        state: "proven", // the header is deterministically absent from the live response
        location: url,
        description: `The response from ${url} does not set ${r.header}.`,
        remediation: r.remediation,
        proof: { method: "header read on the live response", replay: `curl -sI ${url} | grep -i ${r.header}` },
      });
    }
  }
  // CORS: credentials allowed together with a wildcard or null origin is a real
  // cross-origin data-exposure bug (a reflected origin + credentials is the
  // exploitable shape; `*` + credentials browsers block, but it signals the
  // same misconfigured intent, and `null` is reachable from sandboxed frames).
  const acac = (headers.get("access-control-allow-credentials") ?? "").toLowerCase().trim();
  const acao = (headers.get("access-control-allow-origin") ?? "").trim();
  if (acac === "true" && (acao === "*" || acao.toLowerCase() === "null")) {
    out.push({
      id: `headers:cors:${url}`,
      check: "headers",
      title: `CORS allows credentials with origin ${acao}`,
      severity: "high",
      state: "proven",
      location: `${url} (CORS)`,
      description: `The response sets Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: ${acao}. Another origin can read authenticated responses.`,
      remediation: "Allow credentials only for an allowlist of exact origins, never * or null, and refuse unknown origins.",
      proof: { method: "live CORS headers", replay: `curl -sI ${url} | grep -i access-control-allow-` },
    });
  }

  const setCookie = headers.get("set-cookie");
  if (setCookie) {
    const low = setCookie.toLowerCase();
    const missing = ["secure", "httponly", "samesite"].filter((a) => !low.includes(a));
    if (missing.length) {
      out.push({
        id: `headers:cookie:${url}`,
        check: "headers",
        title: `Cookie without ${missing.join(", ")}`,
        severity: "medium",
        state: "proven",
        location: `${url} (set-cookie)`,
        description: `A cookie in the response lacks: ${missing.join(", ")}.`,
        remediation: "Set Secure, HttpOnly and SameSite on session cookies.",
        proof: { method: "live Set-Cookie header", replay: `curl -sI ${url} | grep -i set-cookie` },
      });
    }
  }
  return out;
}

const CORS_SENTINEL = "https://crenel-cors-check.invalid";

/** Pure: a response to a request sent with the sentinel Origin. */
export function analyzeReflectedCors(headers: Headers, url: string): Finding | null {
  const acao = (headers.get("access-control-allow-origin") ?? "").trim();
  if (acao !== CORS_SENTINEL) return null;
  const creds = (headers.get("access-control-allow-credentials") ?? "").toLowerCase().trim() === "true";
  return {
    id: `headers:cors-reflect:${url}`,
    check: "headers",
    title: creds ? "CORS reflects any origin, with credentials" : "CORS reflects any origin",
    severity: creds ? "high" : "low",
    state: "proven",
    location: `${url} (CORS)`,
    description: creds
      ? `Sent with Origin: ${CORS_SENTINEL}, the response echoes it in Access-Control-Allow-Origin and allows credentials: any website a signed-in user visits can read their data from this API.`
      : `Sent with Origin: ${CORS_SENTINEL}, the response echoes it in Access-Control-Allow-Origin. Without credentials this exposes only public responses, but it shows the origin is not checked.`,
    remediation: "Compare the Origin against an allowlist of exact origins and answer nothing for the rest; never echo it back as-is.",
    proof: { method: "GET with a sentinel Origin under .invalid", replay: `curl -sI -H 'Origin: ${CORS_SENTINEL}' ${url} | grep -i access-control-allow-`, evidence: `Access-Control-Allow-Origin: ${acao}${creds ? ", Access-Control-Allow-Credentials: true" : ""}` },
  };
}

export const headers: Check = {
  name: "headers",
  title: "Security headers and cookie flags on your staging response",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) {
      ctx.log("headers: no stagingUrl configured");
      return [{
        id: "headers:no-staging",
        check: "headers",
        title: "Security headers not checked (no staging URL)",
        severity: "low",
        state: "unproven",
        location: ctx.projectDir,
        description: "Set scope.stagingUrl to check CSP, HSTS and cookie flags on the live response.",
        remediation: "Add scope.stagingUrl to the config, on a host you own.",
      }];
    }
    try {
      const res = await safeFetch(ctx.stagingUrl, ctx.scope);
      const found = analyzeHeaders(res.headers, res.url);
      // The exploitable CORS shape: the server echoes any Origin it is sent and
      // allows credentials. Ask once with a sentinel origin under .invalid.
      const probe = await safeFetch(ctx.stagingUrl, ctx.scope, { headers: { origin: CORS_SENTINEL } });
      const reflected = analyzeReflectedCors(probe.headers, probe.url);
      if (reflected) found.push(reflected);
      ctx.log(`headers: ${found.length} finding(s) on ${res.url}`);
      return found;
    } catch (err) {
      ctx.log(`headers: ${(err as Error).message}`);
      return [];
    }
  },
};
