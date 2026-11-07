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
  { id: "csp", header: "content-security-policy", severity: "medium", title: "Content-Security-Policy absent", remediation: "Ajouter une CSP restrictive, d'abord en Content-Security-Policy-Report-Only." },
  { id: "hsts", header: "strict-transport-security", severity: "medium", title: "Strict-Transport-Security absent", remediation: "Ajouter HSTS: max-age d'au moins 6 mois, includeSubDomains." },
  { id: "xcto", header: "x-content-type-options", severity: "low", title: "X-Content-Type-Options absent", remediation: "Poser X-Content-Type-Options: nosniff." },
  { id: "xfo", header: "x-frame-options", severity: "low", title: "X-Frame-Options absent (ou frame-ancestors en CSP)", remediation: "Poser X-Frame-Options: DENY ou une directive frame-ancestors." },
  { id: "refpol", header: "referrer-policy", severity: "low", title: "Referrer-Policy absent", remediation: "Poser Referrer-Policy: strict-origin-when-cross-origin." },
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
        description: `La réponse de ${url} ne pose pas l'en-tête ${r.header}.`,
        remediation: r.remediation,
        proof: { method: "en-tête lu sur la réponse live", replay: `curl -sI ${url} | grep -i ${r.header}` },
      });
    }
  }
  const setCookie = headers.get("set-cookie");
  if (setCookie) {
    const low = setCookie.toLowerCase();
    const missing = ["secure", "httponly", "samesite"].filter((a) => !low.includes(a));
    if (missing.length) {
      out.push({
        id: `headers:cookie:${url}`,
        check: "headers",
        title: `Cookie sans ${missing.join(", ")}`,
        severity: "medium",
        state: "proven",
        location: `${url} (set-cookie)`,
        description: `Un cookie de la réponse n'a pas les attributs: ${missing.join(", ")}.`,
        remediation: "Poser Secure, HttpOnly et SameSite sur les cookies de session.",
        proof: { method: "en-tête Set-Cookie live", replay: `curl -sI ${url} | grep -i set-cookie` },
      });
    }
  }
  return out;
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
        title: "En-têtes de sécurité non vérifiés (pas d'URL de staging)",
        severity: "low",
        state: "unproven",
        location: ctx.projectDir,
        description: "Configurez scope.stagingUrl pour vérifier CSP, HSTS et les attributs de cookie sur la réponse live.",
        remediation: "Ajouter scope.stagingUrl dans la config, sur un hôte que vous possédez.",
      }];
    }
    try {
      const res = await safeFetch(ctx.stagingUrl, ctx.scope);
      const found = analyzeHeaders(res.headers, res.url);
      ctx.log(`headers: ${found.length} finding(s) on ${res.url}`);
      return found;
    } catch (err) {
      ctx.log(`headers: ${(err as Error).message}`);
      return [];
    }
  },
};
