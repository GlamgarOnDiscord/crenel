// Cloudflare Access awareness.
//
// A host behind Cloudflare Access answers every anonymous request with its
// login flow: a 302 to <team>.cloudflareaccess.com/cdn-cgi/access/login/<host>,
// a `WWW-Authenticate: Cloudflare-Access` header, a CF_AppSession cookie, or a
// 401/403 Access page. None of that is the app. Before this module a live check
// read that page as if it were the app: headers reported Cloudflare's missing
// CSP, open-redirect saw a 302 to another host, everything else "passed" on a
// page that never reached the code. Now the scoped client recognises the gate,
// records it on the scope, and throws AccessGateError, so every check treats the
// host as not reached; the run then reports ONE info lead per gated host.
//
// The way through is a service token (Cloudflare's documented headers
// CF-Access-Client-Id and CF-Access-Client-Secret,
// https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/).
// scope.access names, per exact host, the two environment variables that hold
// them. The values are read from the environment only (the config schema has
// no field for a value), sent only over https to that exact host (never on a
// redirect to another host, never over http://), and registered for redaction
// so a body echoing them never reaches a report, the journal or the console.

import type { Finding } from "./types.js";

export interface AccessTokenRef {
  /** Name of the environment variable holding the service token's Client ID. */
  clientIdEnv: string;
  /** Name of the environment variable holding the service token's Client Secret. */
  clientSecretEnv: string;
}

/** What the scoped client saw on a host gated by Access. */
export interface AccessGate {
  host: string;
  url: string;
  status: number;
  reason: string;
  /** True when service-token headers were sent on that request (so they were rejected). */
  tokenSent: boolean;
}

/* ---------- redaction ---------- */

const SECRETS = new Set<string>();

/** Remember a secret value so redact() masks it wherever it would be written. */
export function registerSecret(value: string): void {
  if (value.length >= 6) SECRETS.add(value);
}

/** Mask every registered secret: its first 4 characters, then "…[redacted]". */
export function redact(text: string): string {
  let out = text;
  for (const s of SECRETS) if (out.includes(s)) out = out.split(s).join(`${s.slice(0, 4)}…[redacted]`);
  return out;
}

export function hasSecrets(): boolean { return SECRETS.size > 0; }

/** Redact any JSON-serialisable value (journal entries, findings). */
export function redactDeep<T>(value: T): T {
  if (!SECRETS.size || value === undefined) return value;
  const s = JSON.stringify(value);
  if (s === undefined) return value;
  const r = redact(s);
  return r === s ? value : (JSON.parse(r) as T);
}

/** Findings with every registered secret masked (title, description, proof...). */
export function redactFindings(findings: Finding[]): Finding[] {
  return SECRETS.size ? findings.map((f) => redactDeep(f)) : findings;
}

/* ---------- service-token headers ---------- */

export interface ResolvedAccess {
  /** Exact host (lowercase) to the two headers sent to it. */
  headers: Record<string, Record<string, string>>;
  /** Host to a human reason the token could not be loaded (env var unset). */
  missing: Record<string, string>;
}

/**
 * Read the service tokens named in scope.access from the environment. A host
 * whose variables are unset gets no headers and a note, never a guess.
 */
export function resolveAccess(access: Record<string, AccessTokenRef> | undefined, env: NodeJS.ProcessEnv = process.env): ResolvedAccess {
  const out: ResolvedAccess = { headers: {}, missing: {} };
  for (const [rawHost, ref] of Object.entries(access ?? {})) {
    const host = rawHost.toLowerCase().trim();
    const id = env[ref.clientIdEnv];
    const secret = env[ref.clientSecretEnv];
    const unset = [!id && ref.clientIdEnv, !secret && ref.clientSecretEnv].filter(Boolean);
    if (unset.length) {
      out.missing[host] = `environment variable${unset.length > 1 ? "s" : ""} ${unset.join(" and ")} not set`;
      continue;
    }
    registerSecret(id!);
    registerSecret(secret!);
    out.headers[host] = { "CF-Access-Client-Id": id!, "CF-Access-Client-Secret": secret! };
  }
  return out;
}

/* ---------- detection ---------- */

function locationOf(headers: Headers, url: string): URL | null {
  const loc = headers.get("location");
  if (!loc) return null;
  try { return new URL(loc, url); } catch { return null; }
}

/**
 * Why this response is Cloudflare Access's gate rather than the app, or null.
 * Pure. Each signal is one Access sets itself; a page that merely mentions
 * "Cloudflare Access" with a 200 is the app and is not matched.
 */
export function detectAccessGate(status: number, headers: Headers, url: string, body = ""): string | null {
  let path = "";
  try { path = new URL(url).pathname; } catch { /* keep empty */ }
  if (path.startsWith("/cdn-cgi/access/login") || path.startsWith("/cdn-cgi/access/authorized")) return `served the Access login path ${path}`;
  const www = headers.get("www-authenticate") ?? "";
  if (/^\s*Cloudflare-Access\b/i.test(www)) return `WWW-Authenticate: Cloudflare-Access (HTTP ${status})`;
  if (status >= 300 && status < 400) {
    const loc = locationOf(headers, url);
    if (loc && (loc.hostname.endsWith(".cloudflareaccess.com") || loc.pathname.startsWith("/cdn-cgi/access/login"))) {
      return `HTTP ${status} to ${loc.hostname}${loc.pathname.startsWith("/cdn-cgi/access/login") ? "/cdn-cgi/access/login" : ""}`;
    }
  }
  if (status >= 300 && status < 500) {
    const cookies = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [headers.get("set-cookie") ?? ""];
    if (cookies.some((c) => /^\s*CF_AppSession=/i.test(c))) return `HTTP ${status} setting the CF_AppSession cookie`;
  }
  if ((status === 401 || status === 403) && /cloudflareaccess\.com|cf-access-|Cloudflare Access/i.test(body.slice(0, 20_000))) {
    return `HTTP ${status} Cloudflare Access page`;
  }
  return null;
}

/* ---------- finding ---------- */

export function accessFinding(gate: AccessGate, missing?: string): Finding {
  const why = gate.tokenSent
    ? "the service token Crenel sent was not accepted (wrong token, expired, or the Access policy has no Service Auth rule for it)"
    : missing
      ? `scope.access names a service token for this host but ${missing}`
      : "no service token is configured for this host (scope.access)";
  return {
    id: `cloudflare-access:${gate.host}`,
    check: "cloudflare-access",
    title: gate.tokenSent
      ? `${gate.host} protected by Cloudflare Access: service token rejected, live checks see only the login page`
      : `${gate.host} protected by Cloudflare Access: live checks see only the login page; provide a service token`,
    severity: "info",
    state: "unproven",
    location: `https://${gate.host}/`,
    description:
      `${gate.url} answered with Cloudflare Access (${gate.reason}), not with the app. Every live check on ${gate.host} ` +
      `treated it as not reached: nothing on this host was tested, so the absence of findings here means nothing. Cause: ${why}.`,
    remediation:
      "Create a Cloudflare Access service token for scanning, add a Service Auth policy for it on this application, " +
      "export its Client ID and Client Secret as environment variables and name them in the config: " +
      `scope.access: { "${gate.host}": { clientIdEnv: CRENEL_CF_ACCESS_ID, clientSecretEnv: CRENEL_CF_ACCESS_SECRET } }. ` +
      "Crenel sends CF-Access-Client-Id and CF-Access-Client-Secret only over https to this exact host.",
    proof: {
      method: "Access gate recognised on the live response",
      replay: `curl -sI https://${gate.host}/ | grep -iE '^(location|www-authenticate|set-cookie):'`,
      evidence: `${gate.status} ${gate.reason}`,
    },
  };
}

/** One info lead per host the scope saw behind Access, skipping ids already in `seen`. */
export function accessFindings(scope: { accessGates: Map<string, AccessGate>; accessMissing: Record<string, string> }, seen: Set<string> = new Set()): Finding[] {
  const out: Finding[] = [];
  for (const g of scope.accessGates.values()) {
    const f = accessFinding(g, scope.accessMissing[g.host]);
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    out.push(f);
  }
  return out;
}
