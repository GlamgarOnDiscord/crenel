// Scoped HTTP client. This is the P0 harness fix from the research: scope must
// live outside the model, in code. Every outbound request an agent or check
// makes goes through here, which enforces four things:
//
//   1. the host is in the Scope allowlist (you declared you own it);
//   2. the host does not resolve to a private/loopback/link-local address
//      (blocks SSRF and DNS-rebinding to internal services), unless the target
//      explicitly opts into private ranges for an internal staging box;
//   3. every redirect hop is re-validated against the same rules (a 302 cannot
//      smuggle the agent off scope);
//   4. the response body is capped, so a hostile target cannot flood context;
//   5. every request has a timeout and obeys the scope's kill switch, and the
//      scope's observer sees each request sent or refused (journal, budgets);
//   6. only GET and HEAD go out by default. A POST passes when its body is
//      provably a read (readOnlyPost); anything else needs allowActiveTesting;
//   7. a response that is Cloudflare Access's login gate, not the app, throws
//      AccessGateError (the host was not reached) and is recorded on the scope;
//      a declared Access service token is added for its exact host, https only,
//      on each hop that targets it and on no other;
//   8. the scope's request budget and pacing (maxRequests, ratePerSec).
//
// It is deliberately small and dependency-free.

import { lookup } from "node:dns/promises";
import { AccessGateError, Scope, ScopeError } from "./scope.js";
import { detectAccessGate } from "./access.js";

const MAX_REDIRECTS = 5;
const MAX_BYTES = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;

/** True for IPv4/IPv6 addresses that must never be reached from a scan. */
export function isPrivateIp(ip: string): boolean {
  const a = ip.toLowerCase();
  // IPv6
  if (a === "::1" || a === "::") return true;
  if (/^fe[89ab]/.test(a)) return true; // link-local fe80::/10
  if (/^fe[cdef]/.test(a)) return true; // deprecated site-local fec0::/10
  if (a.startsWith("fc") || a.startsWith("fd")) return true; // unique local fc00::/7
  if (a.startsWith("ff")) return true; // multicast ff00::/8
  if (a.startsWith("2002:")) return true; // 6to4
  if (a.startsWith("64:ff9b:")) return true; // NAT64 (embeds IPv4)
  if (a.startsWith("::ffff:")) {
    const rest = a.slice(7);
    if (rest.includes(".")) return isPrivateIp(rest); // v4-mapped, dotted form
    // v4-mapped in hex form (e.g. ::ffff:7f00:1 = 127.0.0.1): the last one or
    // two hextets encode the four IPv4 octets. A resolver or URL literal can
    // hand us this shape, so decode it rather than letting it look public.
    const groups = rest.split(":");
    if (groups.length <= 2 && groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) {
      const nums = groups.map((g) => parseInt(g, 16));
      const hi = nums.length === 2 ? nums[0]! : 0;
      const lo = nums.length === 2 ? nums[1]! : nums[0]!;
      return isPrivateIp(`${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`);
    }
    return false;
  }
  // Any other ::-prefixed form (v4-compatible ::a.b.c.d, reserved ::x) is not a
  // global-unicast address, so it must never be a scan target.
  if (a.startsWith("::")) return true;
  // IPv4
  const m = a.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [p0, p1, p2] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (p0 === 10) return true;
  if (p0 === 127) return true; // loopback
  if (p0 === 0) return true;
  if (p0 === 169 && p1 === 254) return true; // link-local
  if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;
  if (p0 === 192 && p1 === 168) return true;
  if (p0 === 100 && p1 >= 64 && p1 <= 127) return true; // CGNAT
  if (p0 === 192 && p1 === 0 && p2 === 0) return true; // 192.0.0.0/24 IETF
  if (p0 === 198 && (p1 === 18 || p1 === 19)) return true; // 198.18.0.0/15 benchmark
  if (p0 === 192 && p1 === 88 && p2 === 99) return true; // 6to4 relay anycast
  if (p0 >= 224) return true; // 224/4 multicast, 240/4 reserved, 255 broadcast
  return false;
}

async function assertResolvesPublic(host: string, allowPrivate: boolean): Promise<void> {
  if (allowPrivate) return;
  let addrs;
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    throw new ScopeError(`Refused: cannot resolve ${host}`);
  }
  for (const { address } of addrs) {
    if (isPrivateIp(address)) {
      throw new ScopeError(
        `Refused: ${host} resolves to a private address (${address}). ` +
          `Set scope.allowPrivate only for an internal staging box you own.`,
      );
    }
  }
}

export interface SafeResponse {
  status: number;
  url: string;
  headers: Headers;
  body: string;
  truncated: boolean;
}

const READ_METHODS = new Set(["GET", "HEAD"]);
// Credentials a redirect must not carry to another origin (fetch drops Authorization the same way).
const CREDENTIAL_HEADERS = new Set(["authorization", "cookie", "proxy-authorization", "apikey", "x-api-key"]);

/** The headers for the next hop: credentials only stay on the same origin, or on an http -> https upgrade of the same host. */
export function redirectHeaders(headers: Record<string, string> | undefined, from: string, to: string): Record<string, string> | undefined {
  if (!headers) return headers;
  const a = new URL(from), b = new URL(to);
  if (a.origin === b.origin || (a.protocol === "http:" && b.protocol === "https:" && a.hostname === b.hostname)) return headers;
  return Object.fromEntries(Object.entries(headers).filter(([k]) => !CREDENTIAL_HEADERS.has(k.toLowerCase())));
}
// MCP JSON-RPC calls that list or handshake, never call a tool or read a resource's content.
const MCP_READ = new Set(["initialize", "notifications/initialized", "tools/list", "resources/list", "resources/templates/list", "prompts/list"]);

/** A GraphQL document that can only read: no mutation or subscription anywhere (even as a name: conservative). */
export function isGraphqlQueryOnly(query: string): boolean {
  // One left-to-right pass, as GraphQL's lexer reads it: a `"""` inside a comment
  // or a `#` inside a string is not a token, so it can never hide code.
  const code = query.replace(/"""(?:\\"""|[\s\S])*?"""|"(?:\\.|[^"\\\n\r])*"|#[^\n\r]*/g, (t) => (t[0] === "#" ? "" : '""'));
  if (/\b(mutation|subscription)\b/i.test(code)) return false;
  return /^\s*(query\b|\{)/.test(code);
}

/**
 * Why a POST to `url` with `body` only reads, or null. Three shapes, checked on
 * the bytes that would be sent: a single GraphQL query, an MCP list or
 * handshake call, and OSV's batch lookup (a public metadata API).
 */
export function readOnlyPost(url: string, body: string | undefined): string | null {
  if (body === undefined) return null;
  let u: URL;
  try { u = new URL(url); } catch { return null; }
  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") return "osv-lookup";
  let j: unknown;
  try { j = JSON.parse(body); } catch { return null; }
  if (!j || typeof j !== "object" || Array.isArray(j)) return null; // batched GraphQL or JSON-RPC: refused
  const o = j as Record<string, unknown>;
  if (o.jsonrpc === "2.0" && typeof o.method === "string" && MCP_READ.has(o.method)) return "mcp-list";
  if (typeof o.query === "string" && Object.keys(o).every((k) => k === "query" || k === "variables" || k === "operationName") && isGraphqlQueryOnly(o.query)) return "graphql-query";
  return null;
}

/** Fetch `url`, enforcing the scope allowlist, no private IPs, and safe redirects. */
export async function safeFetch(
  url: string,
  scope: Scope,
  init: { method?: string; headers?: Record<string, string>; maxBytes?: number; followRedirects?: boolean; body?: string } = {},
): Promise<SafeResponse> {
  // A caller may raise the cap for one known-large read (registry metadata), never past 16 MB.
  const cap = Math.min(init.maxBytes ?? MAX_BYTES, 16 * 1024 * 1024);
  let current = url;
  let carried = init.headers;
  const method = (init.method ?? "GET").toUpperCase();
  if (!READ_METHODS.has(method) && !scope.allowActiveTesting && !(method === "POST" && readOnlyPost(url, init.body))) {
    const why = `Refused: ${method} ${url} is not a read and allowActiveTesting is off`;
    scope.onRequest?.({ method, url, refused: why });
    throw new ScopeError(why);
  }
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    try {
      scope.signal?.throwIfAborted();
      scope.assertUrlAllowed(current);
      // A host whose root is behind Access (the whole hostname is the Access
      // application) answers every path with the same login page: nothing more is
      // sent to it. A gate seen only on a sub-path (a path-scoped application)
      // leaves the rest of the host reachable.
      const known = scope.accessGates.get(new URL(current).hostname.toLowerCase());
      if (known && new URL(known.url).pathname === "/") throw new AccessGateError(known);
      await assertResolvesPublic(new URL(current).hostname, scope.allowPrivate);
      await scope.pace();
    } catch (err) {
      // Not a refusal of the scope: the host is known to be gated and nothing was sent.
      if (err instanceof AccessGateError) throw err;
      scope.onRequest?.({ method, url: current, refused: (err as Error).message });
      throw err;
    }

    const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
    const signal = scope.signal ? AbortSignal.any([scope.signal, timeout]) : timeout;
    let res: Response;
    // Service-token headers are recomputed for every hop: only this hop's exact host, only https.
    const access = scope.headersFor(current);
    const tokenSent = Object.keys(access).length > 0;
    const headers = tokenSent ? { ...carried, ...access } : carried;
    try {
      // A body only goes out when it passed readOnlyPost above, or under allowActiveTesting.
      res = await fetch(current, { method, headers, body: init.body, redirect: "manual", signal });
    } catch (err) {
      scope.onRequest?.({ method, url: current, error: (err as Error).message });
      throw err;
    }
    scope.onRequest?.({ method, url: current, status: res.status });

    // Cloudflare Access answered instead of the app (status/headers first; a
    // 401/403 body is read below). Never a pass or a fail on the app.
    const gateNow = detectAccessGate(res.status, res.headers, current);
    if (gateNow) {
      await res.body?.cancel().catch(() => {});
      throw gated(scope, current, res.status, gateNow, tokenSent);
    }

    // followRedirects: false returns the 3xx itself, so a check can read where it points without going there.
    if (res.status >= 300 && res.status < 400 && res.headers.get("location") && init.followRedirects !== false) {
      const next = new URL(res.headers.get("location")!, current).toString();
      await res.body?.cancel().catch(() => {});
      carried = redirectHeaders(carried, current, next);
      current = next; // re-validated at the top of the next iteration
      continue;
    }

    // Cap the body.
    const reader = res.body?.getReader();
    let received = 0, truncated = false;
    const chunks: Uint8Array[] = [];
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          if (received + value.length > cap) {
            chunks.push(value.slice(0, cap - received));
            truncated = true;
            await reader.cancel();
            break;
          }
          chunks.push(value);
          received += value.length;
        }
      }
    }
    const body = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
    if (res.status === 401 || res.status === 403) {
      const gateBody = detectAccessGate(res.status, res.headers, current, body);
      if (gateBody) throw gated(scope, current, res.status, gateBody, tokenSent);
    }
    return { status: res.status, url: current, headers: res.headers, body, truncated };
  }
  throw new ScopeError(`Refused: too many redirects from ${url}`);
}

function gated(scope: Scope, url: string, status: number, reason: string, tokenSent: boolean): AccessGateError {
  const gate = { host: new URL(url).hostname.toLowerCase(), url, status, reason, tokenSent };
  scope.noteAccessGate(gate);
  return new AccessGateError(gate);
}
