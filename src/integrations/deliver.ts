// One outbound POST to an integration destination.
//
// This is not a probe and does not go through the scan's scoped client: it
// goes to a host the user declared as a destination, and is checked here:
//   - https only (plain http only to localhost, for a local receiver);
//   - the host is in options.integrations.allowedHosts (exact match);
//   - the host is NOT a scan target (scope.allowedHosts): a notification never
//     becomes a request to the system under test;
//   - redirects are not followed (a 3xx is a failed delivery);
//   - 10 s timeout, the response body read up to 2 KB.
// Every attempt, sent or refused, produces a record the caller journals. A
// record names the host and the status, never the URL path, the body or a
// secret.

import { redact } from "./secrets.js";

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body?: string; redirect: "manual"; signal: AbortSignal }) => Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string>; body?: ReadableStream<Uint8Array> | null }>;

const MAX_RESPONSE = 2048;

/** The first 2 KB of a response, without reading the rest: a destination could answer with an endless body. */
async function readCapped(res: Awaited<ReturnType<FetchLike>>): Promise<string> {
  if (!res.body) return (await res.text().catch(() => "")).slice(0, MAX_RESPONSE);
  const reader = res.body.getReader(), chunks: Uint8Array[] = [];
  let n = 0;
  try {
    while (n < MAX_RESPONSE) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); n += value.length; }
  } catch { /* keep what came */ } finally { void reader.cancel().catch(() => {}); }
  return Buffer.concat(chunks).toString("utf8").slice(0, MAX_RESPONSE);
}

export interface DeliveryRecord {
  at: string;
  kind: "integration";
  integration: string;
  event: string;
  host: string;
  ok: boolean;
  status?: number;
  /** Short reason: the provider's error code or a refusal. Never a secret. */
  error?: string;
  ms: number;
  run?: string;
}

export interface DeliverOptions {
  integration: string;
  event: string;
  url: string;
  body: string;
  headers?: Record<string, string>;
  /** options.integrations.allowedHosts */
  allowedHosts: string[];
  /** scope.allowedHosts: refused as destinations. */
  scanHosts: string[];
  fetch?: FetchLike;
  timeoutMs?: number;
  run?: string;
  /** Secrets to scrub from error messages. */
  secrets?: string[];
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export class DestinationError extends Error {}

/** Throws a DestinationError when the URL may not be used as a destination. */
export function checkDestination(url: string, allowedHosts: string[], scanHosts: string[]): URL {
  let u: URL;
  try { u = new URL(url); } catch { throw new DestinationError("invalid URL"); }
  const host = u.hostname.toLowerCase();
  if (u.protocol !== "https:" && !(u.protocol === "http:" && LOOPBACK.has(host))) throw new DestinationError("https required (plain http only to localhost)");
  if (u.username || u.password) throw new DestinationError("credentials in the URL are refused");
  if (scanHosts.some((h) => h.toLowerCase() === host)) throw new DestinationError(`${host} is a scan target (scope.allowedHosts), not a destination`);
  if (!allowedHosts.some((h) => h.toLowerCase() === host)) throw new DestinationError(`${host} is not in options.integrations.allowedHosts`);
  return u;
}

export interface DeliveryResult {
  /** What gets journaled. */
  record: DeliveryRecord;
  /** First 2 KB of the response (Slack's error code, for instance). Not journaled. */
  responseText?: string;
  retryAfter?: string | null;
}

export async function deliver(o: DeliverOptions): Promise<DeliveryResult> {
  const t0 = Date.now();
  const rec = (r: Partial<DeliveryRecord> & { ok: boolean }, host: string): DeliveryRecord => ({
    at: new Date(t0).toISOString(), kind: "integration", integration: o.integration, event: o.event, host, ms: Date.now() - t0,
    ...(o.run ? { run: o.run } : {}), ...r,
  });
  let u: URL;
  try {
    u = checkDestination(o.url, o.allowedHosts, o.scanHosts);
  } catch (err) {
    let host = "";
    try { host = new URL(o.url).hostname; } catch { /* invalid */ }
    return { record: rec({ ok: false, error: `refused: ${(err as Error).message}` }, host) };
  }
  const f = o.fetch ?? (globalThis.fetch as unknown as FetchLike);
  try {
    const res = await f(u.toString(), {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "Crenel-Integrations/1", ...o.headers },
      body: o.body,
      redirect: "manual",
      signal: AbortSignal.timeout(o.timeoutMs ?? 10_000),
    });
    const text = await readCapped(res);
    const ok = res.status >= 200 && res.status < 300;
    const error = ok ? undefined : res.status >= 300 && res.status < 400 ? "redirect not followed" : (text.trim().split("\n")[0] ?? "").slice(0, 120) || `HTTP ${res.status}`;
    return { record: rec({ ok, status: res.status, ...(error ? { error: redact(error, o.secrets ?? []) } : {}) }, u.hostname), responseText: text, retryAfter: res.headers.get("retry-after") };
  } catch (err) {
    const e = err as Error & { cause?: { code?: string } };
    const reason = e.name === "TimeoutError" ? "timeout" : e.cause?.code ?? e.message;
    return { record: rec({ ok: false, error: redact(String(reason).slice(0, 120), o.secrets ?? []) }, u.hostname) };
  }
}
