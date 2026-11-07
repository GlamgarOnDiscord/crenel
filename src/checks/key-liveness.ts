// Key liveness (trufflehog's method): does a found key still work? One read-only
// call to its own provider answers it: a key that authenticates is an incident
// now, a revoked one is history. Strictly opt-in: the secret is sent to the
// provider it belongs to, and only when that provider's API host is declared in
// scope.allowedHosts. Never a write, never anything but the documented
// "who am I / list" endpoint, and the secret never appears in reports or logs.

import type { Scope } from "../core/scope.js";
import { safeFetch } from "../core/net.js";

export type Liveness = "active" | "revoked" | "unknown";

interface Verifier {
  url: string;
  headers: (key: string) => Record<string, string>;
  /** Decide from the status (and body for APIs that always answer 200). */
  verdict: (status: number, body: string) => Liveness;
  /** What "active" means for this provider, appended to the finding (never stronger than the call shows). */
  activeNote?: string;
}

const byStatus = (status: number): Liveness => (status === 200 ? "active" : status === 401 ? "revoked" : "unknown");
const bearer = (key: string) => ({ authorization: `Bearer ${key}` });

/** Keyed by exposed-secrets pattern id. */
export const VERIFIERS: Record<string, Verifier> = {
  "stripe-secret": { url: "https://api.stripe.com/v1/balance", headers: bearer, verdict: (s) => (s === 200 || s === 403 ? "active" : s === 401 ? "revoked" : "unknown") },
  "stripe-restricted": { url: "https://api.stripe.com/v1/balance", headers: bearer, verdict: (s) => (s === 200 || s === 403 ? "active" : s === 401 ? "revoked" : "unknown") },
  "openai-key": { url: "https://api.openai.com/v1/models", headers: bearer, verdict: byStatus },
  "openai-project-key": { url: "https://api.openai.com/v1/models", headers: bearer, verdict: byStatus },
  "anthropic-key": { url: "https://api.anthropic.com/v1/models", headers: (k) => ({ "x-api-key": k, "anthropic-version": "2023-06-01" }), verdict: byStatus },
  "github-pat": { url: "https://api.github.com/user", headers: (k) => ({ authorization: `token ${k}`, "user-agent": "crenel" }), verdict: byStatus },
  "github-fine-grained-pat": { url: "https://api.github.com/user", headers: (k) => ({ authorization: `token ${k}`, "user-agent": "crenel" }), verdict: byStatus },
  "github-oauth": { url: "https://api.github.com/user", headers: (k) => ({ authorization: `token ${k}`, "user-agent": "crenel" }), verdict: byStatus },
  "slack-token": { url: "https://slack.com/api/auth.test", headers: bearer, verdict: (s, b) => (s !== 200 ? "unknown" : /"ok"\s*:\s*true/.test(b) ? "active" : /invalid_auth|token_revoked|account_inactive/.test(b) ? "revoked" : "unknown") },
  "sendgrid-key": { url: "https://api.sendgrid.com/v3/scopes", headers: bearer, verdict: byStatus },
  // Google: listing Gemini models is free and read-only. The key goes in x-goog-api-key, never the URL.
  // 200 = the key reaches the Gemini API; 400 API_KEY_INVALID = revoked; a 403 (referrer, IP or API
  // restriction, service disabled) says nothing about the key's other APIs: unknown.
  "google-api-key": { url: "https://generativelanguage.googleapis.com/v1beta/models", headers: (k) => ({ "x-goog-api-key": k }),
    verdict: (s, b) => (s === 200 ? "active" : s === 400 && /API_KEY_INVALID|API key not valid/.test(b) ? "revoked" : "unknown"),
    activeNote: "The Gemini API answered without a referrer: no referrer restriction was observed (IP or API restrictions on other Google services are not tested), and generation is billed to your project." },
  "npm-token": { url: "https://registry.npmjs.org/-/whoami", headers: bearer, verdict: byStatus },
};

/** The provider host a pattern's key would be sent to, or null when there is no verifier. */
export function verifierHost(patternId: string): string | null {
  const v = VERIFIERS[patternId];
  return v ? new URL(v.url).hostname : null;
}

/**
 * Check one key. Returns "unknown" without sending anything when the pattern has
 * no verifier or its provider host is not declared.
 */
export async function checkLiveness(patternId: string, key: string, scope: Scope, urlOverride?: string): Promise<{ liveness: Liveness; status?: number; host?: string; note?: string }> {
  const v = VERIFIERS[patternId];
  if (!v) return { liveness: "unknown" };
  const url = urlOverride ?? v.url;
  if (!scope.isHostAllowed(url)) return { liveness: "unknown", host: new URL(url).hostname };
  try {
    const res = await safeFetch(url, scope, { method: "GET", headers: v.headers(key) });
    const liveness = v.verdict(res.status, res.body);
    return { liveness, status: res.status, host: new URL(url).hostname, ...(liveness === "active" && v.activeNote ? { note: v.activeNote } : {}) };
  } catch {
    return { liveness: "unknown", host: new URL(url).hostname };
  }
}
