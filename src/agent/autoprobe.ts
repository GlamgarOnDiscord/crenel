// Deterministic auto-probe for the exploration layer (track B, honest variant).
//
// The free-exploration model finds a different subset each run (variance). This
// removes the model from the PROBE-GENERATION step: given the endpoints the
// deterministic recon discovered (and the configured test accounts), it submits a
// systematic set of claims — one per endpoint x applicable technique — to the SAME
// generic validators. Proof stays gated by the validators (no self-assertion, no
// signature); every request still goes through the scoped client. The result is
// reproducible (no run-to-run variance) and honest.
//
// autoClaims is pure (tested without a network); runAutoProbe validates each claim.

import type { Claim, ClaimVerdict, ValidatorEnv } from "./validators.js";
import { validateClaim, actorToken } from "./validators.js";

export interface Endpoint { url: string; params?: string[]; graphql?: boolean }

/** Build the systematic claim set for the discovered endpoints. Pure. `accounts`
 * are the configured test-account ids (a/b/c) that have a token. `origin` is the
 * scheme+host for the CORS probe. No target-specific values: only the endpoints the
 * recon already found and the generic techniques. */
export function autoClaims(input: { endpoints: Endpoint[]; accounts: string[]; origin?: string }): Claim[] {
  const { endpoints, accounts } = input;
  const has = (a: string) => accounts.includes(a);
  const claims: Claim[] = [];
  let n = 0;
  const add = (cls: string, detail: Record<string, unknown>) => claims.push({ id: `auto:${cls}:${n++}`, class: cls, source: "check", detail });

  if (input.origin) add("explore.cors", { url: input.origin });

  for (const ep of endpoints) {
    if (ep.graphql) add("explore.graphql", { url: ep.url });
    // Broken-auth / BOLA: anonymous read, and a cross-tenant read as A of B's object.
    if (has("b")) {
      add("explore.cross-actor", { url: ep.url, attacker: "anon", owner: "b" });
      if (has("a")) add("explore.cross-actor", { url: ep.url, attacker: "a", owner: "b" });
    }
    // JWT signature bypass against any endpoint that may be protected (needs an account token).
    if (has("a")) add("explore.jwt-forge", { url: ep.url, as: "a" });
    // Injection on each discovered parameter (query), and NoSQL body-template on the endpoint.
    for (const p of (ep.params ?? []).slice(0, 8)) add("explore.injection", { url: ep.url, param: p, where: "query" });
  }
  return claims;
}

export interface AutoProbeResult { proven: ClaimVerdict[]; tried: number }

/** Validate every auto-generated claim and keep the proven ones. The validators
 * enforce scope, controls and no-false-positive; this only drives them. */
export async function runAutoProbe(env: ValidatorEnv, input: { endpoints: Endpoint[]; origin?: string }, opts: { maxClaims?: number } = {}): Promise<AutoProbeResult> {
  const accounts = (["a", "b", "c"] as const).filter((a) => actorToken(env.options, a));
  const claims = autoClaims({ endpoints: input.endpoints, accounts, origin: input.origin }).slice(0, opts.maxClaims ?? 120);
  const proven: ClaimVerdict[] = [];
  for (const c of claims) {
    try { const v = await validateClaim(c, env); if (v.state === "proven") proven.push(v); } catch { /* a probe that throws is not a proof */ }
  }
  return { proven, tried: claims.length };
}
