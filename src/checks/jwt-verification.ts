// jwt-verification: broken JWT signature verification on the deployed API, proven
// deterministically (no model). When the config declares protected endpoints and a
// test account, this forges tokens from that account's real JWT with the standard
// generic attacks — alg:none (+ case variants), RS256->HS256 algorithm confusion
// (the server's public key from the usual JWKS paths used as the HMAC secret), and
// a small weak-secret dictionary — and proves a bypass only when a forged token is
// ACCEPTED while the SAME token with a corrupted signature is REJECTED. Declaring
// the endpoints is config, like the authz matrix; the attack logic has no target
// signature. GET only, declared host only.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { forgeNoneVariants, forgeHs256, jwkToPems, WEAK_SECRETS, jwtForgeOracle, corruptSig, headerOf, isRsaAlg, isHmacAlg } from "../agent/jwt.js";

interface JwtOpts { endpoints?: string[]; as?: "a" | "b" | "c" }

async function jwksPems(base: string, ctx: CheckContext, jwksUrl?: string): Promise<string[]> {
  const pems: string[] = [];
  for (const p of [jwksUrl, "/.well-known/jwks.json", "/jwks.json", "/oauth/jwks"].filter((x): x is string => !!x)) {
    const url = p.startsWith("http") ? p : base + p;
    if (!ctx.scope.isHostAllowed(url)) continue;
    try {
      const r = await safeFetch(url, ctx.scope, { headers: { accept: "application/json" }, maxBytes: 64 * 1024 });
      if (r.status !== 200) continue;
      const j = JSON.parse(r.body) as { keys?: Record<string, unknown>[] };
      for (const k of j.keys ?? []) pems.push(...jwkToPems(k));
    } catch { /* next */ }
  }
  return [...new Set(pems)];
}

export const jwtVerification: Check = {
  name: "jwt-verification",
  title: "JWT signature verification broken on the deployed API",
  readOnly: true, // forged tokens on GET requests, declared host only
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    const opts = (ctx.options["jwt-verification"] ?? {}) as JwtOpts;
    const endpoints = opts.endpoints ?? [];
    if (!endpoints.length) return []; // opt-in: the user declares protected endpoints
    const as = opts.as ?? "a";
    const accounts = (ctx.options["authz-matrix"] as { accounts?: Record<string, { token?: string }> } | undefined)?.accounts ?? {};
    const token = accounts[as]?.token;
    if (!token) { ctx.log(`jwt-verification: no token for account ${as.toUpperCase()}`); return []; }
    const hdr = headerOf(token);
    const findings: Finding[] = [];
    for (const ep of endpoints) {
      const url = ep.startsWith("http") ? ep : base + ep;
      if (!ctx.scope.isHostAllowed(url)) continue;
      const read = async (tok: string) => { const r = await safeFetch(url, ctx.scope, { headers: { authorization: `Bearer ${tok}` }, maxBytes: 256 * 1024 }); return { status: r.status, body: r.body }; };
      const candidates: { how: string; token: string }[] = [];
      for (const t of forgeNoneVariants(token, { role: "admin" })) candidates.push({ how: "alg:none", token: t });
      if (isRsaAlg(hdr?.alg)) for (const pem of (await jwksPems(base, ctx)).slice(0, 8)) { const t = forgeHs256(token, pem); if (t) candidates.push({ how: "RS->HS algorithm confusion", token: t }); }
      if (isHmacAlg(hdr?.alg) || !hdr?.alg) for (const s of WEAK_SECRETS) { const t = forgeHs256(token, s); if (t) candidates.push({ how: `weak secret "${s}"`, token: t }); }
      for (const c of candidates.slice(0, 24)) {
        try {
          const forged = await read(c.token);
          if (!(forged.status >= 200 && forged.status < 300)) continue;
          const control = await read(corruptSig(c.token));
          if (jwtForgeOracle({ forged, control }).verdict !== "proven") continue;
          findings.push({
            id: `jwt-verification:${ep}:${c.how.split(" ")[0]}`,
            check: "jwt-verification",
            title: `JWT signature bypass (${c.how}) on ${ep}`,
            severity: "critical",
            state: "proven",
            location: url,
            description: `A forged token (${c.how}) is accepted on ${ep} while the same token with a corrupted signature is rejected: the server does not verify signatures correctly. Anyone can mint any identity.`,
            remediation: "Pass an explicit algorithm allowlist to the verifier (no 'none', no HS when the key is RSA), and validate kid/key types.",
            proof: { method: `forged token vs corrupted-signature control, GET ${ep}`, replay: `GET ${url} with a ${c.how} token`, evidence: `forged -> HTTP ${forged.status}, corrupted-sig -> HTTP ${control.status}` },
            regressionHint: `After deploy, a ${c.how} token on ${ep} must be rejected.`,
          });
          break; // one proof per endpoint is enough
        } catch { /* next candidate */ }
      }
    }
    if (!findings.length) ctx.log("jwt-verification: no forged token accepted on the declared endpoints");
    return findings;
  },
};
