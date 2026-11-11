// data-exposure: a live endpoint hands back credentials in its response — an API
// returning every user's plaintext password, a debug route dumping secrets. This is
// excessive data exposure (OWASP API3), and it is deterministic: the response body
// carries the secrets. The operator declares the endpoints to read (from the API's
// own spec; the api-docs check surfaces the OpenAPI); the check GETs each and reports
// one that leaks credentials.
//
// Zero false positives come from a strict signal: at least two DISTINCT plaintext
// password values (not a hash, not a mask, not empty) under password-shaped keys, so
// a single schema field named "password" or a column of bcrypt hashes never triggers
// it. Read-only — plain GETs on declared, in-scope endpoints.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { resolveAccounts, type LoginSpec } from "./session.js";

interface Opts { endpoints?: string[]; as?: string }

const PASSWORD_KEY = /^(?:password|passwd|pwd|pass|user_?password|plainpassword)$/i;
// Values that are NOT a plaintext secret: a known hash, a mask, or a trivial blank.
const HASH = /^(\$2[aby]\$|\$argon2|\$pbkdf2|\$scrypt|\{SHA|\{SSHA|[a-f0-9]{32,}$|[A-Za-z0-9+/]{43}=?$)/i;
const MASK = /^(\*{3,}|•{3,}|x{3,}|\.{3,}|\[?redacted\]?|null|undefined|-+)$/i;

function isPlaintextSecret(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const s = v.trim();
  return s.length >= 3 && s.length <= 128 && !HASH.test(s) && !MASK.test(s);
}

/** Collect plaintext values held under a password-shaped key anywhere in the JSON. */
function leakedPasswords(json: unknown, out: Set<string>, depth = 0): void {
  if (depth > 8 || json == null || typeof json !== "object") return;
  if (Array.isArray(json)) { for (const v of json) leakedPasswords(v, out, depth + 1); return; }
  for (const [k, v] of Object.entries(json as Record<string, unknown>)) {
    if (PASSWORD_KEY.test(k) && isPlaintextSecret(v)) out.add(v);
    else leakedPasswords(v, out, depth + 1);
  }
}

export const dataExposure: Check = {
  name: "data-exposure",
  title: "A live endpoint returns credentials in its response (plaintext passwords exposed)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["data-exposure"] ?? {}) as Opts;
    const endpoints = o.endpoints ?? [];
    if (!ctx.stagingUrl || endpoints.length === 0) { if (endpoints.length) ctx.log("data-exposure: no staging URL"); return []; }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const declared = ((ctx.options["authz-matrix"] ?? {}) as { accounts?: Record<string, { token?: string; cookie?: string; login?: LoginSpec }> }).accounts ?? {};
    // Only the account this check reads as logs in (declared login, src/checks/session.ts).
    const accounts = o.as && declared[o.as]?.login ? await resolveAccounts(ctx, { [o.as]: declared[o.as] }, "data-exposure") : declared;
    const token = o.as ? accounts[o.as]?.token : undefined, cookie = o.as ? accounts[o.as]?.cookie : undefined;
    const headers: Record<string, string> = { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(cookie ? { cookie } : {}) };
    const findings: Finding[] = [];
    for (const ep of endpoints.slice(0, 40)) {
      const url = ep.startsWith("http") ? ep : base + (ep.startsWith("/") ? ep : "/" + ep);
      if (!ctx.scope.isHostAllowed(url)) continue;
      try {
        const r = await safeFetch(url, ctx.scope, { method: "GET", headers, maxBytes: 1024 * 1024 });
        if (r.status < 200 || r.status >= 300) continue;
        let json: unknown;
        try { json = JSON.parse(r.body); } catch { continue; }
        const found = new Set<string>();
        leakedPasswords(json, found);
        // Two or more DISTINCT plaintext passwords: an API handing back real
        // credentials, not a lone schema field. One is a lead, not a proof.
        if (found.size < 2) { if (found.size === 1) ctx.log(`data-exposure: ${ep} exposes one password-shaped value; a single value is a lead, not proof`); continue; }
        findings.push({
          id: `data-exposure:${ep}`,
          check: "data-exposure",
          title: `Endpoint ${ep} returns plaintext passwords (${found.size} exposed)`,
          severity: "critical",
          state: "proven",
          location: url,
          description: `GET ${ep} returns a response carrying ${found.size} distinct plaintext passwords under password-shaped keys. Anyone who can reach it harvests every account's credential — a direct account-takeover and credential-stuffing supply. Passwords must never leave the server in plaintext, and a response must never include a password field at all.`,
          remediation: `Remove the password (and any secret) from this response; never serialize credentials to a client. If this is a debug route, delete it or gate it behind a non-production flag and authentication. Store passwords only as a salted hash.`,
          proof: {
            method: "live GET on staging: the JSON response carries multiple plaintext passwords under password-shaped keys (values are not hashes or masks)",
            replay: `curl -s ${JSON.stringify(url)}${token ? " -H 'authorization: Bearer <TOKEN>'" : ""} | grep -i password`,
            evidence: `${found.size} distinct plaintext passwords exposed at ${ep} (values redacted)`,
          },
          regressionHint: `After the fix, GET ${ep} must not return any password field.`,
        });
      } catch (err) {
        ctx.log(`data-exposure: ${ep} failed: ${(err as Error).message}`);
      }
    }
    ctx.log(`data-exposure: ${findings.length} endpoint(s) leaking credentials`);
    return findings;
  },
};
