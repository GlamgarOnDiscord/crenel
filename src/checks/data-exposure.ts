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
import { resolveAccounts, sessionHeaders, sessionReplayHeaders, type LoginSpec, type Session } from "./session.js";

type PiiContract =
  | { policy: "owner-only"; ownerField: string; ownerValueEnv: string }
  | { policy: "canary"; canaryEnv: string };
interface Opts { endpoints?: string[]; as?: string; pii?: boolean | PiiContract }
const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/;

// A plausible real email address. Placeholders (noreply@, no-reply@, a bare
// example.com with no local part) are not someone's personal data.
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const PLACEHOLDER_EMAIL = /^(?:no-?reply|postmaster|mailer-daemon|do-?not-?reply|admin|support|info|example)@/i;
/** Distinct, real-looking email addresses anywhere in the JSON (PII). */
function leakedEmails(json: unknown, out: Set<string>, depth = 0): void {
  if (depth > 8 || json == null) return;
  if (typeof json === "string") { for (const m of json.matchAll(EMAIL)) { const e = m[0].toLowerCase(); if (!PLACEHOLDER_EMAIL.test(e)) out.add(e); } return; }
  if (typeof json !== "object") return;
  if (Array.isArray(json)) { for (const v of json) leakedEmails(v, out, depth + 1); return; }
  for (const v of Object.values(json as Record<string, unknown>)) leakedEmails(v, out, depth + 1);
}

function containsScalar(json: unknown, wanted: string, depth = 0): boolean {
  if (depth > 8 || json == null) return false;
  if (typeof json !== "object") return String(json) === wanted;
  return Object.values(json as Record<string, unknown>).some((v) => containsScalar(v, wanted, depth + 1));
}

function foreignPiiRecords(json: unknown, ownerField: string, owner: string, depth = 0): number {
  if (depth > 8 || !json || typeof json !== "object") return 0;
  if (Array.isArray(json)) return json.reduce((n, v) => n + foreignPiiRecords(v, ownerField, owner, depth + 1), 0);
  const o = json as Record<string, unknown>;
  const emails = new Set<string>();
  leakedEmails(o, emails);
  const own = o[ownerField];
  const here = emails.size > 0 && (typeof own === "string" || typeof own === "number") && String(own) !== owner ? 1 : 0;
  return here + Object.values(o).reduce<number>((n, v) => n + foreignPiiRecords(v, ownerField, owner, depth + 1), 0);
}

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
    const rawAccounts = ((ctx.options["authz-matrix"] ?? {}) as { accounts?: Record<string, Session & { login?: LoginSpec }> }).accounts ?? {};
    // Resolve only the selected actor. Logging every configured account in for a
    // one-actor read is unnecessary traffic and can mutate login/session state.
    const selected = o.as && rawAccounts[o.as] ? await resolveAccounts(ctx, { [o.as]: rawAccounts[o.as] }, "data-exposure") : {};
    const sess = o.as ? selected[o.as] : undefined;
    const headers = sessionHeaders(sess);
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
        if (found.size === 1) ctx.log(`data-exposure: ${ep} exposes one password-shaped value; a single value is a lead, not proof`);
        if (found.size >= 2) findings.push({
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
            replay: `curl -s ${JSON.stringify(url)}${sessionReplayHeaders(sess)} | grep -i password`,
            evidence: `${found.size} distinct plaintext passwords exposed at ${ep} (values redacted)`,
          },
          regressionHint: `After the fix, GET ${ep} must not return any password field.`,
        });
        if (o.pii) {
          const emails = new Set<string>();
          leakedEmails(json, emails);
          const contract = typeof o.pii === "object" ? o.pii : undefined;
          const canary = contract?.policy === "canary" && ENV_NAME.test(contract.canaryEnv) ? process.env[contract.canaryEnv] : undefined;
          const owner = contract?.policy === "owner-only" && ENV_NAME.test(contract.ownerValueEnv) ? process.env[contract.ownerValueEnv] : undefined;
          const foreign = contract?.policy === "owner-only" && owner ? foreignPiiRecords(json, contract.ownerField, owner) : 0;
          const canarySeen = !!(canary && containsScalar(json, canary));
          // Several emails are only a signal: a gated member directory may be
          // intentional. Proof needs an explicit owner-only policy plus a foreign
          // owner in the same record, or an operator-provided canary value.
          if (emails.size >= 2 || foreign > 0 || canarySeen) {
            const anon = await safeFetch(url, ctx.scope, { method: "GET", maxBytes: 4096 }).catch(() => null);
            const contractProof = foreign > 0 || canarySeen;
            findings.push({
                id: `data-exposure:pii:${ep}`,
                check: "data-exposure",
                title: contractProof
                  ? `Excessive data exposure: ${ep} violates its declared ${contract!.policy} privacy contract`
                  : `Possible excessive data exposure: ${ep} returns ${emails.size} personal emails`,
                severity: contractProof ? "high" : "medium",
                state: contractProof ? "proven" : "unproven",
                location: url,
                description: contractProof
                  ? `GET ${ep} with the selected ordinary account returned ${canarySeen ? "the declared privacy canary" : `${foreign} record(s) carrying personal email data whose ${contract!.policy === "owner-only" ? contract!.ownerField : "owner"} does not match the caller`}. This violates the operator-declared ${contract!.policy} contract.${anon ? ` Anonymous HTTP ${anon.status}.` : ""}`
                  : `GET ${ep} returned ${emails.size} distinct personal emails. That may be an intentional member directory; authentication status alone does not prove the records are unauthorized, so this remains a review lead.${anon ? ` Anonymous HTTP ${anon.status}.` : ""}`,
                remediation: `Return only the caller's own data, or scope the response to resources they own; never include other accounts' email, phone or vehicle in a list a normal user can read. Filter at the data layer, not the client.`,
                proof: {
                  method: contractProof ? `live authenticated GET checked against the declared ${contract!.policy} privacy contract` : "live authenticated GET; multiple PII values observed, authorization not established",
                  replay: `curl -s ${JSON.stringify(url)}${sessionReplayHeaders(sess, "A")} | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+' | sort -u`,
                  evidence: contractProof ? `${canarySeen ? "declared canary present" : `${foreign} foreign-owner PII record(s)`}; values redacted` : `${emails.size} distinct personal emails; values redacted; no owner/canary proof`,
                },
                regressionHint: `After the fix, GET ${ep} with a normal account must not return another account's email address.`,
              });
          }
        }
      } catch (err) {
        ctx.log(`data-exposure: ${ep} failed: ${(err as Error).message}`);
      }
    }
    ctx.log(`data-exposure: ${findings.length} endpoint(s) leaking credentials`);
    return findings;
  },
};
