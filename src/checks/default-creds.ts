// default-creds: a login endpoint accepts a well-known default/weak credential.
// This is NOT a brute-force and NOT a target signature: it tries a small, generic
// dictionary of universally-known weak passwords (the same idea as the JWT weak-
// secret dictionary) against accounts the operator declares (or conventional admin
// names), and proves a finding ONLY when a dictionary password is ACCEPTED while a
// random wrong password on the SAME account is REJECTED — the negative control
// that rules out an accept-all endpoint. Active (it submits logins), opt-in.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { randomBytes } from "node:crypto";

interface CredEndpoint {
  /** Path or absolute URL of the login endpoint. */
  url: string;
  /** Body field for the identity. Default "email". */
  userField?: string;
  /** Body field for the password. Default "password". */
  passField?: string;
  /** Accounts (emails/usernames) to try the dictionary against. Required: with no
   * account the check does nothing, so a password list never hits an account the
   * operator did not name (which could lock it out). */
  accounts?: string[];
  /** HTTP method. Default POST. */
  method?: string;
}

// Universally-known weak / default passwords. Generic, not any one target's answer
// (the same spirit as a top-N password list); extend via options if needed.
const DEFAULT_PASSWORDS = [
  "admin", "admin123", "password", "Password1", "123456", "12345678", "changeme",
  "root", "toor", "test", "letmein", "welcome", "qwerty", "admin@123", "P@ssw0rd",
];

// A login is "accepted" when it answers 2xx AND carries a non-empty authentication
// artefact: a token/JWT value of real length in the body, or a session cookie with
// a real value. A bare key or the word "token" in prose is not enough — we require
// a plausible secret, so a 2xx page that merely mentions auth is not a login. The
// negative control (a wrong password on the same account, which must NOT be
// accepted) then rules out an accept-all endpoint.
const TOKEN_VALUE = /"(?:token|access[_-]?token|jwt|id[_-]?token|authorization)"\s*:\s*"([^"]{16,})"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/i;
function accepted(res: { status: number; body: string; headers: Headers }): boolean {
  if (res.status < 200 || res.status >= 300) return false;
  if (TOKEN_VALUE.test(res.body)) return true;
  // A session cookie whose value is a real, non-trivial secret (not a flag/empty).
  const sc = res.headers.get("set-cookie") ?? "";
  const m = /(?:sess[^=;]*|token|jwt|sid|auth[^=;]*)=([^;,\s]{12,})/i.exec(sc);
  return !!m && !/^(deleted|null|false|0|-)$/i.test(m[1] ?? "");
}

export const defaultCreds: Check = {
  name: "default-creds",
  title: "A login accepts a well-known default / weak credential",
  readOnly: false, // submits login attempts: active gate + opt-in
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["default-creds"] ?? {}) as { enabled?: boolean; endpoints?: CredEndpoint[]; passwords?: string[] };
    if (o.enabled !== true || !ctx.stagingUrl || !(o.endpoints?.length)) return [];
    ctx.scope.assertActiveAllowed("default-creds (login attempts)");
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    const dict = (o.passwords?.length ? o.passwords : DEFAULT_PASSWORDS);
    const findings: Finding[] = [];
    for (const ep of o.endpoints) {
      const url = ep.url.startsWith("http") ? ep.url : base + ep.url;
      if (!ctx.scope.isHostAllowed(url)) continue;
      const uf = ep.userField ?? "email", pf = ep.passField ?? "password";
      const method = ep.method ?? "POST";
      const login = async (user: string, pass: string) => {
        const body = JSON.stringify({ [uf]: user, [pf]: pass });
        // Do not follow redirects: a login that sets the session on a 3xx must be
        // read at the first hop so the initial Set-Cookie is visible.
        const r = await safeFetch(url, ctx.scope, { method, headers: { "content-type": "application/json" }, body, followRedirects: false, maxBytes: 64 * 1024 });
        return { status: r.status, body: r.body, headers: r.headers };
      };
      // Only accounts the operator explicitly declared are probed: trying a password
      // list against conventional names could lock out real accounts the operator
      // did not mean to test.
      for (const user of ep.accounts ?? []) {
        // Control FIRST: a random wrong password on this account must be rejected.
        // If it is accepted, the endpoint accepts anything — prove nothing here.
        let control;
        try { control = await login(user, "crenel-wrong-" + randomBytes(8).toString("hex")); } catch { continue; }
        if (accepted(control)) { ctx.log(`default-creds: ${user} accepts any password (not a default-cred finding)`); continue; }
        let hit: string | null = null;
        for (const pass of dict) {
          try { if (accepted(await login(user, pass))) { hit = pass; break; } } catch { /* next */ }
        }
        if (!hit) continue;
        findings.push({
          id: `default-creds:${ep.url}:${user}`,
          check: "default-creds",
          title: `Default/weak credential accepted for ${user} at ${ep.url}`,
          severity: "high",
          state: "proven",
          location: url,
          description: `The account ${user} logs in with the well-known password "${hit}" at ${ep.url}, while a random wrong password is rejected. Anyone can take over this account with a public password list.`,
          remediation: `Force a password reset for accounts using default/weak passwords; block common passwords at sign-up and on change; add rate limiting and MFA on login.`,
          proof: {
            method: "live login on staging: a well-known password is accepted while a random wrong password on the same account is rejected (negative control)",
            replay: `curl -i -X ${method} -H 'content-type: application/json' --data ${JSON.stringify(JSON.stringify({ [uf]: user, [pf]: hit }))} ${JSON.stringify(url)}  # authenticates; a wrong password returns ${control.status}`,
            evidence: `"${hit}" -> accepted; random wrong password -> HTTP ${control.status}`,
          },
          regressionHint: `After deploy, ${user} must not log in with "${hit}" at ${ep.url}.`,
        });
      }
    }
    if (findings.length === 0) ctx.log("default-creds: no default/weak credential accepted");
    return findings;
  },
};
