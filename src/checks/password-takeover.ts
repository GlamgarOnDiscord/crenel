// password-takeover: one account changes ANOTHER account's password — the sharpest
// BOLA/BFLA there is, a direct account takeover. A read-back cannot always see a
// password (it is write-only in most APIs), so the proof is the LOGIN itself: the
// attacker sets the victim's password to a value only the attacker knows, then logs
// in as the victim with it. If that login succeeds, the cross-account write landed —
// unarguable, and no stored marker needed. A control write to a NON-existent victim
// must be rejected first, so an accept-all endpoint proves nothing. The victim's
// password is then restored with the victim's own token, so the account is left
// working.
//
// Active (it writes, destructively, then restores): scope.allowActiveTesting AND
// options.password-takeover.enabled. Staging throwaway accounts only.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { ActiveClient, activeOptions, nonce, ok2xx, writesFinding, type ActiveBase } from "./active-common.js";
import { safeFetch } from "../core/net.js";

interface Login {
  /** Login endpoint, e.g. "/users/v1/login". */
  path: string;
  /** Body field for the identity / password. Defaults "username" / "password". */
  userField?: string;
  passField?: string;
  /** The victim's login identity (username/email). */
  victimUser: string;
  /** Extra body fields the login needs. */
  template?: Record<string, unknown>;
  /** What a SUCCESSFUL login looks like. Default: 2xx and a JWT in the body. */
  success?: { statuses?: number[]; bodyIncludes?: string };
}
interface TakeoverTarget {
  name: string;
  /** Password-change route with :id, e.g. "/users/v1/:id/password". */
  changePath: string;
  /** The victim's id for the :id in changePath. */
  victimId: string;
  /** PUT (default), PATCH or POST. */
  method?: string;
  /** Body that carries the new password; {{PW}} is replaced by the probe value. */
  body: string;
  /** How to confirm the takeover and restore afterwards. */
  login: Login;
  /** The victim's real password, to restore via the victim's own token. */
  restorePassword: string;
}
interface Opts extends ActiveBase { targets?: TakeoverTarget[] }

function loginOk(res: { status: number; body: string }, s?: Login["success"]): boolean {
  const statusOk = s?.statuses?.length ? s.statuses.includes(res.status) : ok2xx(res.status);
  if (!statusOk) return false;
  if (s?.bodyIncludes) return res.body.includes(s.bodyIncludes);
  return /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/.test(res.body) || /"(?:token|auth_token|access_token|jwt)"\s*:\s*"[^"]{16,}"/i.test(res.body);
}

export function plannedTakeover(options: Record<string, unknown>, base: string): { method: string; url: string }[] {
  const o = (options["password-takeover"] ?? {}) as Opts;
  if (o.enabled !== true) return [];
  const u = (p: string) => base.replace(/\/+$/, "") + (p.startsWith("/") ? p : "/" + p);
  return (o.targets ?? []).flatMap((t) => {
    const m = (t.method ?? "PUT").toUpperCase();
    const cp = u(t.changePath.replace(":id", encodeURIComponent(t.victimId)));
    return [{ method: m, url: cp }, { method: "POST", url: u(t.login.path) }, { method: m, url: cp }];
  });
}

export const passwordTakeover: Check = {
  name: "password-takeover",
  title: "An account changes another account's password (account takeover), active, staging only",
  readOnly: false,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = activeOptions<Opts>(ctx, "password-takeover");
    if (!o) return [];
    const targets = (o.targets ?? []);
    if (!ctx.stagingUrl || targets.length === 0) { ctx.log("password-takeover: needs a stagingUrl and options.password-takeover.targets"); return []; }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const attacker = o.accounts.a?.token, victim = o.accounts.b?.token;
    if (!attacker || !victim) { ctx.log("password-takeover: needs tokens for account a (attacker) and b (victim)"); return []; }
    const client = new ActiveClient(ctx, "password-takeover", o.maxRequests);
    const notes: string[] = [];
    const findings: Finding[] = [];
    const u = (p: string) => base + (p.startsWith("/") ? p : "/" + p);
    const login = async (user: string, pw: string, l: Login) => {
      const b = JSON.stringify({ ...(l.template ?? {}), [l.userField ?? "username"]: user, [l.passField ?? "password"]: pw });
      const r = await safeFetch(u(l.path), ctx.scope, { method: "POST", headers: { "content-type": "application/json" }, body: b });
      return { status: r.status, body: r.body };
    };

    for (const t of targets) {
      const method = (t.method ?? "PUT").toUpperCase();
      if (!t.name || !t.changePath?.includes(":id") || !t.victimId || !t.body || !t.login?.path || !t.login.victimUser || t.restorePassword === undefined) {
        notes.push(`${t.name ?? "(unnamed)"}: skipped, needs name, changePath with :id, victimId, body, login.path, login.victimUser and restorePassword.`);
        continue;
      }
      const changeUrl = (id: string) => u(t.changePath.replace(":id", encodeURIComponent(id)));
      const canary = `Crenel-${nonce()}-Aa1!`;
      try {
        client.reserve(4);
        // 1. Control: attacker changes a NON-existent victim's password. Must be rejected.
        const bogus = `crenel-nonexistent-${nonce()}`;
        const ctl = await client.send(method, changeUrl(bogus), attacker, JSON.parse(t.body.replace(/\{\{PW\}\}/g, canary)), { actor: "a", purpose: "control: change a non-existent account's password", restore: "nothing to restore" });
        if (ok2xx(ctl.status)) { notes.push(`${t.name}: changing a non-existent account's password was accepted (HTTP ${ctl.status}); the endpoint validates nothing, no proof.`); continue; }
        // 2. Attacker sets the victim's password to the canary.
        const w = await client.send(method, changeUrl(t.victimId), attacker, JSON.parse(t.body.replace(/\{\{PW\}\}/g, canary)), { actor: "a", purpose: `attacker (A) sets the victim (${t.victimId}) password`, restore: `the victim's password is reset to its declared value` });
        if (!ok2xx(w.status)) { notes.push(`${t.name}: the attacker could not change the victim's password (HTTP ${w.status}) — good, the boundary holds.`); continue; }
        // 3. Confirm: log in as the victim with the canary the attacker set.
        const asVictim = await login(t.login.victimUser, canary, t.login);
        const taken = loginOk(asVictim, t.login.success);
        // 4. Restore: the victim resets its own password (JWTs usually survive a change).
        let restored = "restore not attempted";
        try {
          const rb = JSON.parse(t.body.replace(/\{\{PW\}\}/g, t.restorePassword));
          const rr = await client.send(method, changeUrl(t.victimId), victim, rb, { actor: "b", purpose: "restore: the victim resets its own password", restore: "the restore itself" });
          restored = ok2xx(rr.status) ? "victim password restored" : `restore returned HTTP ${rr.status}; reset ${t.login.victimUser} by hand`;
        } catch (e) { restored = `restore failed (${(e as Error).message}); reset ${t.login.victimUser} by hand`; }
        notes.push(`${t.name}: ${restored}.`);
        if (!taken) { notes.push(`${t.name}: the attacker's write was accepted but login as the victim with the new password failed — the change may not have applied; no proof.`); continue; }
        findings.push({
          id: `password-takeover:${t.name}`,
          check: "password-takeover",
          title: `Account takeover: one account changes another's password at ${t.changePath}`,
          severity: "critical",
          state: "proven",
          location: changeUrl(t.victimId),
          description: `Account A changed account ${t.victimId}'s password through ${method} ${t.changePath}, and a login as ${t.login.victimUser} with the password A chose then succeeded — A took over the account. Changing a non-existent account's password was rejected (HTTP ${ctl.status}), so this is a real object boundary A crosses, not an accept-all endpoint.`,
          remediation: `Authorize the password change against the caller: only the account itself (or an admin) may change a password. Bind the target to the authenticated identity, never to a path id the caller supplies.`,
          proof: {
            method: "live on staging: control (non-existent victim) rejected, A set the victim's password, login as the victim with A's value succeeded, then the victim's password was restored",
            replay: `# A sets the victim's password, then anyone logs in as the victim:\ncurl -i -X ${method} ${JSON.stringify(changeUrl(t.victimId))} -H 'authorization: Bearer <A_TOKEN>' -H 'content-type: application/json' --data ${JSON.stringify(t.body.replace(/\{\{PW\}\}/g, "<new-password>"))}`,
            evidence: `control -> HTTP ${ctl.status}; A writes victim -> HTTP ${w.status}; login as victim with A's password -> HTTP ${asVictim.status} (accepted)`,
          },
          regressionHint: `After the fix, A changing ${t.victimId}'s password must be rejected (401/403), and a login as the victim with an A-chosen password must fail.`,
        });
      } catch (err) {
        notes.push(`${t.name}: stopped (${(err as Error).message}).`);
      }
    }
    const receipt = writesFinding("password-takeover", base, client.writes, notes);
    if (receipt) findings.push(receipt);
    ctx.log(`password-takeover: ${client.requests} request(s), ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};
