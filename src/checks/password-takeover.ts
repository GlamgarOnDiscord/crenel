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
  /** NAME of the environment variable holding the victim's restore password. */
  restorePasswordEnv: string;
}
interface Opts extends ActiveBase { targets?: TakeoverTarget[] }
const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/;

/** Put a password into a JSON string template without replacement-string or
 * JSON escaping surprises. `{{PW}}` is documented inside a JSON string. */
export function passwordBody(template: string, password: string): unknown {
  const escaped = JSON.stringify(password).slice(1, -1);
  return JSON.parse(template.replace(/\{\{PW\}\}/g, () => escaped));
}

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
    return [
      { method: m, url: u(t.changePath.replace(":id", "crenel-nonexistent-control")) },
      { method: "POST", url: u(t.login.path) },
      { method: m, url: cp },
      { method: "POST", url: u(t.login.path) },
      { method: m, url: cp },
    ];
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
    for (const t of targets) {
      const method = (t.method ?? "PUT").toUpperCase();
      if (!t.name || typeof t.changePath !== "string" || !t.changePath.includes(":id") || !t.victimId || typeof t.body !== "string" || !t.body.includes("{{PW}}") || !t.login?.path || !t.login.victimUser || !ENV_NAME.test(t.restorePasswordEnv ?? "")) {
        notes.push(`${t.name ?? "(unnamed)"}: skipped, needs name, changePath with :id, victimId, body, login.path, login.victimUser and restorePasswordEnv (an environment variable name).`);
        continue;
      }
      const restorePassword = process.env[t.restorePasswordEnv];
      if (!restorePassword) { notes.push(`${t.name}: skipped before any write because ${t.restorePasswordEnv} is not set.`); continue; }
      const changeUrl = (id: string) => u(t.changePath.replace(":id", encodeURIComponent(id)));
      const canary = `Crenel-${nonce()}-Aa1!`;
      try {
        if (!new Set(["PUT", "PATCH", "POST"]).has(method)) { notes.push(`${t.name}: skipped, method must be PUT, PATCH or POST.`); continue; }
        client.reserve(5);
        const loginBody = (pw: string, l: Login) => ({ ...(l.template ?? {}), [l.userField ?? "username"]: l.victimUser, [l.passField ?? "password"]: pw });
        const login = async (pw: string, l: Login, purpose: string) => {
          const r = await client.send("POST", u(l.path), undefined, loginBody(pw, l), { actor: "anonymous", purpose, restore: "nothing to restore" });
          return { status: r.status, body: r.body };
        };
        // 1. Control: attacker changes a NON-existent victim's password. Must be rejected.
        const bogus = `crenel-nonexistent-${nonce()}`;
        const ctl = await client.send(method, changeUrl(bogus), attacker, passwordBody(t.body, canary), { actor: "a", purpose: "control: change a non-existent account's password", restore: "nothing to restore" });
        if (ok2xx(ctl.status)) { notes.push(`${t.name}: changing a non-existent account's password was accepted (HTTP ${ctl.status}); the endpoint validates nothing, no proof.`); continue; }
        // A random password must fail before the mutation, or this login oracle accepts everything.
        const before = await login(canary, t.login, "control: victim login with the random password before any change");
        if (loginOk(before, t.login.success)) { notes.push(`${t.name}: login accepted the random control password before any change; login oracle is not discriminating, no proof.`); continue; }
        // 2. Attempt the mutation, then ALWAYS restore in finally. A server can
        // apply a write and drop the connection before the client sees a status;
        // that indeterminate write must be treated as possibly applied.
        let w: Awaited<ReturnType<ActiveClient["send"]>> | undefined;
        let attackRecord = undefined as (typeof client.writes)[number] | undefined;
        let asVictim = { status: 0, body: "" }, taken = false, flowError: Error | undefined;
        let restored = "restore not attempted";
        const beforeAttackWrites = client.writes.length;
        try {
          w = await client.send(method, changeUrl(t.victimId), attacker, passwordBody(t.body, canary), { actor: "a", purpose: `attacker (A) sets the victim (${t.victimId}) password`, restore: `the victim's password is reset to its declared value` });
          attackRecord = w.record;
          if (ok2xx(w.status)) {
            // 3. Confirm only an accepted write, while restoration remains
            // guaranteed whether this login succeeds, fails or throws.
            asVictim = await login(canary, t.login, "confirmation: victim login with A's canary password");
            taken = loginOk(asVictim, t.login.success);
          }
        } catch (err) {
          flowError = err as Error;
          attackRecord = client.writes[beforeAttackWrites];
        } finally {
          try {
            const rb = passwordBody(t.body, restorePassword);
            const rr = await client.send(method, changeUrl(t.victimId), victim, rb, { actor: "b", purpose: "restore: the victim resets its own password", restore: "the restore itself" });
            restored = ok2xx(rr.status) ? "victim password restored" : `restore returned HTTP ${rr.status}; reset ${t.login.victimUser} by hand`;
          } catch (e) { restored = `restore failed (${(e as Error).message}); reset ${t.login.victimUser} by hand`; }
        }
        if (attackRecord) attackRecord.restore = restored === "victim password restored" ? "restored" : `not restored: ${restored}`;
        notes.push(`${t.name}: ${restored}.`);
        if (flowError) { notes.push(`${t.name}: mutation or confirmation became indeterminate (${flowError.message}); restore was still attempted; no proof.`); continue; }
        if (!w || !ok2xx(w.status)) { notes.push(`${t.name}: the attacker could not change the victim's password (HTTP ${w?.status ?? "unknown"}) — no proof.`); continue; }
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
