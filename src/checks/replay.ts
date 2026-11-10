// replay: a single-use action is honored more than once. A coupon, voucher,
// gift card, password-reset OTP or any one-shot token that the server accepts a
// SECOND time is a replay flaw — money minted twice, an OTP that never burns,
// a nonce that does not protect. Neither a read-only probe nor a code review
// catches it reliably (the "mark it used" step lives in the handler, or
// nowhere); the only proof is sending the same token twice and watching the
// second one land. HexStrike and a free LLM agent do not test this at all.
//
// Active mode, opt-in twice: scope.allowActiveTesting AND options.replay.enabled.
// Only declared endpoints, bodies and tokens are touched. Each target:
//
//   1. control: submit an INVALID token (declared, or a random one). It MUST be
//      rejected. If it is accepted, the endpoint accepts anything — prove
//      nothing here (a replay would be meaningless).
//   2. first use: submit the real single-use token. It must be accepted (else
//      the declaration is wrong: note it, touch nothing else).
//   3. replay: submit the SAME token again. If it is accepted a SECOND time,
//      the token is not single-use — PROVEN. When a readBack is declared, the
//      effect must also change again (the value compounds), so a 200 that merely
//      says "already applied" is never mistaken for a real replay.
//
// The declared token is consumed by the test (that is the point); the report
// says so. Use a throwaway coupon/OTP on staging.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { ActiveClient, activeOptions, getField, MAX_TARGETS, nonce, ok2xx, setField, urlOf, writesFinding, type ActiveBase, type Answer } from "./active-common.js";

export interface ReplayTarget {
  name: string;
  /** Action endpoint (no :id needed; a single declared object). */
  path: string;
  /** POST (default), PUT or PATCH. */
  method?: string;
  /** Body that applies the single-use token, as the client sends it. */
  body: Record<string, unknown>;
  /** Dotted path of the single-use token inside `body` (swapped for the control). */
  tokenField: string;
  /** What "accepted" looks like. A 2xx status is the default; narrow it with
   * statuses and/or a body substring the success response carries. */
  accepted?: { statuses?: number[]; bodyIncludes?: string };
  /** A token that MUST be rejected, for the control. Default: a random nonce. */
  invalidToken?: string;
  /** Optional effect to confirm the replay compounded: read `field` at `path`
   * before the first use and after the replay; the value must differ. */
  readBack?: { path: string; field: string };
  /** Which declared account's token authenticates the calls. Default "a". */
  as?: "a" | "b";
}

interface Opts extends ActiveBase { targets?: ReplayTarget[] }

function isAccepted(res: Answer, acc: ReplayTarget["accepted"]): boolean {
  const statusOk = acc?.statuses?.length ? acc.statuses.includes(res.status) : ok2xx(res.status);
  if (!statusOk) return false;
  if (acc?.bodyIncludes) return res.body.includes(acc.bodyIncludes);
  return true;
}

/** The requests one run can send, for the agent's active gate (reads included). */
export function plannedReplays(options: Record<string, unknown>, base: string): { method: string; url: string }[] {
  const o = (options["replay"] ?? {}) as Opts;
  if (o.enabled !== true) return [];
  return (o.targets ?? []).slice(0, MAX_TARGETS).flatMap((t) => {
    const m = (t.method ?? "POST").toUpperCase();
    const url = urlOf(base, t.path);
    const reqs = [{ method: m, url }, { method: m, url }, { method: m, url }];
    if (t.readBack) { const r = urlOf(base, t.readBack.path); reqs.push({ method: "GET", url: r }, { method: "GET", url: r }, { method: "GET", url: r }); }
    return reqs;
  });
}

export const replay: Check = {
  name: "replay",
  title: "A single-use token (coupon, OTP, voucher) is accepted more than once, active, staging only",
  readOnly: false,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = activeOptions<Opts>(ctx, "replay");
    if (!o) return [];
    const targets = (o.targets ?? []).slice(0, MAX_TARGETS);
    if (!ctx.stagingUrl || targets.length === 0) { ctx.log("replay: needs a stagingUrl and options.replay.targets"); return []; }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const client = new ActiveClient(ctx, "replay", o.maxRequests);
    const notes: string[] = [];
    const findings: Finding[] = [];

    for (const t of targets) {
      const method = (t.method ?? "POST").toUpperCase();
      if (!["POST", "PUT", "PATCH"].includes(method) || !t.name || !t.path || !t.body || !t.tokenField) {
        notes.push(`${t.name ?? "(unnamed)"}: skipped, a target needs name, path, body, tokenField and a method among POST, PUT, PATCH.`);
        continue;
      }
      const token = o.accounts[t.as ?? "a"]?.token;
      const url = urlOf(base, t.path);
      try {
        client.reserve(t.readBack ? 6 : 3);
        const readEffect = async () => (t.readBack ? getField((await client.read(urlOf(base, t.readBack.path), token)).json, t.readBack.field) : undefined);
        // 1. Control: an invalid token must be rejected, or the endpoint is accept-all.
        const bad = setField(t.body, t.tokenField, t.invalidToken ?? `crenel-invalid-${nonce()}`);
        const ctl = await client.send(method, url, token, bad, { actor: t.as ?? "a", purpose: "control: invalid token", restore: "nothing to restore" });
        if (isAccepted(ctl, t.accepted)) {
          notes.push(`${t.name}: the endpoint accepted an invalid token (HTTP ${ctl.status}); it validates nothing, so a replay proves nothing.`);
          continue;
        }
        const before = await readEffect();
        // 2. First use of the real token: must be accepted.
        const first = await client.send(method, url, token, t.body, { actor: t.as ?? "a", purpose: "first use of the single-use token", restore: "not restored: the test consumed the token" });
        if (!isAccepted(first, t.accepted)) {
          notes.push(`${t.name}: the declared token was not accepted on first use (HTTP ${first.status}); check path, body and tokenField.`);
          continue;
        }
        // Snapshot the effect AFTER the first use, BEFORE the replay: the proof is
        // that the SECOND request moves it again, not merely that it changed once.
        const mid = await readEffect();
        // 3. Replay: the SAME token again.
        const second = await client.send(method, url, token, t.body, { actor: t.as ?? "a", purpose: "replay: the same single-use token again", restore: "not restored: the test consumed the token" });
        const acceptedTwice = isAccepted(second, t.accepted);
        let compounded = true, effectNote = "";
        if (t.readBack) {
          const after = await readEffect();
          compounded = JSON.stringify(mid) !== JSON.stringify(after); // the replay itself changed state
          effectNote = ` ${t.readBack.field}: ${JSON.stringify(before)} (start) -> ${JSON.stringify(mid)} (after 1st) -> ${JSON.stringify(after)} (after replay)`;
        }
        if (!acceptedTwice || !compounded) {
          notes.push(`${t.name}: no replay — the second use was ${acceptedTwice ? "accepted but moved nothing (the first use's effect is idempotent)" : `rejected (HTTP ${second.status})`}. The token is single-use.`);
          continue;
        }
        findings.push({
          id: `replay:${t.name}`,
          check: "replay",
          title: `Single-use token accepted twice at ${t.path} (${t.name})`,
          severity: "high",
          state: "proven",
          location: url,
          description: `The same token was accepted twice at ${method} ${t.path} (HTTP ${first.status} then ${second.status}), while an invalid token was rejected (HTTP ${ctl.status}).${t.readBack ? ` The effect compounded:${effectNote}.` : ""} A one-shot value (coupon, voucher, OTP, nonce) can be replayed: redeemed for value repeatedly, or brute-forced without ever burning.`,
          remediation: `Mark the token spent inside the same transaction that honors it, and reject any later use; for OTPs, invalidate on first check and rate-limit attempts.`,
          proof: {
            // The single-use token is a live secret: never write its value into a
            // finding (reports and integrations may be read widely). Show the body
            // with the token field redacted; the operator holds the real value.
            method: "live on staging: invalid token rejected (control), real token accepted, same token accepted again" + (t.readBack ? ", effect confirmed to move again on the replay" : ""),
            replay: `# apply the SAME token twice, observe both accepted:\ncurl -i -X ${method} ${JSON.stringify(url)} -H 'content-type: application/json' --data ${JSON.stringify(JSON.stringify(setField(t.body, t.tokenField, "<the single-use token>")))}  # run twice`,
            evidence: `control invalid -> HTTP ${ctl.status}; first use -> HTTP ${first.status}; replay -> HTTP ${second.status}${t.readBack ? `;${effectNote}` : ""}`,
          },
          regressionHint: `After the fix, a second ${method} ${t.path} with the same token must be rejected.`,
        });
      } catch (err) {
        notes.push(`${t.name}: stopped (${(err as Error).message}).`);
      }
    }
    const receipt = writesFinding("replay", base, client.writes, notes);
    if (receipt) findings.push(receipt);
    ctx.log(`replay: ${client.requests} request(s), ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};
