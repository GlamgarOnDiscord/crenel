// race: a limit checked and then consumed in two steps (read the count, then
// write it), so concurrent requests all pass the check before any of them
// writes: a single-use coupon redeemed ten times, an invite accepted twice,
// credits spent below zero. AI-generated handlers do this by default
// (`if (user.credits >= cost) { ... await update(...) }` with no transaction or
// atomic condition), and no read can show it.
//
// Active mode, opt-in twice: scope.allowActiveTesting AND
// options.race.enabled: true, and a declared target whose limit you know
// (`max`). One burst per target, as account A: `concurrency` identical
// requests (default 10, at most 25), sent together, never repeated, never
// looped. Proven when more than `max` succeed AND a follow-up read shows more
// than `max` uses consumed. What the burst consumed is not restored (a coupon
// redeemed is redeemed): the receipt says how many uses were spent.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { ActiveClient, activeOptions, getField, MAX_TARGETS, ok2xx, urlOf, writesFinding, type ActiveBase } from "./active-common.js";

export interface RaceTarget {
  name: string;
  /** The route that consumes the limited resource, e.g. /api/coupons/redeem */
  path: string;
  /** POST (default), PUT, PATCH or DELETE. */
  method?: string;
  /** JSON body sent with every request of the burst. */
  body?: unknown;
  /** How many of the burst may succeed (a single-use coupon: 1). */
  max: number;
  /** Requests in the burst: default 10, at most 25. */
  concurrency?: number;
  /** A's read that shows what was consumed (a balance, a count). */
  readPath?: string;
  /** Dotted path of a number in that read. */
  readField?: string;
  /** How much readField moves per success (default 1; the sign does not matter). */
  perSuccess?: number;
}

interface Opts extends ActiveBase { targets?: RaceTarget[] }

export const DEFAULT_CONCURRENCY = 10;
export const MAX_CONCURRENCY = 25;
const MAX_RACE_TARGETS = 5;

const burstOf = (t: RaceTarget) => Math.max(2, Math.min(Math.floor(t.concurrency ?? DEFAULT_CONCURRENCY), MAX_CONCURRENCY));

export function plannedRace(options: Record<string, unknown>, base: string): { method: string; url: string }[] {
  const o = (options.race ?? {}) as Opts;
  if (o.enabled !== true) return [];
  return (o.targets ?? []).slice(0, MAX_RACE_TARGETS).flatMap((t) => [
    { method: `${(t.method ?? "POST").toUpperCase()}`, url: `${urlOf(base, t.path)} (x${burstOf(t)} at once)` },
    ...(t.readPath ? [{ method: "GET", url: urlOf(base, t.readPath) }] : []),
  ]);
}

export const race: Check = {
  name: "race",
  title: "Limits consumed by concurrent requests (coupon, credits, invites: TOCTOU), active, staging only",
  readOnly: false,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = activeOptions<Opts>(ctx, "race");
    if (!o) return [];
    const targets = (o.targets ?? []).slice(0, Math.min(MAX_TARGETS, MAX_RACE_TARGETS));
    if (!ctx.stagingUrl || targets.length === 0) { ctx.log("race: needs a stagingUrl and options.race.targets"); return []; }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const a = o.accounts.a?.token;
    if (!a) { ctx.log("race: needs a token for account a"); return []; }
    const client = new ActiveClient(ctx, "race", o.maxRequests);
    const notes: string[] = [];
    const findings: Finding[] = [];
    for (const t of targets) {
      const method = (t.method ?? "POST").toUpperCase();
      if (!t.name || !t.path || !["POST", "PUT", "PATCH", "DELETE"].includes(method) || !Number.isInteger(t.max) || t.max < 0) {
        notes.push(`${t.name ?? "(unnamed)"}: skipped, a target needs name, path, an integer max (how many may succeed) and POST, PUT, PATCH or DELETE.`);
        continue;
      }
      const k = burstOf(t);
      if (k <= t.max) { notes.push(`${t.name}: skipped, a burst of ${k} cannot exceed max ${t.max}; raise concurrency (at most ${MAX_CONCURRENCY}).`); continue; }
      try {
        client.reserve(k + (t.readPath ? 2 : 0));
        const f = await burst(client, base, t, method, k, a, notes);
        if (f) findings.push(f);
      } catch (err) {
        notes.push(`${t.name}: stopped (${(err as Error).message}).`);
      }
    }
    const receipt = writesFinding("race", base, client.writes, notes);
    if (receipt) findings.push(receipt);
    ctx.log(`race: ${client.requests} request(s), ${client.writes.length} write(s), ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};

async function burst(client: ActiveClient, base: string, t: RaceTarget, method: string, k: number, a: string, notes: string[]): Promise<Finding | null> {
  const url = urlOf(base, t.path);
  const readUrl = t.readPath ? urlOf(base, t.readPath) : undefined;
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v)) ? Number(v) : undefined);
  let v0: number | undefined;
  if (readUrl) {
    const r = await client.read(readUrl, a);
    v0 = t.readField ? num(getField(r.json, t.readField)) : undefined;
    if (v0 === undefined) notes.push(`${t.name}: ${t.readField ? `${t.readField} is not a number in` : "no readField for"} GET ${t.readPath} (HTTP ${r.status}), the burst is judged on responses only.`);
  }
  // One burst: every request is created before any is awaited. No retry, no loop.
  const answers = await Promise.allSettled(Array.from({ length: k }, (_, i) =>
    client.send(method, url, a, t.body, { actor: "A", purpose: `race burst ${i + 1}/${k} on ${t.name}` })));
  const ok = answers.filter((x) => x.status === "fulfilled" && ok2xx(x.value.status)).length;
  const statuses = answers.map((x) => (x.status === "fulfilled" ? String(x.value.status) : "error"));
  for (const x of answers) if (x.status === "fulfilled" && x.value.record) x.value.record.restore = ok2xx(x.value.status) ? `not restored: one use of ${t.name} consumed by the test` : "nothing to restore";
  let consumed: number | undefined, v1: number | undefined;
  if (readUrl && v0 !== undefined) {
    const r = await client.read(readUrl, a);
    v1 = num(getField(r.json, t.readField!));
    if (v1 !== undefined) consumed = Math.abs(v1 - v0) / Math.abs(t.perSuccess || 1);
  }
  const byResponse = ok > t.max;
  const byRead = consumed !== undefined && consumed > t.max + 1e-9;
  if (!byResponse && !byRead) return null;
  const proven = byResponse && byRead;
  const statusLine = `${ok} of ${k} answered 2xx (${[...new Set(statuses)].map((s) => `${s} x${statuses.filter((x) => x === s).length}`).join(", ")})`;
  const readLine = consumed === undefined ? "no follow-up read" : `${t.readField} ${v0} -> ${v1}, ${+consumed.toFixed(2)} use(s) consumed`;
  return {
    id: `race:${t.name}:${method}:${t.path}`,
    check: "race",
    title: proven
      ? `${t.name}: ${ok} of ${k} concurrent requests went through where at most ${t.max} may (${method} ${t.path})`
      : `${t.name}: possible race on ${method} ${t.path}, not proven (${byResponse ? "responses only" : "the read only"})`,
    severity: proven ? "high" : "medium",
    state: proven ? "proven" : "unproven",
    location: url,
    description: proven
      ? `${k} identical ${method} requests sent together as account A: ${statusLine}, and A's read shows ${readLine}, above the declared limit of ${t.max}. The handler checks the limit and consumes it in two steps, so concurrent requests all pass the check. Nothing was restored: the test spent ${+consumed!.toFixed(2)} use(s) of ${t.name}.`
      : `${k} identical ${method} requests sent together: ${statusLine}; ${readLine}. ${byResponse ? "More than the limit answered 2xx, but no read confirms what was consumed: declare readPath and readField." : "The read moved more than the limit allows while the responses did not: review by hand."}`,
    remediation: `Make the check and the consumption one atomic step: a conditional update (update ... set uses = uses + 1 where id = ? and uses < max, then check the row count), a unique constraint on (coupon, user), or a transaction with SELECT ... FOR UPDATE. Keep the generated test.`,
    proof: {
      method: "one burst of identical concurrent requests on staging, counted by response and by A's read before and after",
      replay: `seq ${k} | xargs -P ${k} -I{} curl -s -o /dev/null -w '%{http_code}\\n' -X ${method} -H 'authorization: Bearer <A_TOKEN>'${t.body !== undefined ? ` -H 'content-type: application/json' -d '${JSON.stringify(t.body)}'` : ""} '${url}'`,
      evidence: `${statusLine}; ${readLine}; limit ${t.max}`,
    },
    regressionHint: proven ? [
      `test(${JSON.stringify(`race: at most ${t.max} of ${k} concurrent ${method} ${t.path} succeed`)}, async () => {`,
      `  // Needs a fresh ${t.name} (a coupon nobody redeemed, credits for exactly ${t.max} use(s)).`,
      `  const send = () => fetch(\`\${BASE_URL}${t.path}\`, { method: ${JSON.stringify(method)}, headers: { authorization: \`Bearer \${TOKEN_A}\`, "content-type": "application/json" }${t.body !== undefined ? `, body: JSON.stringify(${JSON.stringify(t.body)})` : ""} });`,
      `  const res = await Promise.all(Array.from({ length: ${k} }, send));`,
      `  expect(res.filter((r) => r.ok).length).toBeLessThanOrEqual(${t.max});`,
      `});`,
    ].join("\n") : undefined,
  };
}
