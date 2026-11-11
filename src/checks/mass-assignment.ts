// mass-assignment: an update route that copies the whole request body into the
// row (Object.assign, ORM update(req.body), Supabase .update(body)), so a user
// sets fields the form never shows: role, plan, credits, isAdmin, ownerId.
// The classic "made myself admin" of AI-generated CRUD. A read cannot prove
// it; only the write, and the read that follows, can.
//
// Active mode, opt-in twice: scope.allowActiveTesting AND
// options.mass-assignment.enabled: true. Account A only ever updates its OWN
// object (declared route), with privileged fields set to values the user
// declares. Proven when A's next read shows a field at the declared value it
// did not have before. Every changed field is then written back to its old
// value and read again; what could not be restored is reported.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { resolveAccounts } from "./session.js";
import { ActiveClient, activeOptions, getField, MAX_TARGETS, ok2xx, same, setField, urlOf, writesFinding, type ActiveBase } from "./active-common.js";

export interface MassTarget {
  name: string;
  /** A's own update route; may hold :id (then `id` is A's object). */
  path: string;
  id?: string;
  /** Read route (default: path). */
  readPath?: string;
  /** PATCH (default), PUT or POST. */
  method?: string;
  /** Privileged fields (dotted paths) and the value to try, e.g. { role: "admin", credits: 999999 }. */
  fields: Record<string, unknown>;
  /** Ordinary fields the form sends, so the request looks like a normal update. */
  body?: Record<string, unknown>;
}

interface Opts extends ActiveBase { targets?: MassTarget[] }

const PRIVILEGE = /role|admin|owner|tenant|org|permission|scope|superuser|staff|verified/i;

export function plannedMass(options: Record<string, unknown>, base: string): { method: string; url: string }[] {
  const o = (options["mass-assignment"] ?? {}) as Opts;
  if (o.enabled !== true) return [];
  return (o.targets ?? []).slice(0, MAX_TARGETS).flatMap((t) => [
    { method: (t.method ?? "PATCH").toUpperCase(), url: urlOf(base, t.path, t.id) },
    { method: "GET", url: urlOf(base, t.readPath ?? t.path, t.id) },
  ]);
}

export const massAssignment: Check = {
  name: "mass-assignment",
  title: "Privileged fields (role, plan, credits, owner) accepted in a user's own update, active, staging only",
  readOnly: false,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = activeOptions<Opts>(ctx, "mass-assignment");
    if (!o) return [];
    if (ctx.stagingUrl) o.accounts = await resolveAccounts(ctx, o.accounts, "mass-assignment"); // declared logins (src/checks/session.ts)
    const targets = (o.targets ?? []).slice(0, MAX_TARGETS);
    if (!ctx.stagingUrl || targets.length === 0) { ctx.log("mass-assignment: needs a stagingUrl and options.mass-assignment.targets"); return []; }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const a = o.accounts.a?.token;
    if (!a) { ctx.log("mass-assignment: needs a token for account a"); return []; }
    const client = new ActiveClient(ctx, "mass-assignment", o.maxRequests);
    const notes: string[] = [];
    const findings: Finding[] = [];
    for (const t of targets) {
      const method = (t.method ?? "PATCH").toUpperCase();
      const fields = Object.entries(t.fields ?? {});
      if (!t.name || !t.path || !["PATCH", "PUT", "POST"].includes(method) || fields.length === 0 || (t.path.includes(":id") && !t.id)) {
        notes.push(`${t.name ?? "(unnamed)"}: skipped, a target needs name, path (with id when it holds :id), fields, and PATCH, PUT or POST.`);
        continue;
      }
      try {
        // Worst case: read, write, read, then one restore and one read.
        client.reserve(5);
        const f = await target(client, base, t, method, a, notes);
        if (f) findings.push(f);
      } catch (err) {
        notes.push(`${t.name}: stopped (${(err as Error).message}).`);
      }
    }
    const receipt = writesFinding("mass-assignment", base, client.writes, notes);
    if (receipt) findings.push(receipt);
    ctx.log(`mass-assignment: ${client.requests} request(s), ${client.writes.length} write(s), ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};

async function target(client: ActiveClient, base: string, t: MassTarget, method: string, a: string, notes: string[]): Promise<Finding | null> {
  const readUrl = urlOf(base, t.readPath ?? t.path, t.id), writeUrl = urlOf(base, t.path, t.id);
  const before = await client.read(readUrl, a);
  if (!ok2xx(before.status) || before.json === undefined) { notes.push(`${t.name}: A cannot read its own object (GET ${before.status}), nothing sent.`); return null; }
  const tried = Object.entries(t.fields).filter(([k, v]) => {
    if (same(getField(before.json, k), v)) { notes.push(`${t.name}: ${k} is already ${JSON.stringify(v)} for A, not tried (declare another value).`); return false; }
    return true;
  });
  if (tried.length === 0) return null;
  const extra = Object.entries(t.body ?? {});
  // PUT replaces the object: send A's object as it just read it, plus the fields (setField copies).
  let body: Record<string, unknown> = method === "PUT" && before.json && typeof before.json === "object" ? (before.json as Record<string, unknown>) : {};
  for (const [k, v] of [...extra, ...tried]) body = setField(body, k, v);
  const w = await client.send(method, writeUrl, a, body, { actor: "A", purpose: `A updates its own ${t.name} with ${tried.map(([k]) => k).join(", ")}` });
  const after = await client.read(readUrl, a);
  const changed = tried.filter(([k, v]) => same(getField(after.json, k), v));
  const invisible = tried.filter(([k]) => getField(before.json, k) === undefined && getField(after.json, k) === undefined).map(([k]) => k);
  if (invisible.length) notes.push(`${t.name}: ${invisible.join(", ")} not in A's read, so a change cannot be seen; declare a readPath that returns ${invisible.length > 1 ? "them" : "it"}.`);

  // Put back every field the write moved (privileged ones, and the ordinary ones it carried).
  const moved = [...extra, ...tried].map(([k]) => k).filter((k) => !same(getField(after.json, k), getField(before.json, k)));
  if (moved.length === 0) { w.record!.restore = "nothing to restore"; return null; }
  let back: Record<string, unknown> = method === "PUT" && after.json && typeof after.json === "object" ? (after.json as Record<string, unknown>) : {};
  for (const k of moved) back = setField(back, k, getField(before.json, k) ?? null);
  let left = moved;
  try {
    await client.send(method, writeUrl, a, back, { actor: "A", purpose: `restore ${moved.join(", ")}`, restore: "the restore itself" });
    const check = await client.read(readUrl, a);
    left = moved.filter((k) => { const was = getField(before.json, k), now = getField(check.json, k); return !(same(now, was) || (was === undefined && now == null)); });
  } catch { /* left = moved */ }
  w.record!.restore = left.length ? `not restored: ${left.map((k) => `${k} should be ${JSON.stringify(getField(before.json, k) ?? null)}`).join(", ")}` : "restored";
  if (changed.length === 0) return null;

  const names = changed.map(([k]) => k);
  const privileged = names.some((k) => PRIVILEGE.test(k));
  const restoredText = left.length ? `NOT restored: ${left.map((k) => `${k} should be ${JSON.stringify(getField(before.json, k) ?? null)}`).join(", ")}` : "every field restored to its old value";
  return {
    id: `mass-assignment:${t.name}:${method}:${names.join(",")}`,
    check: "mass-assignment",
    title: `Account A set ${names.join(", ")} on its own ${t.name} through ${method} ${t.path}`,
    severity: privileged ? "critical" : "high",
    state: "proven",
    location: writeUrl,
    description:
      `A ${method} on A's own ${t.name} carrying ${changed.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ")} was accepted (HTTP ${w.status}), and A's next read shows ` +
      `${changed.map(([k, v]) => `${k} ${JSON.stringify(getField(before.json, k) ?? null)} -> ${JSON.stringify(v)}`).join(", ")}. The route copies the request body into the object, ` +
      `so any user can grant themselves ${privileged ? "privileges" : "what they did not pay for"}. Write sent: ${method} ${writeUrl} ${JSON.stringify(body)}; ${restoredText}.`,
    remediation: `Build the update from an allowlist of the fields a user may change (a schema with .pick/.strict, or explicit columns), never from the raw body; set ${names.join(", ")} only from server-side logic (webhook, admin action).`,
    proof: {
      method: "active update of A's own object on staging: A's read before, the update with privileged fields, A's read after, restore",
      replay: `curl -i -X ${method} -H 'authorization: Bearer <A_TOKEN>' -H 'content-type: application/json' -d '${JSON.stringify(body)}' '${writeUrl}'`,
      evidence: `${method} -> HTTP ${w.status}; before: ${tried.map(([k]) => `${k}=${JSON.stringify(getField(before.json, k) ?? null)}`).join(", ")}; after: ${tried.map(([k]) => `${k}=${JSON.stringify(getField(after.json, k) ?? null)}`).join(", ")}; ${left.length ? "not restored" : "restored"}`,
    },
    regressionHint: [
      `test(${JSON.stringify(`mass-assignment: a user cannot set ${names.join(", ")} through ${method} ${t.path}`)}, async () => {`,
      `  const pick = (o, p) => p.split(".").reduce((x, k) => x?.[k], o);`,
      `  await fetch(\`\${BASE_URL}${urlOf("", t.path, t.id)}\`, { method: ${JSON.stringify(method)}, headers: { authorization: \`Bearer \${TOKEN_A}\`, "content-type": "application/json" }, body: JSON.stringify(${JSON.stringify(Object.fromEntries(changed))}) });`,
      `  const me = await (await fetch(\`\${BASE_URL}${urlOf("", t.readPath ?? t.path, t.id)}\`, { headers: { authorization: \`Bearer \${TOKEN_A}\` } })).json();`,
      ...changed.map(([k, v]) => `  expect(pick(me, ${JSON.stringify(k)})).not.toEqual(${JSON.stringify(v)});`),
      `});`,
    ].join("\n"),
  };
}
