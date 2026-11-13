// authz-write: broken object-level authorization on WRITES (IDOR on PATCH, PUT,
// POST, DELETE). AI code review misses it for the same reason as read IDOR
// (the ownership check lives elsewhere, or nowhere), and a read-only probe
// cannot see it: the only proof is a state change on someone else's object.
//
// Active mode, opt-in twice: scope.allowActiveTesting AND
// options.authz-write.enabled: true. Only declared targets, declared ids and
// declared test accounts are touched. For each target:
//
//   1. control: A changes its OWN object (ownId) and reads the change back, then
//      puts the old value back. If that fails, the declaration is wrong (route,
//      field, body) and B's object is never touched;
//   2. B reads its object (victimId): the value before;
//   3. an anonymous caller sends the same write; B reads again;
//   4. A sends the write; B reads again;
//   5. after each write that changed B's object, B writes the old value back
//      and reads it to confirm.
//
// A canary value (crenel-canary-<nonce>) is written to one declared field, so
// a match in B's read can only come from Crenel's request: the proof is B's
// own read, not A's status code. DELETE is only sent to ids the user marked
// disposable, and is never restored (the report says so).

import type { Check, CheckContext, Finding } from "../core/types.js";
import { resolveAccounts } from "./session.js";
import { ActiveClient, activeOptions, canary, getField, MAX_TARGETS, ok2xx, same, sameIdentity, setField, urlOf, writesFinding, type ActiveBase, type WriteRecord } from "./active-common.js";

export interface WriteTarget {
  name: string;
  /** Write route with :id, e.g. /api/projects/:id */
  path: string;
  /** Read route with :id (default: path). */
  readPath?: string;
  /** PATCH (default), PUT, POST or DELETE. */
  method?: string;
  /** Dotted path of the canary field in the read body (not used by DELETE). */
  field?: string;
  /** B's object. Never discovered: declared here. */
  victimId: string;
  /** A's own object, for the control. Required. */
  ownId: string;
  /** DELETE only: both ids are throwaway objects the user created for this test. */
  disposable?: boolean;
}

interface Opts extends ActiveBase { targets?: WriteTarget[] }

const DENY_DELETE = new Set([404, 410]);

/** The requests one target can send, for the agent's gate (reads included). */
export function plannedWrites(options: Record<string, unknown>, base: string): { method: string; url: string }[] {
  const o = (options["authz-write"] ?? {}) as Opts;
  if (o.enabled !== true) return [];
  return (o.targets ?? []).slice(0, MAX_TARGETS).flatMap((t) => {
    const m = (t.method ?? "PATCH").toUpperCase();
    return [
      { method: m, url: urlOf(base, t.path, t.ownId) },
      { method: m, url: urlOf(base, t.path, t.victimId) },
      { method: "GET", url: urlOf(base, t.readPath ?? t.path, t.victimId) },
    ];
  });
}

export const authzWrite: Check = {
  name: "authz-write",
  title: "Cross-tenant writes (account A changing or deleting account B's objects), active, staging only",
  readOnly: false,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = activeOptions<Opts>(ctx, "authz-write");
    if (!o) return [];
    if (ctx.stagingUrl) o.accounts = await resolveAccounts(ctx, o.accounts, "authz-write"); // declared logins (src/checks/session.ts)
    const targets = (o.targets ?? []).slice(0, MAX_TARGETS);
    if (!ctx.stagingUrl || targets.length === 0) { ctx.log("authz-write: needs a stagingUrl and options.authz-write.targets"); return []; }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const a = o.accounts.a?.token, b = o.accounts.b?.token;
    const notes: string[] = [];
    if (!a || !b) { ctx.log("authz-write: needs tokens for accounts a and b"); return []; }
    const twin = sameIdentity(a, b);
    if (twin) { ctx.log(`authz-write: accounts A and B ${twin}, nothing sent`); return [{ id: "authz-write:same-identity", check: "authz-write", title: "Test accounts A and B are the same identity: no write was sent", severity: "medium", state: "unproven", location: "options.authz-write.accounts", description: `The tokens for A and B ${twin}.`, remediation: "Use two accounts of two different tenants." }]; }
    const client = new ActiveClient(ctx, "authz-write", o.maxRequests);
    const findings: Finding[] = [];

    for (const t of targets) {
      const method = (t.method ?? "PATCH").toUpperCase();
      if (!["PATCH", "PUT", "POST", "DELETE"].includes(method) || !t.name || !t.path?.includes(":id") || !t.victimId || !t.ownId) {
        notes.push(`${t.name ?? "(unnamed)"}: skipped, a target needs name, a path with :id, victimId, ownId and a method among PATCH, PUT, POST, DELETE.`);
        continue;
      }
      if (t.victimId === t.ownId) { notes.push(`${t.name}: skipped, victimId and ownId are the same object.`); continue; }
      try {
        // Reserve the target's worst case up front (restores included), so the
        // budget never cuts a run between a write and the write that undoes it.
        client.reserve(method === "DELETE" ? 7 : 18);
        const f = method === "DELETE" ? await deleteTarget(client, base, t, a, b, notes) : await fieldTarget(client, base, t, method, a, b, notes);
        findings.push(...f);
      } catch (err) {
        notes.push(`${t.name}: stopped (${(err as Error).message}).`);
      }
    }
    const receipt = writesFinding("authz-write", base, client.writes, notes);
    if (receipt) findings.push(receipt);
    ctx.log(`authz-write: ${client.requests} request(s), ${client.writes.length} write(s), ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};

async function fieldTarget(client: ActiveClient, base: string, t: WriteTarget, method: string, a: string, b: string, notes: string[]): Promise<Finding[]> {
  if (!t.field) { notes.push(`${t.name}: skipped, ${method} needs a declared canary field.`); return []; }
  const field = t.field;
  const readOwn = urlOf(base, t.readPath ?? t.path, t.ownId), writeOwn = urlOf(base, t.path, t.ownId);
  const readVictim = urlOf(base, t.readPath ?? t.path, t.victimId), writeVictim = urlOf(base, t.path, t.victimId);
  // PUT replaces the object: send the object as its owner just read it, with the field changed.
  const bodyFor = (before: unknown, value: unknown) => (method === "PUT" ? setField(before, field, value) : setField({}, field, value));

  // 1. Control on A's own object.
  const ownBefore = await client.read(readOwn, a);
  if (!ok2xx(ownBefore.status) || getField(ownBefore.json, field) === undefined) {
    notes.push(`${t.name}: control skipped B's object, A cannot read ${field} on its own object (GET ${ownBefore.status}).`);
    return [];
  }
  const ownOld = getField(ownBefore.json, field);
  const c0 = canary();
  const ctl = await client.send(method, writeOwn, a, bodyFor(ownBefore.json, c0), { actor: "A", purpose: "control: A changes its own object" });
  const ownAfter = await client.read(readOwn, a);
  if (!same(getField(ownAfter.json, field), c0)) {
    ctl.record!.restore = "nothing to restore";
    notes.push(`${t.name}: control failed, A's ${method} on its own object (HTTP ${ctl.status}) did not change ${field}; check the route, method and field. B's object was not touched.`);
    return [];
  }
  await restore(client, method, writeOwn, readOwn, a, ownAfter.json, field, ownOld, ctl.record!, "A");

  // 2. B's object before.
  const before = await client.read(readVictim, b);
  if (!ok2xx(before.status) || getField(before.json, field) === undefined) {
    notes.push(`${t.name}: B cannot read ${field} on ${t.victimId} (GET ${before.status}); declare an object B owns.`);
    return [];
  }
  const old = getField(before.json, field);
  const out: Finding[] = [];

  // 3 and 4. Anonymous, then A. The canary in B's read is the proof.
  for (const actor of [{ key: "anon", token: undefined as string | undefined, who: "an anonymous caller" }, { key: "a", token: a, who: "account A" }]) {
    const value = canary();
    const w = await client.send(method, writeVictim, actor.token, bodyFor(before.json, value), { actor: actor.key === "anon" ? "anonymous" : "A", purpose: `attack: ${actor.who} writes B's object` });
    const after = await client.read(readVictim, b);
    const changed = same(getField(after.json, field), value);
    if (!changed) { w.record!.restore = "nothing to restore"; continue; }
    const restored = await restore(client, method, writeVictim, readVictim, b, after.json, field, old, w.record!, "B");
    out.push({
      id: `authz-write:${t.name}:${method}:${t.victimId}${actor.key === "a" ? "" : ":anon"}`,
      check: "authz-write",
      title: `${actor.key === "anon" ? "An anonymous caller" : "Account A"} changed account B's ${t.name} (${method} ${w.status})`,
      severity: "critical",
      state: "proven",
      location: writeVictim,
      description:
        `With ${actor.key === "anon" ? "no token" : "account A's token"}, a ${method} on ${t.name} ${t.victimId}, owned by account B, set ${field} to ${JSON.stringify(value)}, and B's own read then returned that value ` +
        `(before: ${JSON.stringify(old)}). The server checks who is signed in but not who owns the object. Control: A changing its own ${t.name} works, so the route and field are right. ` +
        `Write sent: ${method} ${writeVictim} {${JSON.stringify(field)}: ${JSON.stringify(value)}}; ${restored ? `restored by B to ${JSON.stringify(old)}` : `NOT restored, B's ${field} still needs to be set back to ${JSON.stringify(old)}`}.`,
      remediation: `Scope every write on ${t.name} to the caller's tenant at the data layer (update ... where id = ? and owner_id = session.account_id), answer 404 otherwise, and keep the generated test.`,
      proof: {
        method: "active write on staging: control on A's own object, B's read before, the write, B's read after (canary value)",
        replay: `curl -i -X ${method}${actor.token ? " -H 'authorization: Bearer <A_TOKEN>'" : ""} -H 'content-type: application/json' -d '${JSON.stringify(setField({}, field, "<canary>"))}' '${writeVictim}'`,
        evidence: `${method} -> HTTP ${w.status}; B's read before: ${field}=${JSON.stringify(old)}; after: ${field}=${JSON.stringify(value)}; ${restored ? "restored" : "not restored"}`,
      },
      regressionHint: regressionTest(t, method, field, actor.key === "anon" ? "anon" : "a"),
    });
  }
  return out;
}

/** The owner (or A on its own object) writes the old value back, then reads it. */
async function restore(client: ActiveClient, method: string, writeUrl: string, readUrl: string, token: string, current: unknown, field: string, old: unknown, rec: WriteRecord, who: string): Promise<boolean> {
  const body = method === "PUT" ? setField(current, field, old) : setField({}, field, old);
  // A POST action route (approve, rename) is not always a way back; PATCH is tried after it.
  for (const m of method === "POST" ? ["POST", "PATCH"] : [method]) {
    try {
      await client.send(m, writeUrl, token, body, { actor: who, purpose: `restore ${field}` , restore: "the restore itself" });
      const r = await client.read(readUrl, token);
      if (same(getField(r.json, field), old)) { rec.restore = "restored"; return true; }
    } catch { /* recorded below */ }
  }
  rec.restore = `not restored: field ${field} needs manual restoration`;
  return false;
}

async function deleteTarget(client: ActiveClient, base: string, t: WriteTarget, a: string, b: string, notes: string[]): Promise<Finding[]> {
  if (t.disposable !== true) { notes.push(`${t.name}: DELETE skipped, mark the target disposable: true (both ids are throwaway objects).`); return []; }
  const readOwn = urlOf(base, t.readPath ?? t.path, t.ownId), readVictim = urlOf(base, t.readPath ?? t.path, t.victimId);
  const ownBefore = await client.read(readOwn, a);
  const before = await client.read(readVictim, b);
  if (!ok2xx(ownBefore.status) || !ok2xx(before.status)) {
    notes.push(`${t.name}: DELETE skipped, the disposable objects must exist (A's ${t.ownId}: ${ownBefore.status}, B's ${t.victimId}: ${before.status}); recreate them.`);
    return [];
  }
  // Control: A deletes its own throwaway object and it is gone.
  const ctl = await client.send("DELETE", urlOf(base, t.path, t.ownId), a, undefined, { actor: "A", purpose: "control: A deletes its own disposable object" });
  const ownAfter = await client.read(readOwn, a);
  if (!DENY_DELETE.has(ownAfter.status)) {
    ctl.record!.restore = "nothing to restore";
    notes.push(`${t.name}: control failed, A's DELETE on its own ${t.ownId} (HTTP ${ctl.status}) left it readable (${ownAfter.status}). B's object was not touched.`);
    return [];
  }
  ctl.record!.restore = `not restored: ${t.ownId} deleted (disposable, recreate it)`;
  for (const actor of [{ key: "anon", token: undefined as string | undefined }, { key: "a", token: a }]) {
    const w = await client.send("DELETE", urlOf(base, t.path, t.victimId), actor.token, undefined, { actor: actor.key === "anon" ? "anonymous" : "A", purpose: `attack: ${actor.key === "anon" ? "anonymous" : "A"} deletes B's disposable object` });
    const after = await client.read(readVictim, b);
    if (!DENY_DELETE.has(after.status)) { w.record!.restore = "nothing to restore"; continue; }
    w.record!.restore = `not restored: ${t.victimId} deleted (disposable, recreate it)`;
    return [{
      id: `authz-write:${t.name}:DELETE:${t.victimId}${actor.key === "a" ? "" : ":anon"}`,
      check: "authz-write",
      title: `${actor.key === "anon" ? "An anonymous caller" : "Account A"} deleted account B's ${t.name} (DELETE ${w.status})`,
      severity: "critical",
      state: "proven",
      location: urlOf(base, t.path, t.victimId),
      description: `B could read its disposable ${t.name} ${t.victimId} (HTTP ${before.status}); after a DELETE with ${actor.key === "anon" ? "no token" : "account A's token"} (HTTP ${w.status}), B's own read answers ${after.status}. Control: A deleting its own disposable ${t.ownId} works. Both objects are gone and were NOT restored: recreate them before the next run.`,
      remediation: `Scope deletes on ${t.name} to the caller's tenant (delete ... where id = ? and owner_id = session.account_id), answer 404 otherwise.`,
      proof: {
        method: "active DELETE on a declared disposable object: control on A's own, B's read before and after",
        replay: `curl -i -X DELETE${actor.token ? " -H 'authorization: Bearer <A_TOKEN>'" : ""} '${urlOf(base, t.path, t.victimId)}'`,
        evidence: `B's read before: ${before.status}; DELETE -> ${w.status}; B's read after: ${after.status}; not restored (disposable)`,
      },
      regressionHint: regressionTest(t, "DELETE", undefined, actor.key === "anon" ? "anon" : "a"),
    }];
  }
  return [];
}

function regressionTest(t: WriteTarget, method: string, field: string | undefined, actor: "a" | "anon"): string {
  const path = t.path.replace(":id", t.victimId);
  const read = (t.readPath ?? t.path).replace(":id", t.victimId);
  const auth = actor === "anon" ? "{}" : "{ authorization: `Bearer ${TOKEN_A}` }";
  const lines = [
    `test(${JSON.stringify(`authz-write: ${actor === "anon" ? "an anonymous caller" : "account A"} cannot ${method} account B's ${t.name}`)}, async () => {`,
    `  // ${t.victimId} belongs to account B${method === "DELETE" ? " (a disposable object: recreate it if this test ever fails)" : ""}.`,
    `  const readB = () => fetch(\`\${BASE_URL}${read}\`, { headers: { authorization: \`Bearer \${TOKEN_B}\` } });`,
  ];
  if (field) {
    lines.push(
      `  const pick = (o) => ${JSON.stringify(field)}.split(".").reduce((x, k) => x?.[k], o);`,
      "  const before = pick(await (await readB()).json());",
      `  const res = await fetch(\`\${BASE_URL}${path}\`, { method: ${JSON.stringify(method)}, headers: { ...${auth}, "content-type": "application/json" }, body: JSON.stringify(${JSON.stringify(setField({}, field, "crenel-regression"))}) });`,
      "  expect([401, 403, 404]).toContain(res.status);",
      "  expect(pick(await (await readB()).json())).toEqual(before);",
    );
  } else {
    lines.push(
      `  const res = await fetch(\`\${BASE_URL}${path}\`, { method: "DELETE", headers: ${auth} });`,
      "  expect([401, 403, 404]).toContain(res.status);",
      "  expect((await readB()).status).toBe(200);",
    );
  }
  lines.push("});");
  return lines.join("\n");
}
