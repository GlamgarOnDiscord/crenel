// signup-privilege: a registration (or any create) endpoint accepts a PRIVILEGED
// field the caller should never set — admin/role/isAdmin/plan/credits/verified — so
// anyone signs up as an administrator. mass-assignment covers UPDATES to an object
// the caller already owns; this covers CREATE, where there is no prior object and the
// proof is read back from a listing. Two registrations make it deterministic and
// zero-FP:
//   1. control: register WITHOUT the privileged field. The created record must show
//      the field at its default (absent/false). This proves the field is privileged
//      by default, not something every account simply has.
//   2. probe: register WITH the privileged field set. If the created record shows the
//      field at the injected value, the server accepted a field it should have
//      ignored — PROVEN.
// Each record is found in the readback by a unique identity value the check chose, so
// one run never reads another account's object. Throwaway accounts, visibly marked.
//
// Active (it creates accounts): scope.allowActiveTesting AND options.signup-privilege.enabled.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { ActiveClient, activeOptions, getField, MAX_TARGETS, nonce, ok2xx, setField, urlOf, writesFinding, type ActiveBase } from "./active-common.js";

interface SignupTarget {
  name: string;
  /** The create endpoint, e.g. "/users/v1/register". */
  path: string;
  /** POST (default) or PUT. */
  method?: string;
  /** Body template for a valid signup; identity fields are made unique per call. */
  body: Record<string, unknown>;
  /** Fields in `body` to make unique each call (e.g. ["username","email"]). The
   * first is used to find the created record in the readback. Default ["username"]. */
  identity?: string[];
  /** The privileged field(s) that must be ignored, and the value to attempt. */
  privileged: Record<string, unknown>;
  /** A readback that lists created records (e.g. "/users/v1/_debug"). */
  readPath: string;
  /** Dotted path to the array inside the readback. Default: the first array found. */
  listField?: string;
  /** Which declared account's token authenticates the calls (default: anonymous). */
  as?: "a" | "b";
}
interface Opts extends ActiveBase { targets?: SignupTarget[] }

/** Find the array of records inside a readback body. */
function records(json: unknown, listField?: string): Record<string, unknown>[] {
  if (listField) { const v = getField(json, listField); return Array.isArray(v) ? v : []; }
  if (Array.isArray(json)) return json as Record<string, unknown>[];
  if (json && typeof json === "object") for (const v of Object.values(json as Record<string, unknown>)) if (Array.isArray(v)) return v as Record<string, unknown>[];
  return [];
}
function findBy(list: Record<string, unknown>[], field: string, value: unknown): Record<string, unknown> | undefined {
  return list.find((r) => String(getField(r, field)) === String(value));
}

export function plannedSignup(options: Record<string, unknown>, base: string): { method: string; url: string }[] {
  const o = (options["signup-privilege"] ?? {}) as Opts;
  if (o.enabled !== true) return [];
  return (o.targets ?? []).slice(0, MAX_TARGETS).flatMap((t) => {
    const m = (t.method ?? "POST").toUpperCase(), w = urlOf(base, t.path), r = urlOf(base, t.readPath);
    return [{ method: m, url: w }, { method: "GET", url: r }, { method: m, url: w }, { method: "GET", url: r }];
  });
}

export const signupPrivilege: Check = {
  name: "signup-privilege",
  title: "A registration endpoint accepts a privileged field (sign up as admin), active, staging only",
  readOnly: false,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = activeOptions<Opts>(ctx, "signup-privilege");
    if (!o) return [];
    const targets = (o.targets ?? []).slice(0, MAX_TARGETS);
    if (!ctx.stagingUrl || targets.length === 0) { ctx.log("signup-privilege: needs a stagingUrl and options.signup-privilege.targets"); return []; }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const client = new ActiveClient(ctx, "signup-privilege", o.maxRequests);
    const notes: string[] = [];
    const findings: Finding[] = [];

    for (const t of targets) {
      const method = (t.method ?? "POST").toUpperCase();
      const privFields = Object.entries(t.privileged ?? {});
      if (!t.name || !t.path || !t.readPath || !t.body || privFields.length === 0 || !["POST", "PUT"].includes(method)) {
        notes.push(`${t.name ?? "(unnamed)"}: skipped, needs name, path, readPath, body, privileged fields and POST/PUT.`);
        continue;
      }
      const idFields = t.identity ?? ["username"];
      const idField = idFields[0]!;
      const token = t.as ? o.accounts[t.as]?.token : undefined;
      // Build a signup body with unique identity values; tag with a marker.
      const unique = (seed: string) => {
        let b = { ...t.body };
        for (const f of idFields) b = setField(b, f, `crenel-${seed}-${nonce()}`.slice(0, 40));
        return b;
      };
      try {
        client.reserve(4);
        // 1. Control: register WITHOUT the privileged field.
        const ctlBody = unique("ctl");
        const ctlId = getField(ctlBody, idField);
        const ctl = await client.send(method, urlOf(base, t.path), token, ctlBody, { actor: t.as ?? "anon", purpose: "control: a normal signup", restore: "throwaway account" });
        if (!ok2xx(ctl.status)) { notes.push(`${t.name}: a normal signup was rejected (HTTP ${ctl.status}); check body/path.`); continue; }
        const afterCtl = records((await client.read(urlOf(base, t.readPath), token)).json, t.listField);
        const ctlRec = findBy(afterCtl, idField, ctlId);
        if (!ctlRec) { notes.push(`${t.name}: the control account is not visible in the readback; declare the right readPath/listField.`); continue; }
        const defaults = privFields.filter(([k, v]) => sameVal(getField(ctlRec, k), v));
        if (defaults.length === privFields.length) { notes.push(`${t.name}: the privileged field already holds the target value by default; declare a value a normal signup does not get.`); continue; }
        // 2. Probe: register WITH the privileged field set.
        let probeBody = unique("probe");
        const probeId = getField(probeBody, idField);
        for (const [k, v] of privFields) probeBody = setField(probeBody, k, v);
        const probe = await client.send(method, urlOf(base, t.path), token, probeBody, { actor: t.as ?? "anon", purpose: `probe: signup carrying ${privFields.map(([k]) => k).join(", ")}`, restore: "throwaway account" });
        if (!ok2xx(probe.status)) { notes.push(`${t.name}: the signup carrying the privileged field was rejected (HTTP ${probe.status}) — good, it is not accepted.`); continue; }
        const probeRec = findBy(records((await client.read(urlOf(base, t.readPath), token)).json, t.listField), idField, probeId);
        if (!probeRec) { notes.push(`${t.name}: the probe account is not visible in the readback.`); continue; }
        const accepted = privFields.filter(([k, v]) => sameVal(getField(probeRec, k), v) && !sameVal(getField(ctlRec, k), v));
        if (accepted.length === 0) { notes.push(`${t.name}: the server ignored the privileged field (not reflected on the created account) — correct behaviour.`); continue; }
        findings.push({
          id: `signup-privilege:${t.name}`,
          check: "signup-privilege",
          title: `Registration accepts a privileged field at ${t.path} (${accepted.map(([k]) => k).join(", ")})`,
          severity: "critical",
          state: "proven",
          location: urlOf(base, t.path),
          description: `A signup to ${method} ${t.path} carrying ${accepted.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ")} created an account with that value set, while a control signup without it did not. The registration endpoint mass-assigns a privileged field, so anyone registers as ${accepted.map(([k]) => k).join("/")} — an instant admin/privilege takeover.`,
          remediation: `Whitelist the fields a signup may set; never bind the request body straight to the user model. Reject or ignore ${accepted.map(([k]) => k).join(", ")} on registration and set privilege server-side only.`,
          proof: {
            method: "live on staging: a control signup shows the field at its default, a probe signup carrying the field shows it set — the server accepted a field it should ignore",
            replay: `curl -i -X ${method} ${JSON.stringify(urlOf(base, t.path))} -H 'content-type: application/json' --data ${JSON.stringify(JSON.stringify(setField({ ...t.body }, accepted[0]![0], accepted[0]![1])))}`,
            evidence: `control ${idField}=${ctlId}: ${accepted.map(([k]) => `${k}=${JSON.stringify(getField(ctlRec, k))}`).join(", ")}; probe ${idField}=${probeId}: ${accepted.map(([k]) => `${k}=${JSON.stringify(getField(probeRec, k))}`).join(", ")}`,
          },
          regressionHint: `After the fix, a signup carrying ${accepted.map(([k]) => k).join(", ")} must create an account where that field stays at its default.`,
        });
      } catch (err) {
        notes.push(`${t.name}: stopped (${(err as Error).message}).`);
      }
    }
    const receipt = writesFinding("signup-privilege", base, client.writes, notes);
    if (receipt) findings.push(receipt);
    ctx.log(`signup-privilege: ${client.requests} request(s), ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};

function sameVal(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
