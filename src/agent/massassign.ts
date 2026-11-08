// Mass-assignment oracle for the exploration layer (explore.mass-assignment).
//
// OWASP API6: an update endpoint binds the whole request body onto the object,
// so a field the client was never meant to set (role, isAdmin, credits, plan,
// verified…) is accepted and persisted. The exploration model names the field
// and the value; this validator proves the MECHANISM with a differential and a
// control, never a signature:
//
//   baseline  : read the object as the actor            -> field = v0
//   control   : update WITHOUT the field, re-read        -> field still v0 (the
//               field is not moved by an unrelated write)
//   injected  : update WITH field = value, re-read       -> field = value
//
// Proven iff the field took exactly the injected value, that value differs from
// the baseline, and the control update left it unchanged (so the change is
// caused by our injection, not a coincidence or an echo). Whether the field is
// one the client should control is the model's reading; what is proven is that
// the API accepted and persisted it. The object is the actor's own, so no other
// tenant is touched; the writes mutate state, so this needs active mode.

export interface Observed { status: number; body: string }
const ok2xx = (s: number) => s >= 200 && s < 300;

/** Find a JSON key at any depth and return its scalar value as a canonical
 * string ("true", "42", "admin"), or undefined when absent or non-scalar.
 * First occurrence in a depth-first walk wins. Pure. */
export function fieldValue(body: string, field: string): string | undefined {
  let root: unknown;
  try { root = JSON.parse(body); } catch { return undefined; }
  const seen = new Set<unknown>();
  const walk = (node: unknown): string | undefined => {
    if (node === null || typeof node !== "object") return undefined;
    if (seen.has(node)) return undefined;
    seen.add(node);
    if (!Array.isArray(node)) {
      const obj = node as Record<string, unknown>;
      if (Object.prototype.hasOwnProperty.call(obj, field)) {
        const v = obj[field];
        if (v === null || typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
      }
      for (const k of Object.keys(obj)) { const r = walk(obj[k]); if (r !== undefined) return r; }
    } else {
      for (const el of node) { const r = walk(el); if (r !== undefined) return r; }
    }
    return undefined;
  };
  return walk(root);
}

/** Canonical string form of a value the model supplied (so "true"/true/1 compare
 * against what the server echoes back through fieldValue). */
export function canonical(value: unknown): string {
  if (value === null) return "null";
  return String(value);
}

export function massAssignOracle(input: {
  field: string;
  injected: unknown;
  baseline: Observed;
  control: Observed;
  injectedRead: Observed;
}): { verdict: "set" | "lead" | "denied"; reason: string } {
  const { field, baseline, control, injectedRead } = input;
  const injected = canonical(input.injected);
  if (!ok2xx(baseline.status)) return { verdict: "denied", reason: `cannot read the object as the actor (HTTP ${baseline.status})` };
  const v0 = fieldValue(baseline.body, field);
  if (v0 === undefined) return { verdict: "lead", reason: `field "${field}" is not in the actor's own read: cannot prove persistence, review by hand` };
  if (injected === v0) return { verdict: "lead", reason: `the injected value equals the current value of "${field}": pick a value that differs` };
  const vC = fieldValue(control.body, field);
  if (vC !== undefined && vC !== v0) return { verdict: "lead", reason: `"${field}" changed (${v0} -> ${vC}) on an update that did NOT include it: the field is not isolated, review by hand` };
  const vI = fieldValue(injectedRead.body, field);
  if (vI === undefined) return { verdict: "lead", reason: `"${field}" vanished from the read after the injected update: inconclusive` };
  if (vI === injected) return { verdict: "set", reason: `"${field}" was ${v0}, the request body set it to ${injected} and the actor's own re-read confirms ${vI}; the control update without the field left it at ${v0}` };
  return { verdict: "lead", reason: `"${field}" did not take the injected value (read back ${vI}, injected ${injected}): the field may be ignored or coerced, review by hand` };
}

/** Build a JSON or form body merging `base` with an optional extra field. Pure. */
export function buildBody(base: Record<string, unknown>, extra: Record<string, unknown> | null, as: "json" | "form"): { body: string; contentType: string } {
  const merged = extra ? { ...base, ...extra } : { ...base };
  if (as === "form") {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(merged)) p.set(k, typeof v === "string" ? v : JSON.stringify(v));
    return { body: p.toString(), contentType: "application/x-www-form-urlencoded" };
  }
  return { body: JSON.stringify(merged), contentType: "application/json" };
}
