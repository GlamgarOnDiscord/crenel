// Cross-account write oracle for the exploration layer (explore.cross-actor-write).
//
// OWASP API1/API5 on writes: account A deletes or changes an object of account B.
// Ownership is not inferred: the validator has B CREATE the object first, so it
// is B's by construction. Then, with B re-reading after each step:
//   before     : B reads its new object                      -> 2xx
//   anonymous  : the same write with no credentials (control) -> B's read unchanged
//   attacker   : the same write with A's token               -> B's read changed
// Proven iff the object was readable and unchanged after the anonymous attempt,
// and only A's write changed it: DELETE leaves B a 404/410; PUT/PATCH leaves the
// field at exactly the value A wrote (and it was different before). When the
// anonymous write already changes it, that is the worse flaw and is reported as
// such. Mechanism only, no target names. Pure, so it is tested without a network.

import { fieldValue, canonical } from "./massassign.js";

export interface Observed { status: number; body: string }
const ok2xx = (s: number) => s >= 200 && s < 300;
const gone = (s: number) => s === 404 || s === 410;

export function crossWriteOracle(input: {
  method: "DELETE" | "PUT" | "PATCH";
  field?: string;
  value?: unknown;
  before: Observed;
  afterAnon: Observed;
  attacker: Observed;
  after: Observed;
}): { verdict: "written" | "anon-written" | "lead" | "denied"; reason: string } {
  const { method, field, before, afterAnon, attacker, after } = input;
  if (!ok2xx(before.status)) return { verdict: "lead", reason: `the owner cannot read its own new object (HTTP ${before.status}): nothing to compare` };
  if (method === "DELETE") {
    if (gone(afterAnon.status)) return { verdict: "anon-written", reason: "a DELETE with no credentials removed the owner's object (its read now answers " + afterAnon.status + ")" };
    if (!ok2xx(afterAnon.status)) return { verdict: "lead", reason: `the owner's read failed after the anonymous control (HTTP ${afterAnon.status}): inconclusive` };
    if (gone(after.status) && ok2xx(attacker.status)) return { verdict: "written", reason: `the object the owner had just created and could read was deleted by the attacker's DELETE (HTTP ${attacker.status}); the owner now gets ${after.status}, while an anonymous DELETE had left it in place` };
    if (gone(after.status)) return { verdict: "lead", reason: `the object is gone but the attacker's DELETE answered HTTP ${attacker.status}: review by hand` };
    return { verdict: "denied", reason: `the owner still reads its object (HTTP ${after.status}) after the attacker's DELETE (HTTP ${attacker.status})` };
  }
  if (!field) return { verdict: "lead", reason: "a PUT/PATCH needs detail.field: the value the write sets" };
  const want = canonical(input.value);
  const v0 = fieldValue(before.body, field);
  if (v0 === undefined) return { verdict: "lead", reason: `"${field}" is not in the owner's read: cannot see a change` };
  if (v0 === want) return { verdict: "lead", reason: `"${field}" is already ${want}: pick a value that differs` };
  const vAnon = fieldValue(afterAnon.body, field);
  if (ok2xx(afterAnon.status) && vAnon === want) return { verdict: "anon-written", reason: `a ${method} with no credentials set "${field}" of the owner's object to ${want}` };
  if (!ok2xx(afterAnon.status) || vAnon !== v0) return { verdict: "lead", reason: `the owner's read changed or failed after the anonymous control (HTTP ${afterAnon.status}): inconclusive` };
  if (!ok2xx(after.status)) return { verdict: "lead", reason: `the owner's read failed after the attacker's write (HTTP ${after.status}): inconclusive` };
  const v1 = fieldValue(after.body, field);
  if (v1 === want) return { verdict: "written", reason: `"${field}" of the object the owner had just created was ${v0}; the attacker's ${method} set it to ${want} and the owner's own re-read confirms it, while an anonymous ${method} had left it at ${v0}` };
  return { verdict: "denied", reason: `"${field}" is still ${v1 ?? "(absent)"} for the owner after the attacker's ${method}` };
}
