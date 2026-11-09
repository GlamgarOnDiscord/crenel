// Privilege-escalation oracle for the exploration layer (explore.priv-escalation).
//
// The strongest, least arguable proof of a broken privilege boundary: an account's
// ACCESS flips from denied to allowed after a write the account made itself. The
// model names a privileged endpoint the account cannot reach (a "gate") and a write
// it can make on its own object (set role/isAdmin/plan). The validator checks the
// gate is STABLY denied for the account (two reads: the negative control), makes the
// write, then checks the SAME gate now answers. Proven iff the gate was denied
// before (both reads) and is allowed after — the account gained access it did not
// have. No target string: the proof is the state flip, not any value. The write
// mutates the account's own object, so it needs active mode; the field is restored
// afterwards. Pure, so it is tested without a network.

export interface Observed { status: number; body: string }
const ok2xx = (s: number) => s >= 200 && s < 300;
const denied = (s: number) => s === 401 || s === 403 || s === 404;

export function privEscOracle(input: {
  gateBefore1: Observed; gateBefore2: Observed; gateAfter: Observed; gateAnon: Observed;
}): { verdict: "escalated" | "lead" | "denied"; reason: string } {
  const { gateBefore1, gateBefore2, gateAfter, gateAnon } = input;
  // The gate must be a real boundary: an anonymous caller is refused.
  if (ok2xx(gateAnon.status)) return { verdict: "lead", reason: `the gate answers an anonymous caller (HTTP ${gateAnon.status}): it is not a privilege boundary` };
  // The account must be refused BEFORE, twice (stable), or there is no boundary to cross.
  if (!denied(gateBefore1.status) || !denied(gateBefore2.status)) return { verdict: "denied", reason: `the account already reaches the gate before any write (HTTP ${gateBefore1.status}/${gateBefore2.status}): nothing was escalated` };
  if (gateBefore1.status !== gateBefore2.status) return { verdict: "lead", reason: `the gate's denial is unstable before the write (HTTP ${gateBefore1.status} then ${gateBefore2.status}): review by hand` };
  // After the account's own write, the gate must answer it.
  if (ok2xx(gateAfter.status)) return { verdict: "escalated", reason: `the account was denied the gate (HTTP ${gateBefore1.status}, twice) and reaches it (HTTP ${gateAfter.status}) only after its own write: it gained access it did not have` };
  return { verdict: "denied", reason: `the gate still denies the account after the write (HTTP ${gateAfter.status})` };
}
