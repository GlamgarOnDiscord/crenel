// Function-level authorization oracle for the exploration layer (explore.bfla).
//
// OWASP API5 (BFLA): a lower-privilege account reaches a function meant for a
// higher-privilege one. "Higher privilege" cannot be guessed, so it must be
// DECLARED in the config (accounts.<x>.privileged: true); the validator only
// proves the mechanism. A privileged account P and a normal account A both call
// the same function; anonymous is the boundary. Proven iff:
//   - P succeeds (the function exists and P may use it),
//   - anonymous is denied (a real boundary, not a public endpoint),
//   - a nonsense variant as A is denied (A does not just get 2xx for everything),
//   - A succeeds the same way P does — for a read, A's body matches P's (A sees
//     the privileged view, not an empty personalized one); for a write, both 2xx.
// No target string. Pure, so it is tested without a network.

export interface Observed { status: number; body: string }
const ok2xx = (s: number) => s >= 200 && s < 300;
const denied = (s: number) => s === 401 || s === 403 || s === 404;

function similar(a: Observed, b: Observed): boolean {
  if (a.status !== b.status) return false;
  const na = a.body.replace(/\s+/g, " ").trim(), nb = b.body.replace(/\s+/g, " ").trim();
  if (na === nb) return true;
  // Close length and a large shared prefix: the same view with a few volatile fields.
  const lo = Math.min(na.length, nb.length), hi = Math.max(na.length, nb.length);
  if (hi === 0 || lo / hi < 0.9) return false;
  let i = 0; while (i < lo && na[i] === nb[i]) i++;
  return i / hi >= 0.8;
}

export function bflaOracle(input: {
  isRead: boolean; privileged: Observed; normal: Observed; anon: Observed; control: Observed;
}): { verdict: "bfla" | "lead" | "denied"; reason: string } {
  const { isRead, privileged, normal, anon, control } = input;
  if (!ok2xx(privileged.status)) return { verdict: "denied", reason: `the privileged account does not reach the function (HTTP ${privileged.status}): nothing to compare` };
  if (ok2xx(anon.status)) return { verdict: "lead", reason: `an anonymous caller reaches it (HTTP ${anon.status}): the function is public, not privilege-gated` };
  if (ok2xx(control.status)) return { verdict: "lead", reason: `a nonsense variant as the normal account also answers 2xx: the endpoint is not discriminating, review by hand` };
  if (!ok2xx(normal.status)) return { verdict: "denied", reason: `the normal account is refused (HTTP ${normal.status}): the function-level check holds` };
  if (isRead && !similar(normal, privileged)) return { verdict: "lead", reason: `the normal account gets 2xx but a different body from the privileged one: it may be a personalized view, not the privileged function — review by hand` };
  return { verdict: "bfla", reason: `the normal account reaches the function the privileged account uses (both HTTP ${normal.status}${isRead ? ", same view" : ""}) while anonymous is denied (HTTP ${anon.status}) and a nonsense variant is denied` };
}
