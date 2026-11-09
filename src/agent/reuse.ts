// Business-logic reuse oracle for the exploration layer (explore.reuse).
//
// A single-use artifact (a coupon, a credit grant, a one-time invite) that the
// server applies more than once is a business-logic flaw (OWASP API; think
// crAPI's reusable coupon). The proof is a differential the validator replays:
// apply the SAME artifact twice and prove BOTH applications succeed the same
// way, while a clearly-invalid artifact is rejected. The endpoint therefore
// tells valid from invalid but not used-from-unused. Whether the artifact was
// meant to be single-use is the model's reading; what is proven is that its
// effect is granted at least twice. Mutating, so it needs active mode.
//
// Pure, so it is tested without a network.

const ok2xx = (s: number) => s >= 200 && s < 300;
export interface Observed { status: number; body: string }

/** A response counts as a successful application when it is 2xx and carries one
 * of the success markers the model named (e.g. "discount", "applied", "credited"). */
function succeeds(r: Observed, markers: string[]): boolean {
  if (!ok2xx(r.status)) return false;
  const body = r.body.toLowerCase();
  return markers.some((m) => m && body.includes(m.toLowerCase()));
}

// Words that turn a success marker into a refusal ("coupon already used", "credit expired").
const REFUSAL = /\b(already|used|redeemed|expired|invalid|exceeded|limit|once|duplicate|not allowed|denied|error)\b/g;

export function reuseOracle(input: {
  first: Observed;
  second: Observed;
  control: Observed;
  /** Strings that only appear when the artifact was actually applied. */
  successMarkers: string[];
}): { verdict: "reused" | "lead" | "denied"; reason: string } {
  const { first, second, control, successMarkers } = input;
  if (!successMarkers.length) return { verdict: "lead", reason: "no success marker given: cannot tell an applied artifact from a rejected one" };
  if (!succeeds(first, successMarkers)) return { verdict: "denied", reason: `the first application did not succeed (HTTP ${first.status}): nothing to reuse` };
  if (succeeds(control, successMarkers)) return { verdict: "lead", reason: "an invalid artifact also 'succeeds': the endpoint does not validate at all, review by hand (not a reuse proof)" };
  if (succeeds(second, successMarkers)) {
    // A marker inside a refusal ("discount already used") is not a second success: the second answer must
    // have the first one's status and carry no refusal word the first did not.
    const refusal = (b: string) => new Set((b.toLowerCase().match(REFUSAL) ?? []));
    const r1 = refusal(first.body), extra = [...refusal(second.body)].filter((w) => !r1.has(w));
    if (second.status !== first.status) return { verdict: "lead", reason: `the second application answered HTTP ${second.status} where the first answered ${first.status}: review by hand` };
    if (extra.length) return { verdict: "lead", reason: `the second answer carries the marker but also "${extra[0]}", which the first did not: likely a refusal, review by hand` };
    return { verdict: "reused", reason: `the same artifact was applied twice (both HTTP ${first.status}, both carry the success marker, no refusal in the second) while an invalid one is rejected` };
  }
  return { verdict: "lead", reason: `the second application did not repeat the success (HTTP ${second.status}): the artifact may be correctly single-use` };
}
