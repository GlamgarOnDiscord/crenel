// User-enumeration oracle for the exploration layer (explore.user-enum).
//
// An endpoint leaks whether an account exists when its answer to a KNOWN account
// differs from its answer to a random one that cannot exist (OWASP: login, sign-up,
// password-reset that say "no such user" vs "wrong password"). The proof is a
// differential with a negative control: the same request is sent three times —
// with a username the model saw exist, and with TWO different random usernames
// that cannot exist. Proven iff the two non-existing answers are the SAME (so the
// difference is existence, not noise) and the existing answer differs from them in
// a stable way (status, or a phrase present in one and not the other). The
// submitted usernames are stripped from each body first, so an endpoint that only
// echoes the input back is never mistaken for a leak. Mechanism only, no target
// string. Pure, so it is tested without a network.

const sha = (s: string) => s; // bodies are compared after normalization, below
export interface Observed { status: number; body: string }

/** Remove the submitted identifier (and generic volatile noise) so two answers that
 * differ only by the echoed username compare equal. */
function normalize(body: string, injected: string): string {
  let b = body;
  if (injected) b = b.split(injected).join("§U§");
  return b
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "§UUID§")
    .replace(/\b\d{10,}\b/g, "§N§")
    .replace(/"(csrf|token|nonce|requestId|timestamp|time|date)"\s*:\s*"[^"]*"/gi, '"$1":"§"')
    .replace(/\s+/g, " ")
    .trim();
}

export function userEnumOracle(input: {
  existingName: string; absentName1: string; absentName2: string;
  existing: Observed; absent1: Observed; absent2: Observed;
}): { verdict: "enum" | "lead" | "denied"; reason: string; signal?: string } {
  const { existing, absent1, absent2 } = input;
  const nE = normalize(existing.body, input.existingName);
  const nA1 = normalize(absent1.body, input.absentName1);
  const nA2 = normalize(absent2.body, input.absentName2);
  // The two non-existing probes must answer identically, or the endpoint is just noisy.
  if (absent1.status !== absent2.status || nA1 !== nA2) {
    return { verdict: "lead", reason: `the two non-existing usernames get different answers (HTTP ${absent1.status} vs ${absent2.status}): the endpoint is noisy, not a clean enumeration` };
  }
  // The existing probe must differ from that stable "absent" answer.
  const statusDiff = existing.status !== absent1.status;
  const bodyDiff = nE !== nA1;
  if (!statusDiff && !bodyDiff) {
    return { verdict: "denied", reason: "an existing and a non-existing username get the same answer: no enumeration" };
  }
  const signal = statusDiff
    ? `existing -> HTTP ${existing.status}, non-existing -> HTTP ${absent1.status}`
    : `same HTTP ${existing.status} but the body differs for an existing vs a non-existing username`;
  return { verdict: "enum", reason: `the endpoint answers an existing username differently from a non-existing one, and identically for two different non-existing ones (${signal})`, signal };
}

void sha;
