// CTF flag-capture oracle for the exploration layer (explore.flag).
//
// A `lead` names a weakness; a `flag` capture PROVES the exploitation end to end.
// When the model reaches a flag through a vulnerability (SSRF to an internal page,
// an IDOR that reads another tenant's record, LFI/path traversal, a deserialization
// RCE that cats the flag file, …), it submits the request that reached it; the
// validator REPLAYS that request and confirms a flag-format token is in the real
// response. Deterministic and ~zero false positive: the flag must actually be
// returned by the replay (the model cannot assert it), and it must NOT be a token
// we sent ourselves — an echo of our own input is a reflection, not a capture.
//
// The pattern is configurable (options.explore.flagPattern). The default is the
// universal CTF flag format `flag{...}` — a FORMAT, never one target's answer, the
// same spirit as matching a SQL-error shape or a canary marker, not a bench string.

const DEFAULT_FLAG = "flag\\{[^}\\s]{3,}\\}";

export function flagOracle(input: { body: string; pattern?: string; sent?: string }): { verdict: "proven" | "denied"; reason: string; flag?: string } {
  let re: RegExp;
  try { re = new RegExp(input.pattern ?? DEFAULT_FLAG, "i"); } catch { re = new RegExp(DEFAULT_FLAG, "i"); }
  const m = input.body.match(re);
  if (!m) return { verdict: "denied", reason: "no flag token in the response" };
  const flag = m[0];
  // Anti-echo control: a flag we put into our own request (URL, headers, body) and
  // saw reflected back is not a capture. The real retrieval must surface it anew.
  if (input.sent && input.sent.includes(flag)) return { verdict: "denied", reason: "the flag token appears in our own request (reflected echo, not retrieved)" };
  return { verdict: "proven", reason: `a flag token was retrieved from the response: ${flag}`, flag };
}
