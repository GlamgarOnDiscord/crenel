// CORS misconfiguration oracle for the exploration layer (explore.cors).
//
// A server that reflects an ARBITRARY Origin into Access-Control-Allow-Origin
// AND sets Access-Control-Allow-Credentials: true lets any site read the
// victim's authenticated responses. The proof is a differential with its own
// control: two different attacker origins are BOTH reflected (so it reflects
// anything, not an allowlist that happened to include one guess), and
// credentials are allowed. Generic — no target signature. A wildcard `*` is
// only a lead: browsers refuse to send credentials to `*`.

export interface CorsResp { acao: string | null; acac: string | null }

/** Canonicalize ACAC: "true" (any case) is the only credential-enabling value. */
const credsOn = (acac: string | null) => (acac ?? "").trim().toLowerCase() === "true";

export function corsOracle(input: { o1: string; r1: CorsResp; o2: string; r2: CorsResp }): { verdict: "proven" | "lead" | "denied"; reason: string; ceiling: "high" | "medium" } {
  const { o1, r1, o2, r2 } = input;
  const reflectsBoth = r1.acao === o1 && r2.acao === o2;
  const creds = credsOn(r1.acac) && credsOn(r2.acac);
  if (reflectsBoth && creds) return { verdict: "proven", reason: `Access-Control-Allow-Origin reflects any origin (tested ${o1} and ${o2}) with Allow-Credentials: true: any site can read authenticated responses`, ceiling: "high" };
  if (r1.acao === "null" && r2.acao === "null" && creds) return { verdict: "proven", reason: "Access-Control-Allow-Origin: null with Allow-Credentials: true: a sandboxed iframe can read authenticated responses", ceiling: "high" };
  if (reflectsBoth) return { verdict: "lead", reason: "the origin is reflected into Access-Control-Allow-Origin but credentials are not allowed: a cross-site read without cookies, review by hand", ceiling: "medium" };
  if ((r1.acao === "*" || r2.acao === "*") && creds) return { verdict: "lead", reason: "Access-Control-Allow-Origin: * with Allow-Credentials set, which browsers reject for credentialed requests: review by hand", ceiling: "medium" };
  return { verdict: "denied", reason: "the server did not reflect the attacker origin into Access-Control-Allow-Origin", ceiling: "medium" };
}
