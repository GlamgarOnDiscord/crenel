// GraphQL field-suggestions oracle for the exploration layer (explore.graphql).
//
// graphql-js (and most servers) answer an unknown field with "Did you mean
// <field>?" when suggestions are enabled, leaking schema names even with
// introspection off. The probe is universal and needs no schema knowledge: ask
// for a deliberate near-miss of `__typename` (a field every schema has); if the
// error carries a suggestion, suggestions are on. Generic behaviour of the
// protocol, not a signature for any target. Pure, so it is tested without a network.

export interface Observed { status: number; body: string }

/** The messages of a GraphQL error response ({"errors":[{"message":…}]}), or null when the body is not one. */
export function graphqlErrors(body: string): string[] | null {
  let j: unknown;
  try { j = JSON.parse(body); } catch { return null; }
  const errs = j && typeof j === "object" && !Array.isArray(j) ? (j as { errors?: unknown }).errors : undefined;
  if (!Array.isArray(errs)) return null;
  return errs.map((e) => (e && typeof e === "object" && typeof (e as { message?: unknown }).message === "string" ? (e as { message: string }).message : "")).filter(Boolean);
}

export function graphqlSuggestionsOracle(input: Observed): { verdict: "proven" | "lead" | "denied"; reason: string } {
  const b = input.body.toLowerCase();
  // Only a parsed GraphQL field-validation error counts: "Did you mean" on an HTML page or a REST error proves nothing.
  const msgs = graphqlErrors(input.body);
  if (msgs?.some((m) => /did you mean/i.test(m) && /field|argument|type/i.test(m))) return { verdict: "proven", reason: 'the GraphQL server returns field-name suggestions ("Did you mean"): schema names leak with suggestions enabled' };
  if (msgs !== null || /^\s*\{\s*"data"\s*:/.test(input.body) || b.includes("cannot query field")) return { verdict: "lead", reason: "the endpoint speaks GraphQL but returned no field suggestion: suggestions may be off" };
  return { verdict: "denied", reason: "no GraphQL field suggestion in the response" };
}

/** Near-misses of universal/common field names: a server with suggestions on
 * answers each with "Did you mean …?". graphql-js suggests meta-fields, graphql-core
 * (Python) only real fields, so both the __typename near-misses and typos of the
 * most common root fields are tried. No target-specific name, no schema knowledge. */
export const SUGGESTION_PROBES = [
  "{ __typenam }", "{ __schem }",
  "{ usr }", "{ usrs }", "{ mee }", "{ nodee }", "{ serch }",
  "{ postz }", "{ productz }", "{ orderz }", "{ commentz }", "{ itemz }",
];

// Query batching: a JSON ARRAY of queries that the server runs in one request,
// which lets a client multiply operations per request (amplification, and a way
// around per-request rate limits). The proof is that a batch of N identical
// queries comes back as N results that each carry data and no error. Whether a
// rate limit applies per operation is NOT tested. Generic protocol behaviour.
export function graphqlBatchOracle(input: { status: number; body: string; sent: number }): { verdict: "proven" | "lead" | "denied"; reason: string } {
  const { sent } = input;
  let j: unknown;
  try { j = JSON.parse(input.body); } catch { return { verdict: "denied", reason: "the batch response is not JSON" }; }
  const okEntry = (e: unknown) => !!e && typeof e === "object" && (e as { data?: unknown }).data != null && !(e as { errors?: unknown }).errors;
  if (input.status >= 200 && input.status < 300 && Array.isArray(j) && j.length === sent && sent >= 2 && j.every(okEntry)) {
    return { verdict: "proven", reason: `query batching is accepted: a batch of ${sent} queries ran in one request and each returned data without error (operations multiply per request; per-operation rate limiting was not tested)` };
  }
  if (Array.isArray(j)) return { verdict: "lead", reason: `the server returned an array of ${j.length} for a batch of ${sent}, not all with data and without error (throttled or partial): review by hand` };
  return { verdict: "denied", reason: "the server did not execute the batched array (batching off)" };
}
