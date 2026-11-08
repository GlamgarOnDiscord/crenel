// GraphQL field-suggestions oracle for the exploration layer (explore.graphql).
//
// graphql-js (and most servers) answer an unknown field with "Did you mean
// <field>?" when suggestions are enabled, leaking schema names even with
// introspection off. The probe is universal and needs no schema knowledge: ask
// for a deliberate near-miss of `__typename` (a field every schema has); if the
// error carries a suggestion, suggestions are on. Generic behaviour of the
// protocol, not a signature for any target. Pure, so it is tested without a network.

export interface Observed { status: number; body: string }

export function graphqlSuggestionsOracle(input: Observed): { verdict: "proven" | "lead" | "denied"; reason: string } {
  const b = input.body.toLowerCase();
  if (/did you mean/.test(b)) return { verdict: "proven", reason: 'the GraphQL server returns field-name suggestions ("Did you mean"): schema names leak with suggestions enabled' };
  if (b.includes('"errors"') || b.includes("cannot query field") || b.includes("graphql")) return { verdict: "lead", reason: "the endpoint speaks GraphQL but returned no field suggestion: suggestions may be off" };
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
// with no per-operation rate limit — DoS amplification / rate-limit bypass. The
// proof is a differential the validator replays: a batch of N identical queries
// comes back as an array of N results. Generic protocol behaviour, no signature.
export function graphqlBatchOracle(input: { status: number; body: string; sent: number }): { verdict: "proven" | "lead" | "denied"; reason: string } {
  const { sent } = input;
  let j: unknown;
  try { j = JSON.parse(input.body); } catch { return { verdict: "denied", reason: "the batch response is not JSON" }; }
  if (Array.isArray(j) && j.length >= sent && sent >= 2) {
    return { verdict: "proven", reason: `query batching is accepted with no rate limit: a batch of ${sent} queries ran and returned ${j.length} results in one request (DoS amplification)` };
  }
  if (Array.isArray(j)) return { verdict: "lead", reason: `the server returned an array of ${j.length} for a batch of ${sent}: review by hand` };
  return { verdict: "denied", reason: "the server did not execute the batched array (batching off)" };
}
