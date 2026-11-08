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

/** Near-misses of universal fields: a server with suggestions on answers each with
 * "Did you mean …?". No schema knowledge needed. */
export const SUGGESTION_PROBES = ["{ __typenam }", "{ __schem }", "{ __typ }"];
