import { test } from "node:test";
import assert from "node:assert/strict";
import { graphqlSuggestionsOracle, SUGGESTION_PROBES } from "./graphql.js";

test("graphql: a 'Did you mean' answer proves field suggestions", () => {
  const r = graphqlSuggestionsOracle({ status: 200, body: '{"errors":[{"message":"Cannot query field \\"__typenam\\". Did you mean \\"__typename\\"?"}]}' });
  assert.equal(r.verdict, "proven");
});
test("graphql: errors without suggestion -> lead", () => {
  const r = graphqlSuggestionsOracle({ status: 200, body: '{"errors":[{"message":"Cannot query field x"}]}' });
  assert.equal(r.verdict, "lead");
});
test("graphql: non-graphql response -> denied", () => {
  const r = graphqlSuggestionsOracle({ status: 404, body: "not here" });
  assert.equal(r.verdict, "denied");
});
test("graphql: probes are GraphQL near-miss queries (no target-specific field)", () => {
  assert.ok(SUGGESTION_PROBES.length >= 3 && SUGGESTION_PROBES.every((p) => p.trim().startsWith("{")));
});
