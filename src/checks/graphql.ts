// graphql: an introspection query answered in production hands anyone the whole
// API map: every type, field and mutation, including the admin ones the UI
// hides. Bug hunters start there. We send the smallest read-only introspection
// query to the usual paths on the declared host, with GET (?query=...) first,
// then as a JSON POST for servers that refuse queries over GET. The client only
// lets that POST out because its body is a query (net.ts readOnlyPost). A
// response that carries __schema data is the proof.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { graphqlSuggestionsOracle, SUGGESTION_PROBES } from "../agent/graphql.js";

const PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"];
const QUERY = "query{__schema{queryType{name}mutationType{name}types{name kind}}}";

type Schema = { types: { name: string; kind: string }[]; mutationType?: { name: string } | null };

async function introspect(send: () => Promise<{ status: number; body: string }>): Promise<Schema | null> {
  try {
    const res = await send();
    if (res.status !== 200) return null;
    const schema = (JSON.parse(res.body) as { data?: { __schema?: Schema } }).data?.__schema;
    return schema?.types?.length ? schema : null;
  } catch { return null; }
}

// Field suggestions ("Did you mean …?") leak schema names even with introspection
// off. Read-only near-miss queries; bails after one request on a non-GraphQL path.
async function suggestionsAt(url: string, ctx: CheckContext): Promise<Finding | null> {
  const probe = async (q: string) => safeFetch(url, ctx.scope, { method: "POST", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ query: q }) });
  for (let i = 0; i < SUGGESTION_PROBES.length; i++) {
    let res;
    try { res = await probe(SUGGESTION_PROBES[i]!); } catch { return null; }
    const v = graphqlSuggestionsOracle({ status: res.status, body: res.body });
    if (v.verdict === "proven") {
      const p = (() => { try { return new URL(url).pathname; } catch { return url; } })();
      return {
        id: `graphql:suggestions:${p}`, check: "graphql",
        title: `GraphQL field suggestions enabled on ${p}`,
        severity: "low", state: "proven", location: url,
        description: `The GraphQL server answers an unknown field with "Did you mean …?", leaking schema field names even when introspection is off.`,
        remediation: "Disable field suggestions in production (graphql-js: a formatError that strips suggestions; graphql-core: disable the suggestion feature).",
        proof: { method: "read-only near-miss query, no credentials", replay: `curl -s -X POST -H 'content-type: application/json' --data '{"query":"${SUGGESTION_PROBES[i]}"}' '${url}'`, evidence: `HTTP ${res.status} with a "Did you mean" suggestion` },
        regressionHint: `After deploy, an unknown field on ${p} must not return a "Did you mean" suggestion.`,
      };
    }
    if (i === 0 && v.verdict === "denied") return null; // not a GraphQL endpoint: stop after one request
  }
  return null;
}

export const graphql: Check = {
  name: "graphql",
  title: "GraphQL introspection open on the deployed API",
  readOnly: true, // a read-only query, GET then POST, on the declared host
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options.graphql ?? {}) as { paths?: string[] };
    const findings: Finding[] = [];
    for (const path of opts.paths ?? PATHS) {
      const url = `${base}${path}?query=${encodeURIComponent(QUERY)}`;
      let via = "GET";
      let schema = await introspect(() => safeFetch(url, ctx.scope, { headers: { accept: "application/json" } }));
      if (!schema) {
        via = "POST";
        schema = await introspect(() => safeFetch(base + path, ctx.scope, { method: "POST", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ query: QUERY }) }));
      }
      if (!schema) {
        // Introspection may be off; still detect field suggestions (schema disclosure)
        // with a couple of query-only probes, but only on a path that speaks GraphQL.
        const sugg = await suggestionsAt(base + path, ctx);
        if (sugg) findings.push(sugg);
        continue;
      }
      const replay = via === "GET" ? `curl -s '${url}'` : `curl -s -X POST -H 'content-type: application/json' --data '${JSON.stringify({ query: QUERY })}' '${base}${path}'`;
      const own = schema.types.filter((t) => !t.name.startsWith("__") && t.kind === "OBJECT").map((t) => t.name);
      findings.push({
        id: `graphql:introspection:${path}`,
        check: "graphql",
        title: `GraphQL introspection is open on ${path} (${own.length} object types${schema.mutationType ? ", mutations included" : ""})`,
        severity: "medium",
        state: "proven",
        location: `${base}${path}`,
        description: `An unauthenticated introspection query on ${path} returned the schema: ${own.slice(0, 12).join(", ")}${own.length > 12 ? "…" : ""}. Anyone can list every query and mutation, including admin ones the UI never shows.`,
        remediation: "Disable introspection in production (or require auth for it), and check each object resolver for ownership: object ids in GraphQL are often guessable global ids.",
        proof: { method: `read-only introspection query with ${via}, no credentials`, replay, evidence: `HTTP 200, __schema with ${schema.types.length} types` },
        regressionHint: `After deploy, an introspection query on ${path} without credentials must fail.`,
      });
      const sugg = await suggestionsAt(base + path, ctx);
      if (sugg) findings.push(sugg);
    }
    if (!findings.length) ctx.log("graphql: no open introspection on the usual paths (GET and POST)");
    return findings;
  },
};
