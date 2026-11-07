// graphql: an introspection query answered in production hands anyone the whole
// API map: every type, field and mutation, including the admin ones the UI
// hides. Bug hunters start there. We send the smallest read-only introspection
// query with GET (?query=...) to the usual paths on the declared host; a
// response that carries __schema data is the proof. GET only: a server that
// accepts GraphQL over POST only is not tested, and that is said in the log.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

const PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"];
const QUERY = "query{__schema{queryType{name}mutationType{name}types{name kind}}}";

export const graphql: Check = {
  name: "graphql",
  title: "GraphQL introspection open on the deployed API",
  readOnly: true, // a read-only query with GET on the declared host
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options.graphql ?? {}) as { paths?: string[] };
    const findings: Finding[] = [];
    for (const path of opts.paths ?? PATHS) {
      const url = `${base}${path}?query=${encodeURIComponent(QUERY)}`;
      let res;
      try { res = await safeFetch(url, ctx.scope, { headers: { accept: "application/json" } }); } catch { continue; }
      if (res.status !== 200) continue;
      let data: { data?: { __schema?: { types?: { name: string; kind: string }[]; mutationType?: { name: string } | null } } };
      try { data = JSON.parse(res.body); } catch { continue; }
      const schema = data.data?.__schema;
      if (!schema?.types?.length) continue;
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
        proof: { method: "read-only introspection query with GET, no credentials", replay: `curl -s '${url}'`, evidence: `HTTP 200, __schema with ${schema.types.length} types` },
        regressionHint: `After deploy, an introspection query on ${path} without credentials must fail.`,
      });
    }
    if (!findings.length) ctx.log("graphql: no introspection over GET on the usual paths (servers accepting POST only are not tested)");
    return findings;
  },
};
