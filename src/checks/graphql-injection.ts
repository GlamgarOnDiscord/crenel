// graphql-injection: find injectable string arguments on a GraphQL API without
// being told where. The check introspects the schema, and for every query/mutation
// field that takes a String argument it builds a VALID probe query (a scalar sub-
// field when the field returns an object) and injects into that argument. The same
// generic oracles decide: a NEW database error that a benign value does not raise
// (error-based SQLi), or a shell/template arithmetic the server evaluated (command
// / template injection). No hard-coded field names — the sinks come from the live
// schema; the payloads and oracles are generic.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { sqliOracle, templateOracle, nonce } from "../agent/inject.js";

const SCALARS = new Set(["String", "ID", "Int", "Float", "Boolean"]);
// A type ref resolves through LIST / NON_NULL wrappers to a named type + kind.
function named(t: any): { kind: string; name: string } {
  while (t && (t.kind === "LIST" || t.kind === "NON_NULL")) t = t.ofType;
  return { kind: t?.kind ?? "", name: t?.name ?? "" };
}
const isString = (a: any) => named(a.type).name === "String";
const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
// A GraphQL response that parses and carries no top-level `errors`: a successful
// data response. Used to exclude a WAF/validation error from the boolean-SQLi
// differential (an error on the quoted payload is not a changed result set).
const noErrors = (body: string): boolean => {
  try { const j = JSON.parse(body); return !!j && typeof j === "object" && !(Array.isArray((j as any).errors) && (j as any).errors.length > 0); } catch { return false; }
};

export const graphqlInjection: Check = {
  name: "graphql-injection",
  title: "Injectable string argument on a GraphQL field (schema-discovered)",
  readOnly: false, // sends injection payloads to resolvers: active gate
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["graphql-injection"] ?? {}) as { enabled?: boolean; endpoint?: string };
    if (o.enabled !== true || !ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    const url = base + (o.endpoint ?? "/graphql");
    if (!ctx.scope.isHostAllowed(url)) return [];
    ctx.scope.assertActiveAllowed("graphql-injection (injection payloads into resolvers)");
    const gql = async (query: string) => {
      try { const r = await safeFetch(url, ctx.scope, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ query }), maxBytes: 128 * 1024 }); return { status: r.status, body: r.body }; } catch { return { status: 0, body: "" }; }
    };
    // 1. introspect fields of query + mutation, with their args and return type.
    const schema = await gql(`{__schema{queryType{fields{name args{name type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}} type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}} mutationType{fields{name args{name type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}} type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}`);
    let j: any; try { j = JSON.parse(schema.body); } catch { return []; }
    const q = j?.data?.__schema?.queryType?.fields ?? [];
    const m = j?.data?.__schema?.mutationType?.fields ?? [];
    const fields = [...q, ...m].filter((f: any) => (f.args ?? []).some(isString)).slice(0, 40);
    if (fields.length === 0) { ctx.log("graphql-injection: no string-argument field in the schema"); return []; }
    // cache a scalar sub-field per object type (so object-returning fields get a valid selection)
    const scalarField = new Map<string, string | null>();
    const selFor = async (ret: { kind: string; name: string }): Promise<string | null> => {
      if (ret.kind === "SCALAR" || ret.name === "") return ""; // scalar: no selection
      if (ret.kind !== "OBJECT") return null; // union/interface: skip (needs fragments)
      if (!scalarField.has(ret.name)) {
        const t = await gql(`{__type(name:"${ret.name}"){fields{name type{kind name ofType{kind name}}}}}`);
        let f: string | null = null;
        try { const fs = JSON.parse(t.body)?.data?.__type?.fields ?? []; const sc = fs.find((x: any) => { const n = named(x.type); return n.kind === "SCALAR" && SCALARS.has(n.name); }); f = sc ? sc.name : null; } catch { f = null; }
        scalarField.set(ret.name, f);
      }
      const f = scalarField.get(ret.name);
      return f ? `{ ${f} }` : null;
    };
    const findings: Finding[] = [];
    for (const f of fields) {
      const strArgs = (f.args ?? []).filter(isString);
      const sel = await selFor(named(f.type));
      if (sel === null) continue;
      for (const arg of strArgs) {
        // other string args filled with a benign constant so the query is valid.
        const others = (f.args ?? []).filter((a: any) => a.name !== arg.name && isString(a)).map((a: any) => `${a.name}: "crenelx"`).join(", ");
        const call = (val: string) => `{ ${f.name}(${arg.name}: "${esc(val)}"${others ? ", " + others : ""}) ${sel} }`.trim();
        const send = async (val: string) => gql(call(val));
        const benignTok = "crenel" + nonce();
        const baseline = await send(benignTok);
        // error-based SQLi: a quote raises a NEW database error.
        const sTrue = await send(benignTok + "' OR '1'='1");
        const sFalse = await send(benignTok + "' AND '1'='2");
        let proof: { kind: string; reason: string; payload: string } | null = null;
        const sq = sqliOracle({ baseline: { status: baseline.status, body: baseline.body }, truthy: { status: sTrue.status, body: sTrue.body }, falsy: { status: sFalse.status, body: sFalse.body } });
        if (sq.verdict === "proven") proof = { ...sq, payload: benignTok + "' OR '1'='1" };
        // GraphQL boolean SQLi: the field always answers 200, so the signal is the
        // result SET. A TRUE tautology returns rows the benign value and the FALSE
        // tautology do not — a literal-string filter would treat all three the same.
        // Guard against a WAF / safe resolver that merely ERRORS on the quoted TRUE
        // payload: require all three to be successful, error-free data responses, so
        // the difference is a changed result set, not a parse/validation error.
        if (!proof && baseline.status === 200 && sTrue.status === 200 && sFalse.status === 200
          && noErrors(baseline.body) && noErrors(sTrue.body) && noErrors(sFalse.body)
          && sTrue.body !== sFalse.body && sTrue.body !== baseline.body && sFalse.body === baseline.body) {
          proof = { kind: "sqli-boolean", reason: `a TRUE tautology (' OR '1'='1) changes the result set while a FALSE one (' AND '1'='2) matches the benign value, all three error-free: the argument reaches the SQL boolean logic`, payload: benignTok + "' OR '1'='1" };
        }
        if (!proof) {
          // OS command / template: a shell arithmetic evaluated next to the nonce.
          for (const form of ["; echo T$((7*7))", "| echo T$((7*7))", "$(echo T$((7*7)))", "T${7*7}"]) {
            const t = nonce("gqlc");
            const injected = benignTok + form.replace("T", t);
            const res = await send(injected);
            const r = templateOracle({ token: t, product: "49", body: res.body });
            if (r.verdict === "proven") { proof = { kind: /\$\(\(|echo|`/.test(form) ? "command" : "template", reason: r.reason, payload: injected }; break; }
          }
        }
        if (!proof) continue;
        const sqli = proof.kind.startsWith("sqli");
        const provenBy = proof.kind === "sqli-boolean" ? "a TRUE/FALSE response-set differential with a benign control"
          : sqli ? "a new database error absent from a benign query"
          : "a computation the server evaluated";
        findings.push({
          id: `graphql-injection:${f.name}:${arg.name}`,
          check: "graphql-injection",
          title: `${sqli ? "SQL injection" : proof.kind === "command" ? "OS command injection" : "Template injection"} in GraphQL ${f.name}(${arg.name}:)`,
          severity: "critical",
          state: "proven",
          location: url,
          description: `The ${arg.name} argument of the GraphQL field ${f.name} is injectable: ${proof.reason}. Discovered from the schema, proven by ${provenBy}.`,
          remediation: `Use parameterized queries / safe APIs in the ${f.name} resolver; never build a query or a shell command from a GraphQL argument.`,
          proof: { method: "schema-discovered sink + generic injection oracle on staging, with a benign control", replay: `POST ${url} with ${call(proof.payload)}`, evidence: proof.reason },
          regressionHint: `After deploy, ${f.name}(${arg.name}:) must not raise a database error or evaluate an expression from its value.`,
        });
        break; // one proof per field is enough
      }
    }
    if (findings.length === 0) ctx.log("graphql-injection: no injectable string argument proven");
    return findings;
  },
};
