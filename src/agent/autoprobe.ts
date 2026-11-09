// Deterministic auto-probe for the exploration layer (track B, honest variant).
//
// The free-exploration model finds a different subset each run (variance). This
// removes the model from the PROBE-GENERATION step: given the endpoints the
// deterministic recon discovered (and the configured test accounts), it submits a
// systematic set of claims — one per endpoint x applicable technique — to the SAME
// generic validators. Proof stays gated by the validators (no self-assertion, no
// signature); every request still goes through the scoped client. The result is
// reproducible (no run-to-run variance) and honest.
//
// autoClaims is pure (tested without a network); runAutoProbe validates each claim.

import type { Claim, ClaimVerdict, ValidatorEnv } from "./validators.js";
import { validateClaim, actorToken } from "./validators.js";
import { safeFetch } from "../core/net.js";
import { ownerFieldValues, tokenIdentity } from "./markers.js";

// Login routes by their usual names (the same in any API), not by a target's path.
const LOGIN_PATH = /(^|\/)(login|signin|sign-in|log-in|authenticate)(\/|$)/i;

export interface Endpoint { url: string; params?: string[]; graphql?: boolean; /** The route with ":id" where the object id goes. */ template?: string }

/** Build the systematic claim set for the discovered endpoints. Pure. `accounts`
 * are the configured test-account ids (a/b/c) that have a token. `origin` is the
 * scheme+host for the CORS probe. No target-specific values: only the endpoints the
 * recon already found and the generic techniques. */
export function autoClaims(input: { endpoints: Endpoint[]; accounts: string[]; origin?: string; ownerIds?: string[] }): Claim[] {
  const { endpoints, accounts } = input;
  const has = (a: string) => accounts.includes(a);
  const claims: Claim[] = [];
  let n = 0;
  const add = (cls: string, detail: Record<string, unknown>) => claims.push({ id: `auto:${cls}:${n++}`, class: cls, source: "check", detail });

  if (input.origin) add("explore.cors", { url: input.origin });

  for (const ep of endpoints) {
    if (ep.graphql) add("explore.graphql", { url: ep.url });
    // Broken-auth / BOLA: anonymous read, and a cross-tenant read as A of B's object.
    if (has("b")) {
      add("explore.cross-actor", { url: ep.url, attacker: "anon", owner: "b" });
      if (has("a")) add("explore.cross-actor", { url: ep.url, attacker: "a", owner: "b" });
      // The owner's own ids (from its token) in an object route: B's own record, read by A.
      if (has("a") && ep.template?.includes(":id")) for (const id of (input.ownerIds ?? []).filter((v) => /^[\w-]{1,64}$/.test(v)).slice(0, 2)) {
        try { add("explore.cross-actor", { url: new URL(ep.template.replace(":id", encodeURIComponent(id)), ep.url).toString(), attacker: "a", owner: "b", id }); } catch { /* skip */ }
      }
    }
    // JWT signature bypass against any endpoint that may be protected (needs an account token).
    if (has("a")) add("explore.jwt-forge", { url: ep.url, as: "a" });
    // Injection on each discovered parameter (query).
    for (const p of (ep.params ?? []).slice(0, 8)) add("explore.injection", { url: ep.url, param: p, where: "query" });
    // A login route: the identifier of the usual JSON login body (SQL tautology or NoSQL operator bypass).
    let path = ""; try { path = new URL(ep.url).pathname; } catch { /* keep */ }
    if (LOGIN_PATH.test(path)) for (const id of ["email", "username"]) add("explore.injection", { url: ep.url, method: "POST", bodyTemplate: JSON.stringify({ [id]: "__INJECT__", password: "crenel-wrong-password" }) });
  }
  return claims;
}

export interface AutoProbeResult { proven: ClaimVerdict[]; tried: number }

/** Validate every auto-generated claim and keep the proven ones. The validators
 * enforce scope, controls and no-false-positive; this only drives them. */
export async function runAutoProbe(env: ValidatorEnv, input: { endpoints: Endpoint[]; origin?: string }, opts: { maxClaims?: number; idScan?: number } = {}): Promise<AutoProbeResult> {
  const accounts = (["a", "b", "c"] as const).filter((a) => actorToken(env.options, a));
  const claims = autoClaims({ endpoints: input.endpoints, accounts, origin: input.origin, ownerIds: tokenIdentity(actorToken(env.options, "b")) }).slice(0, opts.maxClaims ?? 120);
  // The owner's own objects behind each object route: small ids read as B, kept when the object's owner field holds
  // B's id from its token (ownerFieldValues), then claimed as A. Finds B's objects without knowing their ids.
  const bTok = actorToken(env.options, "b");
  const bIds = tokenIdentity(bTok);
  if (bIds.length && accounts.includes("a")) {
    for (const ep of input.endpoints.filter((e) => e.template?.includes(":id")).slice(0, 15)) {
      for (let i = 1; i <= (opts.idScan ?? 12); i++) {
        let url: string;
        try { url = new URL(ep.template!.replace(":id", String(i)), ep.url).toString(); } catch { break; }
        try {
          const r = await safeFetch(url, env.scope, { headers: { authorization: `Bearer ${bTok}` }, maxBytes: 256 * 1024 });
          if (r.status >= 200 && r.status < 300 && ownerFieldValues(r.body).some((v) => bIds.includes(v))) { claims.push({ id: `auto:own:${claims.length}`, class: "explore.cross-actor", source: "check", detail: { url, attacker: "a", owner: "b", id: String(i) } }); break; }
        } catch { break; }
      }
    }
  }
  // A GraphQL endpoint with introspection open: its own String arguments become injection claims.
  for (const ep of input.endpoints.filter((e) => e.graphql)) {
    try {
      const r = await safeFetch(ep.url, env.scope, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ query: GRAPHQL_SCHEMA_QUERY }), maxBytes: 2 * 1024 * 1024 });
      if (r.status >= 200 && r.status < 300) claims.push(...graphqlArgClaims(r.body, ep.url, { mutations: env.scope.allowActiveTesting, ssrf: true }));
    } catch { /* no schema: nothing to add */ }
  }
  const proven: ClaimVerdict[] = [];
  for (const c of claims) {
    try { const v = await validateClaim(c, env); if (v.state === "proven") proven.push(v); } catch { /* a probe that throws is not a proof */ }
  }
  return { proven, tried: claims.length };
}

/* GraphQL arguments from the API's own schema. When introspection is open (the
 * floor check proves that separately), every String argument of a root field is
 * a parameter like a query-string one: one injection claim each, with a template
 * that selects the field's scalar results so a differential shows. Mutations only
 * when active testing is on (they write). Generic: the names come from the
 * target's schema, the techniques from the validators. Pure. */
export const GRAPHQL_SCHEMA_QUERY = "query{__schema{queryType{name}mutationType{name}types{name kind fields{name type{kind name ofType{kind name ofType{kind name}}} args{name type{kind name ofType{kind name}}}}}}}";

interface GqlTypeRef { kind: string; name: string | null; ofType?: GqlTypeRef | null }
interface GqlField { name: string; type: GqlTypeRef; args?: { name: string; type: GqlTypeRef }[] }
interface GqlType { name: string; kind: string; fields?: GqlField[] | null }

const named = (t: GqlTypeRef | null | undefined): GqlTypeRef | null => (!t ? null : t.name ? t : named(t.ofType));

export function graphqlArgClaims(schemaBody: string, url: string, opts: { mutations: boolean; ssrf?: boolean; max?: number }): Claim[] {
  let s: { queryType?: { name: string } | null; mutationType?: { name: string } | null; types?: GqlType[] };
  try { s = (JSON.parse(schemaBody) as { data?: { __schema?: typeof s } }).data?.__schema ?? {}; } catch { return []; }
  const types = new Map((s.types ?? []).map((t) => [t.name, t]));
  const selection = (t: GqlTypeRef): string | null => {
    const n = named(t);
    if (!n) return null;
    if (n.kind === "SCALAR" || n.kind === "ENUM") return "";
    const fields = (types.get(n.name ?? "")?.fields ?? []).filter((f) => { const k = named(f.type)?.kind; return k === "SCALAR" || k === "ENUM"; }).slice(0, 8);
    return ` { __typename${fields.map((f) => ` ${f.name}`).join("")} }`;
  };
  const claims: Claim[] = [];
  const roots: [string | undefined, string][] = [[s.queryType?.name, "query"], ...(opts.mutations ? [[s.mutationType?.name, "mutation"] as [string | undefined, string]] : [])];
  for (const [root, op] of roots) {
    for (const f of (root ? types.get(root)?.fields : undefined) ?? []) {
      const sel = selection(f.type);
      if (sel === null) continue;
      // Out-of-band SSRF: an argument that takes a URL, or a host and a port taken apart (usual names, any API).
      const args = new Map((f.args ?? []).map((a) => [a.name.toLowerCase(), a]));
      const argStr = (n: string) => named(args.get(n)?.type)?.name;
      const urlArg = (f.args ?? []).find((a) => named(a.type)?.name === "String" && /^(url|uri|link|href|endpoint|callback|webhook|target|src|source|image_?url|avatar_?url|feed|remote)$/i.test(a.name));
      if (opts.ssrf && /^[_A-Za-z]\w*$/.test(f.name)) {
        if (urlArg) claims.push({ id: `auto:gql:${claims.length}`, class: "explore.ssrf", source: "check", detail: { url, gql: `${op} { ${f.name}(${urlArg.name}: "__CALLBACK_URL__")${sel} }` } });
        else if (argStr("host") === "String" && args.has("port")) {
          const parts = [`${args.get("host")!.name}: "__CALLBACK_HOST__"`, `${args.get("port")!.name}: ${argStr("port") === "String" ? '"__CALLBACK_PORT__"' : "__CALLBACK_PORT__"}`];
          if (argStr("path") === "String") parts.push(`${args.get("path")!.name}: "/__INJECT__"`);
          if (argStr("scheme") === "String") parts.push(`${args.get("scheme")!.name}: "http"`);
          claims.push({ id: `auto:gql:${claims.length}`, class: "explore.ssrf", source: "check", detail: { url, gql: `${op} { ${f.name}(${parts.join(", ")})${sel} }` } });
        }
      }
      for (const a of f.args ?? []) {
        if (named(a.type)?.name !== "String" || !/^[_A-Za-z]\w*$/.test(a.name) || !/^[_A-Za-z]\w*$/.test(f.name)) continue;
        claims.push({ id: `auto:gql:${claims.length}`, class: "explore.injection", source: "check", detail: { url, gql: `${op} { ${f.name}(${a.name}: "__INJECT__")${sel} }`, param: `${f.name}.${a.name}` } });
      }
    }
  }
  return claims.slice(0, opts.max ?? 40);
}
