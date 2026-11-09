// graphql-ssrf: find a server-side request forgery on a GraphQL API without being
// told the sink. The check introspects the schema and, for every field whose
// String arguments name a URL target (host/url/uri/endpoint/callback/webhook/…),
// makes the server reach an out-of-band listener the check controls — a full URL
// for a single `url`-style argument, or host/port/path/scheme for a structured
// sink (the nonce rides the path). It proves SSRF the industry-standard way: an
// ephemeral listener is hit with a unique nonce, so the server itself reached out.
// Generic (the sink comes from the live schema, the proof is the OOB hit); nothing
// is a finding until the listener is hit.
//
// Safety: active-only (gated by allowActiveTesting), and a field whose name reads
// as destructive (delete/remove/drop/…) is never fired — a URL-less side effect is
// not worth the SSRF probe. Every probe is awaited before the oracle runs, so no
// request outlives the check. The listener must be reachable from the target
// (operator config options.graphql-ssrf.callbackHost / callbackPort: the scanner
// host, or a sibling container's IP when the target is a container on a closed
// bridge).

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { startCallback, ssrfOracle } from "../agent/ssrf.js";
import { nonce } from "../agent/inject.js";

const named = (t: any): { kind: string; name: string } => { while (t && (t.kind === "LIST" || t.kind === "NON_NULL")) t = t.ofType; return { kind: t?.kind ?? "", name: t?.name ?? "" }; };
const isString = (a: any) => named(a.type).name === "String";
const isRequired = (a: any) => a?.type?.kind === "NON_NULL";
// Argument names that commonly carry a URL / host the server will fetch.
const URLARG = /^(url|uri|href|link|endpoint|callback|callback_?url|webhook|webhook_?url|fetch|src|source|image|image_?url|avatar|avatar_?url|proxy|target|host|hostname)$/i;
// Field names whose call could have a destructive side effect beyond the fetch:
// never fired, even to test SSRF.
const DESTRUCTIVE = /(delete|remove|drop|destroy|purge|wipe|erase|revoke|reset)/i;
const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

/** A benign literal for a required scalar argument, so the probe query validates.
 * Returns "" for an optional arg we choose to omit, or null when a REQUIRED arg
 * cannot be filled generically (enum/input object) — the field is then skipped. */
function benignArg(a: any): string | null {
  const n = named(a.type);
  if (n.name === "String" || n.name === "ID") return `${a.name}: "crenelx"`;
  if (n.name === "Int") return `${a.name}: 0`;
  if (n.name === "Float") return `${a.name}: 0.0`;
  if (n.name === "Boolean") return `${a.name}: false`;
  return isRequired(a) ? null : ""; // a required enum/input object we cannot fill => skip the field
}

interface Field { name: string; args: any[]; root: "query" | "mutation" }

export const graphqlSsrf: Check = {
  name: "graphql-ssrf",
  title: "Server-side request forgery on a schema-discovered GraphQL field",
  readOnly: false, // makes the server issue outbound requests: active gate
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["graphql-ssrf"] ?? {}) as { enabled?: boolean; endpoint?: string; callbackHost?: string; callbackPort?: number };
    if (o.enabled !== true || !ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    const url = base + (o.endpoint ?? "/graphql");
    if (!ctx.scope.isHostAllowed(url)) return [];
    ctx.scope.assertActiveAllowed("graphql-ssrf (triggers outbound requests)");
    const gql = async (query: string) => { try { const r = await safeFetch(url, ctx.scope, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ query }), maxBytes: 512 * 1024 }); return r.body; } catch { return ""; } };
    const schema = await gql(`{__schema{queryType{fields{name args{name type{kind name ofType{kind name ofType{kind name}}}}}} mutationType{fields{name args{name type{kind name ofType{kind name ofType{kind name}}}}}}}}`);
    let j: any; try { j = JSON.parse(schema); } catch { return []; }
    // A truncated introspection yields invalid JSON above; a valid-but-partial one
    // simply offers fewer fields — we work with what parsed, never guess a sink.
    const q: Field[] = (j?.data?.__schema?.queryType?.fields ?? []).map((f: any) => ({ ...f, root: "query" }));
    const m: Field[] = (j?.data?.__schema?.mutationType?.fields ?? []).map((f: any) => ({ ...f, root: "mutation" }));
    const sinks = [...q, ...m].filter((f) => !DESTRUCTIVE.test(f.name) && (f.args ?? []).some((a: any) => isString(a) && URLARG.test(a.name))).slice(0, 12);
    if (sinks.length === 0) { ctx.log("graphql-ssrf: no non-destructive URL-like string argument in the schema"); return []; }
    const host = o.callbackHost || "127.0.0.1";
    const findings: Finding[] = [];
    for (const f of sinks) {
      const cb = await startCallback(host, typeof o.callbackPort === "number" ? o.callbackPort : 0);
      try {
        const n = nonce("gqlssrf");
        const strArgs: any[] = (f.args ?? []).filter(isString);
        const hostArg = strArgs.find((a) => /^(host|hostname)$/i.test(a.name));
        const portArg = (f.args ?? []).find((a: any) => /^port$/i.test(a.name));
        const parts: string[] = [];
        let buildable = true;
        if (hostArg && portArg) {
          // structured sink: host / port / path / scheme; the nonce rides the path.
          for (const a of (f.args ?? [])) {
            const nm = a.name.toLowerCase();
            if (nm === "host" || nm === "hostname") parts.push(`${a.name}: "${host}"`);
            else if (nm === "port") parts.push(named(a.type).name === "String" ? `${a.name}: "${cb.port}"` : `${a.name}: ${cb.port}`);
            else if (nm === "path") parts.push(`${a.name}: "/${n}"`);
            else if (nm === "scheme" || nm === "protocol") parts.push(`${a.name}: "http"`);
            else { const b = benignArg(a); if (b === null) { buildable = false; break; } if (b) parts.push(b); }
          }
        } else {
          // single URL-ish arg: inject the whole callback URL, fill the rest benign.
          const urlArg = strArgs.find((a) => URLARG.test(a.name))!;
          for (const a of (f.args ?? [])) {
            if (a.name === urlArg.name) parts.push(`${a.name}: "${esc(cb.url(n))}"`);
            else { const b = benignArg(a); if (b === null) { buildable = false; break; } if (b) parts.push(b); }
          }
        }
        if (!buildable) { ctx.log(`graphql-ssrf: ${f.root} ${f.name} has a required arg we cannot fill generically, skipped`); continue; }
        const argStr = parts.join(", ");
        // The field may return a scalar (no selection) or an object (needs one);
        // __typename is valid on any object. Fire every shape, and AWAIT them all,
        // so no probe outlives the check before the oracle and the callback close.
        const op = f.root === "mutation" ? "mutation" : "query";
        const bodies = [`${op} { ${f.name}(${argStr}) }`, `${op} { ${f.name}(${argStr}) { __typename } }`];
        await Promise.all(bodies.map((b) => gql(b)));
        for (let i = 0; i < 48 && !cb.hits().includes(n); i++) await new Promise((r) => setTimeout(r, 250));
        const r = ssrfOracle({ nonce: n, hits: cb.hits() });
        if (r.verdict !== "proven") { ctx.log(`graphql-ssrf: ${f.root} ${f.name} no callback (host ${host}:${cb.port} reachable from the target?)`); continue; }
        findings.push({
          id: `graphql-ssrf:${f.root}:${f.name}`,
          check: "graphql-ssrf",
          title: `Server-side request forgery (SSRF) in GraphQL ${f.root} ${f.name}`,
          severity: "high",
          state: "proven",
          location: url,
          description: `The GraphQL ${f.root} field ${f.name} fetched an attacker-chosen URL: ${r.reason}. Discovered from the schema (URL-like argument), proven out-of-band. Internal services and cloud metadata are reachable.`,
          remediation: `Do not let a GraphQL argument choose the host of a server-side request; use an allowlist and block link-local / private ranges and redirects.`,
          proof: { method: "schema-discovered sink + out-of-band callback on staging (unique nonce in the request path)", replay: `POST ${url} with ${op} { ${f.name}(${argStr.replace(new RegExp(n, "g"), "<nonce>")}) } — the server calls back to the listener`, evidence: `out-of-band hit received for nonce ${n}` },
          regressionHint: `After deploy, a callback URL in ${f.name} must not produce an out-of-band request.`,
        });
      } finally { await cb.close(); }
    }
    return findings;
  },
};
