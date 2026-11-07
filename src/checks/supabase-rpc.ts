// supabase-rpc: Postgres functions the client calls through PostgREST
// (`supabase.rpc("name")`), executed by the anonymous role. A function that
// returns other users' rows (a SECURITY DEFINER search, a stats helper that
// joins private tables) bypasses row-level security entirely, and RLS audits
// that only look at tables never see it.
//
// Live probe (same opt-ins as baas-exposure's table reads: allowActiveTesting
// AND the Supabase host in allowedHosts): GET /rest/v1/rpc/<name> with the
// bundle's public key only. PostgREST runs every GET and HEAD in a READ ONLY
// transaction whatever the function's volatility, so the call cannot modify
// the database: a function that tries answers 405 (SQLSTATE 25006), reported
// as undetermined, never proven. Negative control: the same GET without the key
// must be refused (401/403), so the data came through the anon role and not
// from an open proxy. Nothing of the response is kept but its shape. Functions
// whose name announces a side effect (send, delete, pay, http...) are never called.

import { readFileSync, statSync } from "node:fs";
import type { Check, CheckContext, Finding, Severity } from "../core/types.js";
import { walkFiles, extOf, relative } from "../core/walk.js";
import { safeFetch } from "../core/net.js";
import { scanBaas, type SupabasePair } from "./baas-exposure.js";

const CODE_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]);
const MAX_FUNCS = 20;
// Names that announce a side effect outside the database (an http extension call
// is not stopped by a read-only transaction): never called, even with GET.
const SIDE_EFFECT = /(delete|remove|reset|revoke|purge|drop|send|notify|email|mail|charge|pay|refund|invite|webhook|http)/i;
const SENSITIVE_COL = /(e-?mail|phone|password|passwd|pass_hash|token|secret|ssn|iban|card|address|birth|salary|api_?key|stripe|session)/i;

export interface RpcCall { name: string; withArgs: boolean; file: string; line: number }

/** `.rpc("name")` / `.rpc('name', { ... })` calls in client code. */
export function extractRpcCalls(content: string, file: string): RpcCall[] {
  const out: RpcCall[] = [];
  for (const m of content.matchAll(/\.rpc\(\s*["'`]([A-Za-z_][A-Za-z0-9_]{0,62})["'`]\s*(,)?/g)) {
    out.push({ name: m[1]!, withArgs: !!m[2], file, line: content.slice(0, m.index!).split("\n").length });
  }
  return out;
}

export function scanRpcCalls(projectDir: string): RpcCall[] {
  const byName = new Map<string, RpcCall>();
  for (const f of walkFiles(projectDir, { accept: (n) => CODE_EXT.has(extOf(n)) })) {
    let text = "";
    try { if (statSync(f).size > 8 * 1024 * 1024) continue; text = readFileSync(f, "utf8"); } catch { continue; }
    for (const c of extractRpcCalls(text, relative(projectDir, f))) if (!byName.has(c.name)) byName.set(c.name, c);
  }
  return [...byName.values()];
}

export type RpcOutcome =
  | { kind: "data"; rows: number; columns: string[]; scalar: boolean }
  | { kind: "empty" } | { kind: "refused" } | { kind: "writes" } | { kind: "needs-args" } | { kind: "other"; status: number };

/** Read PostgREST's answer to the anonymous GET. Only the shape survives. */
export function readRpcAnswer(status: number, body: string, truncated: boolean): RpcOutcome {
  if (status === 401 || status === 403) return { kind: "refused" };
  if (status === 405) return { kind: "writes" };
  if (status === 404 || status === 400) return { kind: "needs-args" };
  if (status < 200 || status >= 300) return { kind: "other", status };
  let data: unknown;
  try { data = JSON.parse(body); } catch { return truncated ? { kind: "data", rows: 1, columns: [], scalar: false } : { kind: "other", status }; }
  if (data === null || data === "" || (Array.isArray(data) && data.length === 0)) return { kind: "empty" };
  if (Array.isArray(data)) {
    const first = data[0];
    return { kind: "data", rows: data.length, columns: first && typeof first === "object" ? Object.keys(first) : [], scalar: !(first && typeof first === "object") };
  }
  if (typeof data === "object") return { kind: "data", rows: 1, columns: Object.keys(data as object), scalar: false };
  return { kind: "data", rows: 1, columns: [], scalar: true };
}

const headers = (key: string) => ({ apikey: key, authorization: `Bearer ${key}`, accept: "application/json" });

export const supabaseRpc: Check = {
  name: "supabase-rpc",
  title: "Supabase functions (rpc) that return data to anonymous visitors",
  readOnly: true, // static listing; live GETs gated like baas-exposure's reads
  async run(ctx: CheckContext): Promise<Finding[]> {
    const calls = scanRpcCalls(ctx.projectDir);
    if (!calls.length) return [];
    const pairs = [...new Map(scanBaas(ctx.projectDir).filter((h): h is SupabasePair => h.kind === "supabase").map((p) => [p.url, p])).values()];
    const out: Finding[] = [];
    for (const pair of pairs) {
      const host = new URL(pair.url).host;
      if (!(ctx.scope.allowActiveTesting && ctx.scope.isHostAllowed(pair.url))) {
        out.push({
          id: `supabase-rpc:${pair.url}`, check: "supabase-rpc", state: "unproven", severity: "low",
          title: `${calls.length} Supabase function(s) called from the client: check who may execute them (${host})`,
          location: `${calls[0]!.file}:${calls[0]!.line}`,
          description: `The client calls ${calls.slice(0, 10).map((c) => c.name).join(", ")} through PostgREST. A function runs with its owner's rights when it is SECURITY DEFINER, so RLS on the tables it reads does not apply.`,
          remediation: `Revoke EXECUTE from anon (and PUBLIC) on functions that are not meant for visitors; prefer SECURITY INVOKER. To prove it, add ${host} to allowedHosts and turn on allowActiveTesting: Crenel then calls each function once with GET (read-only transaction) and the public key.`,
          proof: { method: "rpc() calls found in the client code", replay: `grep -rn '\\.rpc(' "${calls[0]!.file}"` },
        });
        continue;
      }
      ctx.scope.assertActiveAllowed("supabase-rpc (live read)");
      for (const c of calls.slice(0, MAX_FUNCS)) {
        if (SIDE_EFFECT.test(c.name)) { ctx.log(`supabase-rpc: ${c.name} looks like a side effect, not called`); continue; }
        const url = `${pair.url}/rest/v1/rpc/${encodeURIComponent(c.name)}`;
        let res;
        try { res = await safeFetch(url, ctx.scope, { headers: headers(pair.key), maxBytes: 256 * 1024 }); } catch (err) { ctx.log(`supabase-rpc: ${c.name}: ${(err as Error).message}`); continue; }
        const a = readRpcAnswer(res.status, res.body, res.truncated);
        if (a.kind === "writes") {
          out.push({
            id: `supabase-rpc:${pair.url}:${c.name}`, check: "supabase-rpc", state: "unproven", severity: "medium",
            title: `Function ${c.name} writes and the public key reaches it (undetermined)`,
            location: url,
            description: `GET ${c.name} with the public key was refused with 405: PostgREST runs a GET in a read-only transaction and the function tried to modify the database. The anon role can execute it; whether a POST would let any visitor write was not tested (Crenel never sends it).`,
            remediation: `If ${c.name} is not meant for visitors, revoke EXECUTE from anon and PUBLIC; inside, check auth.uid() before writing.`,
            proof: { method: "anonymous GET answered 405 (read-only transaction refused a write)", replay: `curl -s '${url}' -H 'apikey: <ANON_KEY>'`, evidence: `HTTP 405` },
          });
          continue;
        }
        if (a.kind !== "data") { if (a.kind === "needs-args" && c.withArgs) ctx.log(`supabase-rpc: ${c.name} needs arguments, undetermined`); continue; }
        // Negative control: without the key the gateway must refuse.
        let control;
        try { control = await safeFetch(url, ctx.scope, { headers: { accept: "application/json" }, maxBytes: 4096 }); } catch { continue; }
        if (control.status !== 401 && control.status !== 403) { ctx.log(`supabase-rpc: ${c.name}: answered ${control.status} without a key too, not Supabase's gateway`); continue; }
        const sensitive = a.columns.filter((k) => SENSITIVE_COL.test(k));
        const severity: Severity = sensitive.length ? "critical" : a.scalar ? "low" : "medium";
        out.push({
          id: `supabase-rpc:${pair.url}:${c.name}`, check: "supabase-rpc", state: "proven", severity,
          title: `Function ${c.name} returns data to anyone holding the public key (${host})`,
          location: url,
          description: `With only the public key found in ${pair.file}:${pair.line}, GET /rest/v1/rpc/${c.name} returned ${a.scalar ? "a value" : `${a.rows} row(s), ${a.columns.length} field(s)`}${sensitive.length ? `, including likely sensitive ones (${sensitive.join(", ")})` : ""}; without the key it is refused. Any visitor can call it. The response was not kept. ${severity === "critical" ? "" : "It may be public by design (counts, public listings): confirm."}`.trim(),
          remediation: `Revoke EXECUTE on ${c.name} from anon and PUBLIC if visitors should not call it; make it SECURITY INVOKER so RLS applies, or check auth.uid() inside.`,
          proof: { method: "anonymous GET with the bundle's public key (read-only transaction), refused without the key (control); content not kept", replay: `curl -s '${url}' -H 'apikey: <ANON_KEY>' -H 'authorization: Bearer <ANON_KEY>'`, evidence: `HTTP ${res.status} with data; HTTP ${control.status} without the key` },
          regressionHint: `rpc ${c.name} must not return data with the anon key.`,
        });
      }
    }
    ctx.log(`supabase-rpc: ${calls.length} function(s) in the code, ${out.filter((f) => f.state === "proven").length} returning data anonymously`);
    return out;
  },
};
