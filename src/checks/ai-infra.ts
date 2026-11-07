// ai-infra: the AI services next to a SaaS, exposed without auth: model servers
// (Ollama, an OpenAI-compatible /v1/models, LiteLLM), vector databases (Qdrant,
// Chroma, Weaviate), agent builders (Flowise, Langflow). Open, they let anyone
// burn your GPU or API budget, read your embeddings (often private documents),
// or run agent flows. Inventory endpoints only, all GET, on the declared hosts
// (options.ai-infra.urls adds other bases such as http://ai.example.com:11434).

import type { Check, CheckContext, Finding, Severity } from "../core/types.js";
import { safeFetch } from "../core/net.js";

interface Probe { path: string; what: string; severity: Severity; prove: (j: unknown) => string | null }
const arr = (x: unknown, k: string): unknown[] | null => (x && typeof x === "object" && Array.isArray((x as Record<string, unknown>)[k]) ? (x as Record<string, unknown[]>)[k]! : null);

const PROBES: Probe[] = [
  { path: "/api/tags", what: "Ollama model server", severity: "high", prove: (j) => { const m = arr(j, "models"); return m ? `${m.length} model(s) listed` : null; } },
  { path: "/v1/models", what: "OpenAI-compatible model API (LiteLLM, vLLM, LocalAI…)", severity: "high", prove: (j) => { const d = arr(j, "data"); return d && (j as { object?: string }).object === "list" ? `${d.length} model(s) listed` : null; } },
  { path: "/collections", what: "Qdrant vector database", severity: "high", prove: (j) => { const r = (j as { result?: unknown }).result; const c = arr(r, "collections"); return c ? `${c.length} collection(s) listed` : null; } },
  { path: "/api/v2/tenants/default_tenant/databases/default_database/collections", what: "Chroma vector database", severity: "high", prove: (j) => (Array.isArray(j) ? `${j.length} collection(s) listed` : null) },
  { path: "/v1/schema", what: "Weaviate vector database", severity: "high", prove: (j) => { const c = arr(j, "classes"); return c ? `${c.length} class(es) in the schema` : null; } },
  { path: "/api/v1/chatflows", what: "Flowise agent builder", severity: "critical", prove: (j) => (Array.isArray(j) ? `${j.length} chatflow(s) listed` : null) },
  { path: "/api/v1/flows/", what: "Langflow agent builder", severity: "critical", prove: (j) => (Array.isArray(j) ? `${j.length} flow(s) listed` : null) },
];

export const aiInfra: Check = {
  name: "ai-infra",
  title: "Model servers, vector databases and agent builders open without auth",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const extra = ((ctx.options["ai-infra"] ?? {}) as { urls?: string[] }).urls ?? [];
    const bases = [...new Set([...(ctx.stagingUrl ? [ctx.stagingUrl] : []), ...extra].map((u) => u.replace(/\/+$/, "")))].filter((u) => ctx.scope.isHostAllowed(u));
    const out: Finding[] = [];
    for (const base of bases) {
      for (const p of PROBES) {
        let res;
        try { res = await safeFetch(base + p.path, ctx.scope, { headers: { accept: "application/json" } }); } catch { continue; }
        if (res.status !== 200) continue;
        let json: unknown;
        try { json = JSON.parse(res.body); } catch { continue; }
        const proof = p.prove(json);
        if (!proof) continue;
        out.push({
          id: `ai-infra:${base}${p.path}`, check: "ai-infra", title: `${p.what} open without auth at ${base}`, severity: p.severity, state: "proven",
          location: base + p.path,
          description: `${base}${p.path} answered an anonymous request with its inventory (${proof}). Anyone can use the service: run models on your hardware or API budget, read stored embeddings, or run agent flows.`,
          remediation: "Put the service behind authentication (API key, private network or an auth proxy) and never expose it on a public interface.",
          proof: { method: "anonymous GET of the service's inventory endpoint", replay: `curl -s '${base}${p.path}' | head -c 400`, evidence: `HTTP 200, ${proof} (names not kept)` },
          regressionHint: `${base}${p.path} must require credentials.`,
        });
      }
    }
    ctx.log(`ai-infra: ${bases.length} base(s), ${out.length} open service(s)`);
    return out;
  },
};
