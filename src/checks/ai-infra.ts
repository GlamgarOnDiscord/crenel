// ai-infra: the AI services next to a SaaS, exposed without auth: model servers
// (Ollama, an OpenAI-compatible /v1/models, LiteLLM), vector databases (Qdrant,
// Chroma, Weaviate), agent builders (Flowise, Langflow). Open, they let anyone
// burn your GPU or API budget, read your embeddings (often private documents),
// or run agent flows. Inventory endpoints only, GET except the MCP handshake
// and tools/list (POST, read-only by body), on the declared hosts
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

/**
 * An MCP server over SSE answers GET /sse with an `event: endpoint` frame that
 * hands out a session URL: no auth in front means anyone can list and call its
 * tools. Read only the first frame, then stop: the 32-byte cap ends the read on the first frame, the stream itself never ends.
 */
async function mcpOpen(base: string, ctx: CheckContext): Promise<string | null> {
  for (const path of ["/sse", "/mcp/sse"]) {
    try {
      const res = await safeFetch(base + path, ctx.scope, { headers: { accept: "text/event-stream" }, maxBytes: 32 });
      if (res.status === 200 && /event:\s*endpoint/.test(res.body)) return path;
    } catch { /* a stream cut by the cap still yields its first frame; errors mean no server */ }
  }
  return null;
}

const INIT = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "crenel", version: "0" } } });

/**
 * An MCP server over Streamable HTTP takes JSON-RPC by POST. An anonymous
 * `initialize` that comes back with the server's protocolVersion means no auth
 * in front; `tools/list` then counts what anyone could call. Both bodies are
 * handshake and list calls only (net.ts readOnlyPost refuses anything else).
 */
async function mcpHttpOpen(base: string, ctx: CheckContext): Promise<{ path: string; tools: number | null } | null> {
  const headers = { accept: "application/json, text/event-stream", "content-type": "application/json" };
  for (const path of ["/mcp", "/api/mcp"]) {
    let res;
    try { res = await safeFetch(base + path, ctx.scope, { method: "POST", headers, body: INIT, maxBytes: 16 * 1024 }); } catch { continue; }
    if (res.status !== 200 || !/"protocolVersion"\s*:/.test(res.body) || !/"jsonrpc"\s*:\s*"2\.0"/.test(res.body)) continue;
    const session = res.headers.get("mcp-session-id");
    let tools: number | null = null;
    try {
      const list = await safeFetch(base + path, ctx.scope, { method: "POST", headers: { ...headers, ...(session ? { "mcp-session-id": session } : {}) }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }), maxBytes: 256 * 1024 });
      const m = /"tools"\s*:\s*\[/.exec(list.body);
      if (list.status === 200 && m) tools = (list.body.slice(m.index).match(/"name"\s*:/g) ?? []).length;
    } catch { /* the handshake alone is the proof */ }
    return { path, tools };
  }
  return null;
}

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
    for (const base of bases) {
      const path = await mcpOpen(base, ctx);
      if (!path) continue;
      out.push({
        id: `ai-infra:${base}${path}`, check: "ai-infra", title: `MCP server open without auth at ${base}${path}`, severity: "critical", state: "proven",
        location: base + path,
        description: `${base}${path} opened an MCP session for an anonymous caller (event: endpoint). Anyone can list the server's tools and call them with its credentials.`,
        remediation: "Require OAuth or a bearer token on the MCP endpoint (the MCP authorization spec), or keep the server on a private network.",
        proof: { method: "anonymous GET of the SSE endpoint, first frame only", replay: `curl -sN -m 3 '${base}${path}' | head -3`, evidence: "HTTP 200, event: endpoint (session URL not kept)" },
        regressionHint: `${base}${path} must answer 401 without credentials.`,
      });
    }
    for (const base of bases) {
      const open = await mcpHttpOpen(base, ctx);
      if (!open) continue;
      const count = open.tools === null ? "" : `, ${open.tools} tool(s) listed`;
      out.push({
        id: `ai-infra:${base}${open.path}`, check: "ai-infra", title: `MCP server open without auth at ${base}${open.path}`, severity: "critical", state: "proven",
        location: base + open.path,
        description: `${base}${open.path} accepted an anonymous MCP initialize${count}. Anyone can call the server's tools with its credentials.`,
        remediation: "Require OAuth or a bearer token on the MCP endpoint (the MCP authorization spec), or keep the server on a private network.",
        proof: { method: "anonymous MCP initialize and tools/list over POST (handshake and list only)", replay: `curl -s -X POST -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' --data '${INIT}' '${base}${open.path}'`, evidence: `HTTP 200, protocolVersion returned${count} (tool names not kept)` },
        regressionHint: `${base}${open.path} must answer 401 without credentials.`,
      });
    }
    ctx.log(`ai-infra: ${bases.length} base(s), ${out.length} open service(s)`);
    return out;
  },
};
