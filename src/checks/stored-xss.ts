// stored-xss: markup stored through one endpoint is served UNESCAPED by another —
// persistent cross-site scripting, the most damaging XSS (it hits every later
// viewer, not just a crafted link). The deterministic sibling of the model-driven
// explore stored-XSS. The operator declares a store request (a body template with a
// {{XSS}} placeholder — a REST field or a GraphQL mutation) and a serve request; the
// check writes a unique marker wrapped in HTML, reads it back and asks the generic
// xssOracle whether the markup survived unescaped. A marker that comes back escaped
// is a lead (escaping held), never a proof — ~zero false positives.
//
// Active (it writes): gated by scope.allowActiveTesting AND options.stored-xss.enabled.
// The stored record carries a visible crenel marker so an operator can delete it.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { xssOracle, nonce } from "../agent/inject.js";

interface Req { path: string; method?: string; body?: string; contentType?: string }
interface StoredXssTarget {
  name: string;
  /** The write that stores attacker-controlled content. `body` is sent as-is after
   * {{XSS}} is replaced by the payload (a REST JSON body, or a GraphQL mutation). */
  store: Req;
  /** The read that renders the stored content back (a page, or a GraphQL query). */
  serve: Req;
  /** Which declared account authenticates the calls. Default none (anonymous). */
  as?: string;
}
interface Opts { enabled?: boolean; targets?: StoredXssTarget[] }

/** The requests one run sends, for the agent's active gate. */
export function plannedStoredXss(options: Record<string, unknown>, base: string): { method: string; url: string }[] {
  const o = (options["stored-xss"] ?? {}) as Opts;
  if (o.enabled !== true) return [];
  const u = (p: string) => base.replace(/\/+$/, "") + (p.startsWith("/") ? p : "/" + p);
  return (o.targets ?? []).flatMap((t) => [
    { method: (t.store.method ?? "POST").toUpperCase(), url: u(t.store.path) },
    { method: (t.serve.method ?? "GET").toUpperCase(), url: u(t.serve.path) },
  ]);
}

export const storedXss: Check = {
  name: "stored-xss",
  title: "Stored XSS: markup saved through one endpoint is served unescaped by another, active, staging only",
  readOnly: false,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["stored-xss"] ?? {}) as Opts;
    if (o.enabled !== true) return [];
    const targets = o.targets ?? [];
    if (!ctx.stagingUrl || targets.length === 0) { ctx.log("stored-xss: needs a stagingUrl and options.stored-xss.targets"); return []; }
    ctx.scope.assertActiveAllowed("stored-xss (writes a marker to staging)");
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const accounts = ((ctx.options["authz-matrix"] ?? {}) as { accounts?: Record<string, { token?: string }> }).accounts ?? {};
    const findings: Finding[] = [];
    const u = (p: string) => base + (p.startsWith("/") ? p : "/" + p);

    for (const t of targets) {
      if (!t.name || !t.store?.path || !t.serve?.path || t.store.body === undefined) {
        ctx.log(`stored-xss: ${t.name ?? "(unnamed)"}: needs name, store.path, store.body and serve.path`);
        continue;
      }
      const token = `crenel-${nonce()}`;
      const payload = `<svg/onload=1>${token}`;
      const auth: Record<string, string> = t.as && accounts[t.as]?.token ? { authorization: `Bearer ${accounts[t.as]!.token}` } : {};
      try {
        // Store: replace the placeholder with the payload and send the write.
        const storeUrl = u(t.store.path);
        if (!ctx.scope.isHostAllowed(storeUrl)) continue;
        const body = t.store.body.replace(/\{\{XSS\}\}/g, payload);
        const stored = await safeFetch(storeUrl, ctx.scope, {
          method: (t.store.method ?? "POST").toUpperCase(),
          headers: { "content-type": t.store.contentType ?? "application/json", ...auth },
          body,
        });
        if (stored.status >= 400) { ctx.log(`stored-xss: ${t.name}: store returned HTTP ${stored.status}`); continue; }
        // Serve: read it back and let the oracle decide if the markup survived unescaped.
        const serveUrl = u(t.serve.path);
        const served = await safeFetch(serveUrl, ctx.scope, {
          method: (t.serve.method ?? "GET").toUpperCase(),
          headers: { ...(t.serve.body !== undefined ? { "content-type": t.serve.contentType ?? "application/json" } : {}), ...auth },
          body: t.serve.body,
          maxBytes: 1024 * 1024,
        });
        const v = xssOracle({ token, body: served.body, status: served.status });
        if (v.verdict !== "proven") { ctx.log(`stored-xss: ${t.name}: ${v.reason}`); continue; }
        // Unescaped markup only runs in an HTML context. The same bytes inside a JSON
        // data response (e.g. a GraphQL API returning the stored string) are not
        // executable: that is a lead for the HTML view, never a proof here.
        const ctype = (served.headers.get("content-type") ?? "").toLowerCase();
        if (ctype.includes("application/json") || ctype.includes("text/json")) {
          ctx.log(`stored-xss: ${t.name}: marker served unescaped but in a JSON response (not an HTML context); lead only, declare the HTML view as serve`);
          continue;
        }
        findings.push({
          id: `stored-xss:${t.name}`,
          check: "stored-xss",
          title: `Stored XSS: ${t.store.path} content served unescaped at ${t.serve.path} (${t.name})`,
          severity: "high",
          state: "proven",
          location: serveUrl,
          description: `Markup written through ${t.store.method ?? "POST"} ${t.store.path} is served unescaped by ${t.serve.method ?? "GET"} ${t.serve.path} (${v.reason}). A stored, unescaped <svg/onload> runs in every later viewer's browser: session theft, account takeover, worming.`,
          remediation: `Escape stored content for the HTML context on output (or sanitize on input with an allow-list). A GraphQL field is not exempt — encode it wherever it is rendered as HTML.`,
          proof: {
            method: "live on staging: a unique markup marker was written through the store endpoint and came back unescaped from the serve endpoint",
            replay: `# the stored marker ${token} is served as raw <svg/onload=1>…; store then read:\ncurl -i -X ${(t.serve.method ?? "GET").toUpperCase()} ${JSON.stringify(serveUrl)}`,
            evidence: `store -> HTTP ${stored.status}; serve -> HTTP ${served.status}; ${v.reason}; marker ${token}`,
          },
          regressionHint: `After the fix, the marker stored at ${t.store.path} must appear HTML-escaped (or stripped) at ${t.serve.path}, never as raw <svg>.`,
        });
      } catch (err) {
        ctx.log(`stored-xss: ${t.name}: ${(err as Error).message}`);
      }
    }
    ctx.log(`stored-xss: ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};
