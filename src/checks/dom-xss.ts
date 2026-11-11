// dom-xss: a cross-site scripting that only fires in the browser — the markup is
// rendered client-side (a JS template writing `innerHTML`, a GraphQL paste shown by
// a front-end, a URL fragment reaching a DOM sink). A server-response check never
// sees it, because the server returns a JS shell and the payload executes only after
// the browser runs the page. So Crenel runs a real headless browser and watches the
// injected script EXECUTE (an alert carrying our nonce). The browser is OPTIONAL
// (Playwright, dynamically imported): without it the check reports nothing rather
// than guess — it never claims a DOM XSS it did not observe.
//
// Two shapes, both proven only on real execution:
//   - stored: write the payload through a declared endpoint, then load the view.
//   - reflected: load a URL that carries the payload (a {{XSS}} placeholder).
// Active WHEN it stores (writes): scope.allowActiveTesting AND options.dom-xss.enabled.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { proveDomXss } from "../agent/domxss.js";
import { nonce } from "../agent/inject.js";

interface Req { path: string; method?: string; body?: string; contentType?: string }
interface DomXssTarget {
  name: string;
  /** Optional write that stores the payload (REST field or GraphQL mutation); its
   * body has a {{XSS}} placeholder. Omit for a reflected DOM XSS. */
  store?: Req;
  /** The URL the browser loads. A {{XSS}} placeholder here is filled for a reflected
   * sink; for a stored one it is a plain view URL. */
  serve: string;
  /** The payload; {{NONCE}} is replaced by a unique value the browser must alert.
   * Default fires via an image error handler, which runs inside most sinks. */
  payload?: string;
  /** Which declared account authenticates a store write. */
  as?: string;
  /** Per-target browser timeout (ms). Default 15000. */
  timeoutMs?: number;
}
interface Opts { enabled?: boolean; targets?: DomXssTarget[] }

const DEFAULT_PAYLOAD = `<img src=x onerror="alert('{{NONCE}}')">`;

export const domXss: Check = {
  name: "dom-xss",
  // readOnly at the type level; a target that declares `store` writes and is gated below.
  readOnly: true,
  title: "DOM / stored XSS proven by script execution in a real browser",
  async run(ctx: CheckContext): Promise<Finding[]> {
    const o = (ctx.options["dom-xss"] ?? {}) as Opts;
    if (o.enabled !== true) return [];
    const targets = o.targets ?? [];
    if (!ctx.stagingUrl || targets.length === 0) { ctx.log("dom-xss: needs a stagingUrl and options.dom-xss.targets"); return []; }
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    ctx.scope.assertUrlAllowed(base);
    const writes = targets.some((t) => t.store);
    if (writes) ctx.scope.assertActiveAllowed("dom-xss (stores a payload on staging)");
    const accounts = ((ctx.options["authz-matrix"] ?? {}) as { accounts?: Record<string, { token?: string }> }).accounts ?? {};
    const u = (p: string) => (p.startsWith("http") ? p : base + (p.startsWith("/") ? p : "/" + p));
    const findings: Finding[] = [];
    let browserMissing = false;

    for (const t of targets) {
      if (!t.name || !t.serve) { ctx.log("dom-xss: a target needs name and serve"); continue; }
      const mark = `crenel${nonce()}`.replace(/[^a-zA-Z0-9]/g, "").slice(0, 20);
      const payload = (t.payload ?? DEFAULT_PAYLOAD).replace(/\{\{NONCE\}\}/g, mark);
      const auth: Record<string, string> = t.as && accounts[t.as]?.token ? { authorization: `Bearer ${accounts[t.as]!.token}` } : {};
      try {
        if (t.store) {
          const storeUrl = u(t.store.path);
          if (!ctx.scope.isHostAllowed(storeUrl)) continue;
          const body = (t.store.body ?? "").replace(/\{\{XSS\}\}/g, payload);
          const w = await safeFetch(storeUrl, ctx.scope, { method: (t.store.method ?? "POST").toUpperCase(), headers: { "content-type": t.store.contentType ?? "application/json", ...auth }, body });
          if (w.status >= 400) { ctx.log(`dom-xss: ${t.name}: store returned HTTP ${w.status}`); continue; }
        }
        const serveUrl = u(t.serve.replace(/\{\{XSS\}\}/g, encodeURIComponent(payload)));
        if (!ctx.scope.isHostAllowed(serveUrl)) continue;
        const r = await proveDomXss(serveUrl, mark, { timeoutMs: t.timeoutMs ?? 15000, allowHost: (x) => ctx.scope.isHostAllowed(x) });
        if (!r.available) { browserMissing = true; ctx.log(`dom-xss: ${t.name}: ${r.reason}`); continue; }
        if (!r.executed) { ctx.log(`dom-xss: ${t.name}: loaded in a browser, the payload did not execute (${r.reason})`); continue; }
        findings.push({
          id: `dom-xss:${t.name}`,
          check: "dom-xss",
          title: `${t.store ? "Stored" : "DOM"} XSS executes in the browser at ${t.serve} (${t.name})`,
          severity: "high",
          state: "proven",
          location: serveUrl,
          description: `A script Crenel injected${t.store ? ` through ${t.store.method ?? "POST"} ${t.store.path}` : " via the URL"} executed in a real headless browser when ${t.serve} was loaded (${r.reason}). The markup reaches a DOM sink unescaped and runs as script in every viewer's session: credential theft, account takeover.`,
          remediation: `Escape or sanitize the value where the front-end writes it into the DOM; prefer textContent over innerHTML, and sanitize stored content on output. A server-side JSON API returning the value is not enough — the browser sink is the bug.`,
          proof: {
            method: "live: a unique payload was " + (t.store ? "stored, " : "") + "loaded in headless chromium, and its alert fired carrying our nonce",
            replay: (t.store ? `# store the payload, then open ${t.serve} in a browser:\n` : `# open in a browser:\n`) + `# payload: ${payload.replace(mark, "<nonce>")}\n# view: ${serveUrl.replace(mark, "<nonce>")}`,
            evidence: `headless chromium: the injected script executed (${r.reason})`,
          },
          regressionHint: `After the fix, loading ${t.serve} with the stored/injected payload must not execute script in a browser.`,
        });
      } catch (err) {
        ctx.log(`dom-xss: ${t.name}: ${(err as Error).message}`);
      }
    }
    if (browserMissing && findings.length === 0) ctx.log("dom-xss: no browser available (install Playwright or set CRENEL_PLAYWRIGHT); DOM XSS cannot be proven without one");
    ctx.log(`dom-xss: ${findings.filter((f) => f.state === "proven").length} proven`);
    return findings;
  },
};
