// dev-server: a development server (Vite, webpack-dev-server, Next.js dev) left
// reachable on a public host. It serves source files, hot-reload channels and
// often the whole filesystem around the project (Vite's /@fs/), and it has had
// its own CVEs. GETs on the declared host; the proof is the dev runtime itself
// (Vite's createHotContext, an HMR event stream), not a status code.

import { randomBytes } from "node:crypto";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

const PROBES: { path: string; what: string; signature: RegExp; headers?: Record<string, string> }[] = [
  { path: "/@vite/client", what: "Vite dev server", signature: /createHotContext|import\.meta\.hot|__vite__/ },
  { path: "/_next/webpack-hmr", what: "Next.js dev server (HMR channel)", signature: /^(data:|event:|:)/m, headers: { accept: "text/event-stream" } },
  { path: "/webpack-dev-server", what: "webpack-dev-server", signature: /webpack-dev-server|Webpack Dev Server/i },
  { path: "/sockjs-node/info", what: "webpack-dev-server (sockjs)", signature: /"websocket"\s*:\s*(true|false)/ },
];

export const devServer: Check = {
  name: "dev-server",
  title: "Development server reachable on the deployed host",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    let control = "";
    try { const c = await safeFetch(`${base}/crenel-${randomBytes(5).toString("hex")}.js`, ctx.scope); if (c.status === 200) control = c.body; } catch { /* host down */ }
    const out: Finding[] = [];
    for (const p of PROBES) {
      let res;
      try { res = await safeFetch(base + p.path, ctx.scope, { headers: p.headers, maxBytes: 64 * 1024 }); } catch { continue; }
      if (res.status !== 200 || (control && res.body === control) || !p.signature.test(res.body)) continue;
      out.push({
        id: `dev-server:${p.path}`, check: "dev-server", title: `${p.what} exposed on ${new URL(base).host}`, severity: "high", state: "proven",
        location: base + p.path,
        description: `${p.path} answers with the ${p.what} runtime. A dev server serves source files and, for Vite, files around the project through /@fs/; it is not built to face the internet.`,
        remediation: "Serve the production build (vite build / next build && next start), never the dev server, and bind dev servers to localhost.",
        proof: { method: "GET of the dev runtime path, runtime signature in the body, random path as control", replay: `curl -s '${base}${p.path}' | head -c 300`, evidence: `HTTP 200, ${p.what} signature` },
        regressionHint: `After deploy, ${p.path} must return 404.`,
      });
    }
    ctx.log(`dev-server: ${out.length} finding(s)`);
    return out;
  },
};
