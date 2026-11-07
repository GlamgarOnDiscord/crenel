// vercel-preview: preview deployments of a Vercel project, public when
// Deployment Protection is set to "Only Production" or off. Previews run the
// same code against staging data and often with debug flags, and their URLs
// leak in pull requests and chat. We GET each *.vercel.app host the config
// declares or the code references (and that is declared): an app page without
// the Vercel login wall is public.

import { readFileSync, statSync } from "node:fs";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { walkFiles, extOf } from "../core/walk.js";

const VERCEL_HOST = /\b[a-z0-9-]+(?:-[a-z0-9]+)*-[a-z0-9-]+\.vercel\.app\b/gi;
const LOGIN_WALL = /vercel\.com\/(?:login|sso-api)|_vercel_sso_nonce|Authentication Required|vercel-authentication/i;

export const vercelPreview: Check = {
  name: "vercel-preview",
  title: "Vercel preview deployments reachable without the Vercel login",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const hosts = new Set(ctx.scope.allowedHosts.filter((h) => h.endsWith(".vercel.app")));
    for (const file of walkFiles(ctx.projectDir, { accept: (n) => [".js", ".ts", ".tsx", ".json", ".md", ".env", ".html"].includes(extOf(n)) || n.startsWith(".env") })) {
      try { if (statSync(file).size > 2 * 1024 * 1024) continue; for (const m of readFileSync(file, "utf8").matchAll(VERCEL_HOST)) hosts.add(m[0].toLowerCase()); } catch { /* unreadable */ }
    }
    // The production alias is public on purpose: list it to leave it out.
    const production = new Set((((ctx.options["vercel-preview"] ?? {}) as { production?: string[] }).production ?? []).map((h) => h.toLowerCase()));
    const out: Finding[] = [];
    for (const host of hosts) {
      if (production.has(host)) continue;
      const url = `https://${host}/`;
      if (!ctx.scope.isHostAllowed(url)) {
        out.push({ id: `vercel-preview:referenced:${host}`, check: "vercel-preview", title: `Vercel deployment referenced in the code: ${host}`, severity: "info", state: "unproven", location: host,
          description: `The code mentions ${host}. If it is a preview, check that Deployment Protection covers previews.`, remediation: `Declare ${host} in scope.allowedHosts to let Crenel check whether it is public.`, proof: { method: "host found in the scanned code", replay: `grep -rn '${host}' .` } });
        continue;
      }
      let res;
      try { res = await safeFetch(url, ctx.scope, { followRedirects: false }); } catch { continue; }
      const walled = (res.status === 401 || res.status === 403 || (res.status >= 300 && res.status < 400)) && LOGIN_WALL.test(`${res.headers.get("location") ?? ""}${res.body}${res.headers.get("set-cookie") ?? ""}`);
      if (walled || res.status !== 200) continue;
      out.push({
        id: `vercel-preview:public:${host}`, check: "vercel-preview", title: `Vercel deployment ${host} is public`, severity: "medium", state: "proven", location: url,
        description: `${url} serves the app to an anonymous visitor, without the Vercel login wall. If this is a preview, it runs unreleased code against staging data, and its URL travels in pull requests.`,
        remediation: "In Vercel, set Deployment Protection to cover all deployments (Vercel Authentication on previews), or use a protection bypass token for automation.",
        proof: { method: "anonymous GET of the deployment, redirect not followed", replay: `curl -sI '${url}' | head -5`, evidence: `HTTP ${res.status}, no Vercel login wall` },
      });
    }
    ctx.log(`vercel-preview: ${hosts.size} Vercel host(s), ${out.filter((f) => f.state === "proven").length} public`);
    return out;
  },
};
