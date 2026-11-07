// auth-config: what the auth layer tells anyone about itself. Supabase's
// /auth/v1/settings (public key only) says whether sign-ups are open and email
// confirmation is off (anyone can create an account and use it at once, which
// matters when "any signed-in user" is your only check). Better Auth's OpenAPI
// plugin, left on, publishes every auth route. GETs only, declared hosts.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";
import { scanBaas, type SupabasePair } from "./baas-exposure.js";

export const authConfig: Check = {
  name: "auth-config",
  title: "Auth settings readable by anyone: open sign-up without email confirmation, published auth API",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const out: Finding[] = [];
    for (const pair of scanBaas(ctx.projectDir).filter((h): h is SupabasePair => h.kind === "supabase")) {
      const url = `${pair.url}/auth/v1/settings`;
      if (!ctx.scope.isHostAllowed(url)) continue;
      try {
        const res = await safeFetch(url, ctx.scope, { headers: { apikey: pair.key } });
        if (res.status !== 200) continue;
        const s = JSON.parse(res.body) as { disable_signup?: boolean; mailer_autoconfirm?: boolean; phone_autoconfirm?: boolean };
        if (s.disable_signup === false && (s.mailer_autoconfirm || s.phone_autoconfirm)) {
          out.push({
            id: `auth-config:supabase-autoconfirm:${pair.url}`, check: "auth-config", title: `Supabase sign-up is open and accounts are confirmed without email (${new URL(pair.url).host})`,
            severity: "medium", state: "proven", location: url,
            description: "Anyone can create an account with any email address and use it immediately. Every RLS policy that only checks auth.role() = 'authenticated' is then open to the whole internet.",
            remediation: "Turn on email confirmation (or close sign-ups), and write RLS policies on ownership (auth.uid() = owner_id), not on being signed in.",
            proof: { method: "GET of the public auth settings with the bundle's public key", replay: `curl -s '${url}' -H 'apikey: <ANON_KEY>'`, evidence: `disable_signup=false, mailer_autoconfirm=${s.mailer_autoconfirm}, phone_autoconfirm=${s.phone_autoconfirm}` },
          });
        }
      } catch (err) { ctx.log(`auth-config: ${url}: ${(err as Error).message}`); }
    }
    if (ctx.stagingUrl && ctx.scope.isHostAllowed(ctx.stagingUrl)) {
      const base = ctx.stagingUrl.replace(/\/+$/, "");
      for (const path of ["/api/auth/reference", "/api/auth/open-api/generate-schema"]) {
        try {
          const res = await safeFetch(base + path, ctx.scope);
          if (res.status !== 200 || !/better-auth|"openapi"\s*:\s*"3|scalar/i.test(res.body)) continue;
          out.push({
            id: `auth-config:better-auth-openapi:${path}`, check: "auth-config", title: `Better Auth OpenAPI reference published at ${path}`, severity: "low", state: "proven", location: base + path,
            description: "The Better Auth OpenAPI plugin is on in this environment: every auth route, admin plugin endpoints included, is documented for anyone.",
            remediation: "Enable the openAPI plugin only in development.",
            proof: { method: "anonymous GET", replay: `curl -s '${base}${path}' | head -c 300`, evidence: "HTTP 200, OpenAPI reference" },
          });
          break;
        } catch { /* not there */ }
      }
    }
    ctx.log(`auth-config: ${out.length} finding(s)`);
    return out;
  },
};
