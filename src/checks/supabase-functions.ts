// supabase-functions: Supabase Edge Functions that act with the service-role key
// without checking who calls them. The service role bypasses every RLS policy.
// `verify_jwt` (on by default) only checks that the caller holds *a* valid JWT,
// and the public anon key is one, so it stops nobody who opened the site; with
// `verify_jwt = false` in supabase/config.toml not even that. Only a check in the
// code (auth.getUser / getClaims, a webhook signature, a shared secret) limits
// who can trigger the function.
//
// Offline and static, so leads only: supabase/functions/<name>/ files that read
// the service-role key (or an sb_secret_ key from the env) and contain none of
// those checks. A check done in a shared module imported from elsewhere is
// invisible here, hence never proven.

import { readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, extOf, relative } from "../core/walk.js";

const SERVICE_ROLE = /SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY|service_role/;
const CHECKS_CALLER = /auth\.getUser\s*\(|auth\.getClaims\s*\(|getUser\s*\(\s*(token|jwt|authHeader)|jwtVerify\s*\(|verifyJwt\w*\s*\(|constructEvent(Async)?\s*\(|webhooks\.(verify|unwrap)|new\s+Webhook\s*\(|timingSafeEqual|createHmac|crypto\.subtle\.verify|verify(Webhook|Signature)\w*\s*\(|headers\.get\(\s*["'](authorization|x-[\w-]*(secret|signature|token)[\w-]*)["']\s*\)[\s\S]{0,300}Deno\.env\.get\(\s*["'][A-Z0-9_]*(SECRET|TOKEN)["']/i;

/** verify_jwt per function from supabase/config.toml ([functions.<name>] verify_jwt = false). */
export function verifyJwtOff(toml: string): Set<string> {
  const off = new Set<string>();
  let current: string | null = null;
  for (const line of toml.split("\n")) {
    const sec = line.match(/^\s*\[functions\.["']?([\w-]+)["']?\]\s*$/);
    if (sec) { current = sec[1]!; continue; }
    if (/^\s*\[/.test(line)) { current = null; continue; }
    if (current && /^\s*verify_jwt\s*=\s*false\b/.test(line)) off.add(current);
  }
  return off;
}

export const supabaseFunctions: Check = {
  name: "supabase-functions",
  title: "Supabase Edge Functions using the service role without checking the caller",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const out: Finding[] = [];
    const roots = [...new Set([...walkFiles(ctx.projectDir, { accept: (_n, full) => /[\\/]supabase[\\/]functions[\\/][^\\/]+[\\/]/.test(full) && [".ts", ".js", ".tsx", ".mjs"].includes(extOf(_n)) })]
      .map((f) => f.replace(/([\\/]supabase[\\/]functions[\\/][^\\/]+)[\\/].*$/, "$1")))];
    for (const dir of roots) {
      const name = dir.split(/[\\/]/).pop()!;
      if (name.startsWith("_")) continue; // _shared and the like are modules, not functions
      const supabaseDir = dir.replace(/[\\/]functions[\\/][^\\/]+$/, "");
      const toml = join(supabaseDir, "config.toml");
      const off = existsSync(toml) ? verifyJwtOff(readFileSync(toml, "utf8")).has(name) : false;
      const files: { rel: string; text: string }[] = [];
      for (const f of walkFiles(dir, { accept: (n) => [".ts", ".js", ".tsx", ".mjs"].includes(extOf(n)) })) {
        try { if (statSync(f).size <= 2 * 1024 * 1024) files.push({ rel: relative(ctx.projectDir, f), text: readFileSync(f, "utf8") }); } catch { continue; }
      }
      const code = files.map((f) => f.text).join("\n");
      const file = (files.find((f) => SERVICE_ROLE.test(f.text)) ?? files[0])?.rel ?? relative(ctx.projectDir, dir);
      if (!SERVICE_ROLE.test(code) || CHECKS_CALLER.test(code)) continue;
      out.push({
        id: `supabase-functions:${name}`, check: "supabase-functions", state: "unproven", severity: "high",
        title: `Edge Function ${name} uses the service role and never checks the caller${off ? " (verify_jwt = false)" : ""}`,
        location: file,
        description: `${name} reads the service-role key, which bypasses every RLS policy, and its code has no auth.getUser, signature or shared-secret check. ${off ? "supabase/config.toml turns verify_jwt off, so anyone on the internet can call it." : "verify_jwt only requires a valid JWT, and the public anon key shipped in your bundle is one: anyone who opened the site can call it."} Lead: a check in a shared module is invisible here.`,
        remediation: "Read the caller with supabase.auth.getUser(token) and act only for that user (or use the caller's JWT instead of the service role so RLS applies). For webhooks and cron, verify the provider signature or a secret header before doing anything.",
        proof: { method: "static: service-role key read, no caller check in the function's files (lead)", replay: `grep -nE 'SERVICE_ROLE|getUser|verify' -r "${relative(ctx.projectDir, dir)}"` },
        regressionHint: `Calling ${name} with only the anon key (or no key) must answer 401 and do nothing.`,
      });
    }
    ctx.log(`supabase-functions: ${roots.length} function(s), ${out.length} without a caller check`);
    return out;
  },
};
