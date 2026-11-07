// business-logic: hypotheses, never proofs. The flaws that cost vibe-coded SaaS
// money (a price the browser decides, a plan or role the client sets, an invite
// or credits route nobody guards) need writes to prove, which Crenel never
// sends. What the client code shows is enough to point at them, so this check
// reads it offline and reports each shape as an `unproven` hypothesis, with a
// regression test written out for the team to run on staging (Crenel does not
// run it: it writes).
//
//   payment  a request to the app's own route whose body carries an amount,
//            unit_amount, total or price (not a Stripe price id): the server may
//            charge what the browser says;
//   privilege a request body, or a Supabase update/insert, that carries role,
//            plan, tier, credits, isAdmin...: the server or RLS may accept it;
//   routes   /api/admin, /api/invite(s), /api/credits... named in the client.
//
// Requests to third-party hosts (Stripe, PayPal...) are not the app's routes and
// are ignored; so are server files (api/, server/, route handlers), where a body
// with an amount is the server talking to the provider.

import { readFileSync, statSync } from "node:fs";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, extOf, relative } from "../core/walk.js";

const SCAN = new Set([".js", ".mjs", ".cjs", ".jsx", ".tsx", ".ts", ".vue", ".svelte"]);
const SERVER_FILE = /(^|\/)(api|server|functions|supabase\/functions)\/|(^|\/)route\.(t|j)s$|\.server\.(t|j)sx?$/;
const CALL = /\b(fetch|axios(?:\.(?:post|put|patch|request))?|\$\.(?:post|ajax)|ky\.(?:post|put|patch)|\w+\.(?:post|put|patch))\(\s*(["'`])([^"'`\n]{1,200})\2/g;
const PAY_KEY = /(?:[{,]\s*["']?(amount|unit_amount|unitAmount|total|totalPrice|total_price|price)["']?\s*:\s*(?!["'`]price_)[^\s,}]|[{,]\s*(amount|unit_amount|unitAmount|total|totalPrice|total_price)\s*[,}])/;
const PRIV_KEY = /(?:[{,]\s*["']?(role|plan|tier|credits|isAdmin|is_admin|isPro|is_pro|isPaid|is_paid|subscription_status|subscriptionStatus|permissions)["']?\s*:|[{,]\s*(role|plan|tier|credits|isAdmin|isPro|isPaid|permissions)\s*[,}])/;
const SB_WRITE = /\.from\(\s*["'`]([A-Za-z0-9_]{1,63})["'`]\s*\)\s*\.(update|insert|upsert)\(/g;
const SENSITIVE_ROUTE = /["'`](\/api\/(?:v\d+\/)?(?:admin|invites?|invitations?|credits|impersonate|internal|grant|promote)(?:[/?][^"'`\s]*)?)["'`]/g;

/** End of the call whose "(" is at `open`: naive depth count, strings skipped, capped. */
export function callExtent(src: string, open: number, cap = 2000): number {
  let depth = 0;
  for (let i = open; i < Math.min(src.length, open + cap); i++) {
    const ch = src[i]!;
    if (ch === '"' || ch === "'" || ch === "`") {
      for (i++; i < src.length && src[i] !== ch; i++) if (src[i] === "\\") i++;
      continue;
    }
    if (ch === "(") depth++;
    else if (ch === ")" && --depth === 0) return i + 1;
  }
  return Math.min(src.length, open + cap);
}

const isAppRoute = (url: string) => url.startsWith("/") && !url.startsWith("//") || /^\$\{[^}]+\}\/api\//.test(url) || /^https?:\/\/(localhost|127\.0\.0\.1)/.test(url);

export interface Hypothesis { kind: "payment" | "privilege" | "routes"; route: string; key: string; file: string; line: number }

export function findHypotheses(content: string, file: string): Hypothesis[] {
  const out: Hypothesis[] = [];
  const lineOf = (i: number) => content.slice(0, i).split("\n").length;
  for (const m of content.matchAll(CALL)) {
    const url = m[3]!;
    if (!isAppRoute(url)) continue;
    const open = m.index! + m[0].indexOf("(");
    const args = content.slice(open, callExtent(content, open));
    if (m[1] === "fetch" && !/\bbody\s*:/.test(args)) continue; // a GET fetch carries no body
    if (/(?:async\s*)?\(\s*(?:req|request|c|ctx)\s*[,)]|function\s*\(\s*req\b/.test(args)) continue; // a server route being declared (app.post("/x", (req, res) => …)), not a call
    const route = url.split("?")[0]!.replace(/\$\{[^}]+\}/g, ":id");
    const pay = args.match(PAY_KEY);
    if (pay) out.push({ kind: "payment", route, key: pay[1] ?? pay[2]!, file, line: lineOf(m.index!) });
    const priv = args.match(PRIV_KEY);
    if (priv) out.push({ kind: "privilege", route, key: priv[1] ?? priv[2]!, file, line: lineOf(m.index!) });
  }
  for (const m of content.matchAll(SB_WRITE)) {
    const open = m.index! + m[0].length - 1;
    const priv = content.slice(open, callExtent(content, open)).match(PRIV_KEY);
    if (priv) out.push({ kind: "privilege", route: `supabase table ${m[1]} (${m[2]})`, key: priv[1] ?? priv[2]!, file, line: lineOf(m.index!) });
  }
  for (const m of content.matchAll(SENSITIVE_ROUTE)) out.push({ kind: "routes", route: m[1]!.split("?")[0]!, key: "", file, line: lineOf(m.index!) });
  return out;
}

export const businessLogic: Check = {
  name: "business-logic",
  title: "Client code that may let the browser set a price, a plan or a role (hypotheses)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const all: Hypothesis[] = [];
    for (const f of walkFiles(ctx.projectDir, { accept: (n) => SCAN.has(extOf(n)) })) {
      const rel = relative(ctx.projectDir, f);
      if (SERVER_FILE.test(rel) || /\.test\.|\.spec\./.test(rel)) continue;
      try { if (statSync(f).size > 8 * 1024 * 1024) continue; all.push(...findHypotheses(readFileSync(f, "utf8"), rel)); } catch { continue; }
    }
    const seen = new Set<string>();
    const out: Finding[] = [];
    for (const h of all) {
      const k = `${h.kind}:${h.route}:${h.key}`;
      if (h.kind === "routes" || seen.has(k)) continue;
      seen.add(k);
      if (h.kind === "payment") out.push({
        id: `business-logic:payment:${h.route}:${h.key}`, check: "business-logic", state: "unproven", severity: "medium",
        title: `Hypothesis: the browser sends the ${h.key} to ${h.route}`,
        location: `${h.file}:${h.line}`,
        description: `The client posts a body with "${h.key}" to the app's own route ${h.route}. If the server charges, credits or records that value instead of computing it from its own catalogue, anyone can pay what they choose. Not tested: proving it needs a write.`,
        remediation: "Send only an item or Stripe price id from the browser; compute amounts on the server (or let Stripe Checkout do it) and grant access only from the verified webhook.",
        proof: { method: "static: request body built in the client code (hypothesis, not proof)", replay: `sed -n '${h.line},${h.line + 8}p' "${h.file}"` },
        regressionHint: `Write and run on staging (Crenel does not, it writes): as a signed-in test user, send the request to ${h.route} with ${h.key} set to 1; expect a 4xx, or a charge at the server's price, never at 1.`,
      });
      else out.push({
        id: `business-logic:privilege:${h.route}:${h.key}`, check: "business-logic", state: "unproven", severity: "medium",
        title: `Hypothesis: the client sets "${h.key}" through ${h.route}`,
        location: `${h.file}:${h.line}`,
        description: `A body sent from the browser carries "${h.key}". If the server (or a Supabase RLS policy that allows the update) takes it as is, a user can give themselves another plan, role or credits. Not tested: proving it needs a write.`,
        remediation: `Never accept ${h.key} from the client: set it on the server from your own records (a verified payment, an admin action). On Supabase, keep privilege columns out of user-writable tables or restrict them with column privileges.`,
        proof: { method: "static: privilege field in a client-sent body (hypothesis, not proof)", replay: `sed -n '${h.line},${h.line + 8}p' "${h.file}"` },
        regressionHint: `Write and run on staging (Crenel does not, it writes): as a signed-in free test user, send the same request with ${h.key} set to a higher value; expect a 4xx and the stored value unchanged.`,
      });
    }
    const routes = [...new Map(all.filter((h) => h.kind === "routes").map((h) => [h.route, h])).values()];
    if (routes.length) out.push({
      id: "business-logic:routes", check: "business-logic", state: "unproven", severity: "low",
      title: `Hypothesis: ${routes.length} admin, invite or credits route(s) named in the client code`,
      location: `${routes[0]!.file}:${routes[0]!.line}`,
      description: `The client code names ${routes.slice(0, 10).map((r) => r.route).join(", ")}. Each must check the caller's role on the server; a route the UI hides is still reachable by anyone who reads the bundle.`,
      remediation: "Check the role on the server in each handler (not only in the UI or middleware), and add these routes to the authorization matrix.",
      proof: { method: "static: route strings in the client code (hypothesis, not proof)", replay: `grep -rnE '/api/(admin|invite|credits)' "${routes[0]!.file}"` },
      regressionHint: `Write and run on staging: each of ${routes.slice(0, 5).map((r) => r.route).join(", ")} called with a normal account's token must answer 401 or 403 (GET routes can go in options.authz-matrix.resources).`,
    });
    ctx.log(`business-logic: ${out.length} hypothesis(es)`);
    return out;
  },
};
