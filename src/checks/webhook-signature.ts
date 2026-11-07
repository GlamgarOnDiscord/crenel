// webhook-signature: a webhook handler that acts on the payload without
// verifying the sender's signature. Anyone who finds the URL can then POST a
// fake "checkout.session.completed" and get credits, a plan, or a refund. AI
// coding agents write this shape often: parse the JSON, switch on event.type.
// Deterministic and offline, file-level: a file that looks like a webhook
// handler, reads the request body, and contains no verification call at all.
// It stays a lead: a verification done in a shared middleware is invisible here.

import { readFileSync, statSync } from "node:fs";

import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, extOf, relative } from "../core/walk.js";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);
const SCAN = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

// What marks a file as a webhook handler, and which provider it is.
// Event names must appear as string literals ("user.created"), so a property
// like user.createdAt never marks a file as a webhook handler.
const q = (s: string) => new RegExp(String.raw`["'\`](?:${s})["'\`]`, "i");
const PROVIDERS: { name: string; re: RegExp }[] = [
  { name: "Stripe", re: q(String.raw`checkout\.session\.completed|invoice\.paid|customer\.subscription\.\w+|payment_intent\.succeeded|stripe-signature`) },
  { name: "GitHub", re: q(String.raw`x-github-event|x-hub-signature(?:-256)?`) },
  { name: "Clerk/Svix", re: q(String.raw`svix-(?:id|signature|timestamp)|user\.created|session\.created`) },
  { name: "Lemon Squeezy", re: q(String.raw`x-signature|order_created|subscription_created`) },
];
const READS_BODY = /\b(req|request)\.(json|text|body|arrayBuffer)\b|\bawait\s+\w+\.json\(\)/;
// Any of these means the author verified something: we do not second-guess it.
const VERIFIES = /constructEvent(Async)?\s*\(|webhooks\.(verify|unwrap)|new\s+Webhook\s*\(|\.verify\s*\(|verify(Webhook|Signature|Request)\w*\s*\(|timingSafeEqual|createHmac|validateRequest|verifyKey/;

const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;

export const webhookSignature: Check = {
  name: "webhook-signature",
  title: "Webhook handler that never verifies the sender's signature",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const accept = (name: string) => SCAN.has(extOf(name));
    for (const file of walkFiles(ctx.projectDir, { skipDirs: SKIP, accept })) {
      let text: string;
      try {
        if (statSync(file).size > 1024 * 1024) continue;
        text = readFileSync(file, "utf8");
      } catch { continue; }
      const rel = relative(ctx.projectDir, file) || file;
      const named = /webhook/i.test(rel);
      const provider = PROVIDERS.find((p) => p.re.test(text));
      if (!named && !provider) continue;
      if (!READS_BODY.test(text) || VERIFIES.test(text)) continue;
      const at = text.search(READS_BODY);
      const line = lineOf(text, at);
      const who = provider?.name ?? "the provider";
      findings.push({
        id: `webhook-signature:${rel}`,
        check: "webhook-signature",
        title: `Webhook handler without signature verification (${who}): ${rel}`,
        severity: "high",
        state: "unproven",
        location: `${rel}:${line}`,
        description: `${rel} reads the webhook payload and acts on it, but nothing in the file verifies ${who}'s signature. Anyone who knows the URL can send a forged event.`,
        remediation: provider?.name === "Stripe"
          ? "Read the raw body and call stripe.webhooks.constructEvent(body, signature, STRIPE_WEBHOOK_SECRET) before trusting anything; reject on failure."
          : `Verify ${who}'s signature on the raw body (an HMAC compared with timingSafeEqual, or the provider SDK) before acting; reject on failure.`,
        proof: { method: "webhook handler with no verification call in the file", replay: `grep -nE 'constructEvent|verify|timingSafeEqual|createHmac' "${rel}" || echo "no verification"` },
        regressionHint: `Test: POST a forged, unsigned event to the ${rel} route and expect 400/401, with no side effect.`,
      });
    }
    ctx.log(`webhook-signature: ${findings.length} finding(s)`);
    return findings;
  },
};
