import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { webhookSignature } from "./webhook-signature.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

function ctx(projectDir: string): CheckContext {
  return { scope: new Scope({ allowedHosts: [] }), projectDir, options: {}, log: () => {} };
}
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crenel-webhook-"));
  for (const [n, b] of Object.entries(files)) writeFileSync(join(dir, n), b);
  return dir;
}

test("an unsigned Stripe handler is a high lead; a constructEvent one is not flagged", async () => {
  const dir = project({
    "stripe-webhook.ts": 'export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === "checkout.session.completed") grant();\n}\n',
    "stripe-webhook-safe.ts": 'export async function POST(req: Request) {\n  const body = await req.text();\n  const event = stripe.webhooks.constructEvent(body, sig, secret);\n  if (event.type === "checkout.session.completed") grant();\n}\n',
  });
  try {
    const found = await webhookSignature.run(ctx(dir));
    assert.equal(found.length, 1);
    assert.equal(found[0]!.location, "stripe-webhook.ts:2");
    assert.equal(found[0]!.state, "unproven");
    assert.equal(found[0]!.severity, "high");
    assert.match(found[0]!.title, /Stripe/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a GitHub handler verified with an HMAC and timingSafeEqual is not flagged", async () => {
  const dir = project({
    "gh.ts": 'app.post("/hook", (req, res) => {\n  const sig = req.headers["x-hub-signature-256"];\n  const mac = createHmac("sha256", secret).update(req.body).digest("hex");\n  if (!timingSafeEqual(Buffer.from(mac), Buffer.from(sig))) return res.sendStatus(401);\n});\n',
  });
  try { assert.equal((await webhookSignature.run(ctx(dir))).length, 0); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a property such as user.createdAt does not make a file a webhook handler", async () => {
  const dir = project({ "users.tsx": "export function Row({ user }) {\n  const d = await req.json();\n  return <td>{user.createdAt}</td>;\n}\n" });
  try { assert.equal((await webhookSignature.run(ctx(dir))).length, 0); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});
