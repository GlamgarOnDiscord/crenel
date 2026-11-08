// Generic webhooks: a JSON POST per new proven finding and per finished run,
// signed with HMAC-SHA256 so the receiver can check it came from Crenel and
// was not replayed.
//
//   X-Crenel-Event:      finding.proven | run.completed | test
//   X-Crenel-Delivery:   a random id, unique per delivery
//   X-Crenel-Timestamp:  Unix seconds when the delivery was signed
//   X-Crenel-Signature:  sha256=<hex HMAC-SHA256(secret, "v1:" + timestamp + ":" + raw body)>
//
// The scheme follows the two official references it is modelled on:
//   - GitHub, "Validating webhook deliveries": a `sha256=` prefixed hex HMAC of
//     the payload, a high-entropy secret, a constant-time comparison
//     (https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries);
//   - Slack, "Verifying requests from Slack": the timestamp is part of the
//     signed string (`v0:timestamp:body` there) and a request older than five
//     minutes is rejected, which stops a replay
//     (https://docs.slack.dev/authentication/verifying-requests-from-slack).
// `verifyCrenelSignature` is the reference verification, used by the tests and
// shown in docs/INTEGRATIONS.md.

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { Finding } from "../core/types.js";
import { deliver, type DeliverOptions, type DeliveryResult } from "./deliver.js";
import type { WebhookEvent } from "./options.js";

export const SIGNATURE_TOLERANCE_S = 300;
export const MIN_SECRET_LENGTH = 32;

export const newWebhookSecret = () => randomBytes(32).toString("base64url");

export function signCrenel(secret: string, timestamp: number, body: string): string {
  return "sha256=" + createHmac("sha256", secret).update(`v1:${timestamp}:${body}`).digest("hex");
}

/** Reference verification for receivers. `headers` keys are lowercase (as in Node). */
export function verifyCrenelSignature(secret: string, headers: Record<string, string | string[] | undefined>, rawBody: string, nowS = Math.floor(Date.now() / 1000)): boolean {
  const one = (k: string) => { const v = headers[k]; return Array.isArray(v) ? v[0] : v; };
  const ts = Number(one("x-crenel-timestamp"));
  const sig = one("x-crenel-signature") ?? "";
  if (!Number.isInteger(ts) || Math.abs(nowS - ts) > SIGNATURE_TOLERANCE_S) return false;
  const expected = Buffer.from(signCrenel(secret, ts, rawBody));
  const given = Buffer.from(sig);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

/** The finding as a receiver sees it. The proof's replay and evidence stay local: they can carry a token. */
export function findingPayload(f: Finding & { firstSeen?: string; uid?: string }) {
  return {
    id: f.id, check: f.check, title: f.title, severity: f.severity, state: f.state, location: f.location,
    description: f.description, remediation: f.remediation,
    ...(f.proof ? { proofMethod: f.proof.method } : {}),
    ...(f.firstSeen ? { firstSeen: f.firstSeen } : {}),
  };
}

export interface WebhookContext { project: string; run?: string }

export function webhookBody(event: WebhookEvent, ctx: WebhookContext, data: Record<string, unknown>, delivery: string): string {
  return JSON.stringify({ event, delivery, sentAt: new Date().toISOString(), project: ctx.project, ...(ctx.run ? { run: ctx.run } : {}), ...data });
}

export async function sendWebhook(
  hook: { name: string; url: string }, secret: string, event: WebhookEvent, ctx: WebhookContext, data: Record<string, unknown>,
  base: Omit<DeliverOptions, "url" | "body" | "integration" | "event" | "headers">, nowS = Math.floor(Date.now() / 1000),
): Promise<DeliveryResult> {
  const delivery = randomUUID();
  const body = webhookBody(event, ctx, data, delivery);
  return deliver({
    ...base, integration: `webhook:${hook.name}`, event, url: hook.url, body, secrets: [...(base.secrets ?? []), secret],
    headers: {
      "x-crenel-event": event, "x-crenel-delivery": delivery, "x-crenel-timestamp": String(nowS),
      "x-crenel-signature": signCrenel(secret, nowS, body),
    },
  });
}
