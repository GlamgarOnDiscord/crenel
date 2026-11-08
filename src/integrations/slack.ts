// Slack Incoming Webhooks, with a Block Kit message.
//
// Follows https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/
//   - one JSON POST to the webhook URL, `text` plus `blocks`; `text` is the
//     notification fallback (mobile notifications only use it, per
//     https://docs.slack.dev/messaging/formatting-message-text/);
//   - success is HTTP 200 with the body "ok"; an error is a 4xx with a code
//     such as invalid_payload or no_service, journaled as is;
//   - the webhook URL contains a secret: it is never logged or journaled.
// Block Kit limits (https://docs.slack.dev/reference/block-kit/blocks/): at
// most 50 blocks, a header's plain_text at most 150 characters, a section's
// text at most 3000 and at most 10 fields of 2000 each. Incoming webhooks are
// limited to about one message per second
// (https://docs.slack.dev/apis/web-api/rate-limits/): Crenel sends one message
// per run, and on a 429 waits Retry-After once (at most 30 s) before giving up.
//
// What is sent: title, severity, check, location and the fix of each NEW
// PROVEN finding at or above the configured severity (critical or high).
// Never the proof's replay or evidence: they can carry a token.

import type { Finding, Severity } from "../core/types.js";
import { deliver, type DeliverOptions, type DeliveryResult } from "./deliver.js";

const MAX_FINDINGS = 10;
const SEV_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

/** Escape the three control characters of Slack's mrkdwn. */
export const escapeMrkdwn = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const clip = (s: string, n: number) => (s.length <= n ? s : s.slice(0, n - 1) + "…");

export interface SlackMessage { text: string; blocks: Record<string, unknown>[] }

export function slackFindingsMessage(findings: Finding[], ctx: { project: string; run?: string }): SlackMessage {
  const n = findings.length;
  const bySev = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((s) => [s, findings.filter((f) => f.severity === s).length] as const).filter(([, c]) => c > 0).map(([s, c]) => `${c} ${s}`).join(", ");
  const text = clip(`Crenel: ${n} new proven finding${n > 1 ? "s" : ""} (${bySev}) on ${ctx.project}`, 150);
  const blocks: Record<string, unknown>[] = [
    { type: "header", text: { type: "plain_text", text: clip(`${n} new proven finding${n > 1 ? "s" : ""}: ${ctx.project}`, 150), emoji: false } },
  ];
  for (const f of findings.slice(0, MAX_FINDINGS)) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: clip(`*${escapeMrkdwn(f.title)}*\n${escapeMrkdwn(f.remediation)}`, 3000) },
      fields: [
        { type: "mrkdwn", text: clip(`*Severity*\n${SEV_LABEL[f.severity]}`, 2000) },
        { type: "mrkdwn", text: clip(`*Check*\n\`${escapeMrkdwn(f.check)}\``, 2000) },
        { type: "mrkdwn", text: clip(`*Location*\n\`${escapeMrkdwn(f.location)}\``, 2000) },
      ],
    });
    blocks.push({ type: "divider" });
  }
  if (n > MAX_FINDINGS) blocks.push({ type: "section", text: { type: "mrkdwn", text: `…and ${n - MAX_FINDINGS} more in the Crenel console.` } });
  blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: clip(escapeMrkdwn(`Proven by Crenel with a replayable proof${ctx.run ? `, run ${ctx.run}` : ""}. Leads are never sent.`), 3000) }] });
  return { text, blocks };
}

export function slackTestMessage(project: string): SlackMessage {
  return {
    text: `Crenel test message for ${project}`,
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: `*Crenel is connected* to this channel for ${escapeMrkdwn(project)}.\nOnly new proven critical or high findings will be posted here.` } },
      { type: "context", elements: [{ type: "mrkdwn", text: "Test sent from the Crenel console." }] },
    ],
  };
}

/** POST a message; on a 429, wait Retry-After once (at most 30 s). */
export async function sendSlack(
  url: string, message: SlackMessage, base: Omit<DeliverOptions, "url" | "body" | "integration">,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
): Promise<DeliveryResult> {
  const opts = { ...base, integration: "slack", url, body: JSON.stringify(message), secrets: [...(base.secrets ?? []), url] };
  let res = await deliver(opts);
  if (res.record.status === 429) {
    const wait = Number(res.retryAfter ?? "1");
    if (Number.isFinite(wait) && wait >= 0 && wait <= 30) {
      await sleep(wait * 1000);
      res = await deliver(opts);
    }
  }
  // Slack answers 200 "ok" on success; anything else is a failure.
  if (res.record.ok && res.responseText !== undefined && res.responseText.trim() !== "ok") {
    res.record.ok = false;
    res.record.error = res.responseText.trim().slice(0, 120) || "unexpected response";
  }
  return res;
}

/** Slack's documented shape: https://hooks.slack.com/services/T…/B…/… */
export function isSlackWebhookUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "https:" && (u.hostname === "hooks.slack.com" || u.hostname === "hooks.slack-gov.com") && /^\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+$/.test(u.pathname);
  } catch { return false; }
}
