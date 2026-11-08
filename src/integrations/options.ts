// options.integrations: where Crenel may send its own notifications.
//
// These are destinations the user declares, never scan targets. They live in
// their own allowlist (options.integrations.allowedHosts), apart from
// scope.allowedHosts: a host listed in the scan scope is refused as a
// destination, and a destination is never probed by a check. Secrets (the
// Slack webhook URL, each webhook's signing secret) are never in this file:
// they come from an environment variable or from .crenel/secrets.json (0600).

import { z } from "zod";
import type { Config } from "../core/config.js";
import { LOCALES } from "./i18n.js";

const Host = z.string().trim().toLowerCase().min(1).regex(/^[a-z0-9.-]+$|^\[[0-9a-f:.]+\]$/, "a hostname, without scheme or path");
const Name = z.string().regex(/^[a-z0-9][a-z0-9-]{0,39}$/, "lowercase letters, digits and dashes (max 40)");

export const WEBHOOK_EVENTS = ["finding.proven", "run.completed"] as const;
export type WebhookEvent = (typeof WEBHOOK_EVENTS)[number] | "test";

export const IntegrationsOptions = z.object({
  /** Language of the PR comment, Slack messages and webhook summaries (see i18n.ts for "auto"). */
  locale: z.enum(["auto", ...LOCALES]).default("auto"),
  github: z.object({
    /**
     * Logo shown in the PR comment's header. Only an https URL anyone can
     * fetch: GitHub's image proxy cannot read a private repository's raw file.
     */
    logoUrl: z.string().url().refine((u) => u.startsWith("https://"), "https only").optional(),
  }).strict().optional(),
  /** Destination hosts Crenel may POST notifications to. Never scanned. */
  allowedHosts: z.array(Host).default([]),
  slack: z.object({
    enabled: z.boolean().default(false),
    /** Only proven findings at or above this severity are sent: critical or high. */
    minSeverity: z.enum(["critical", "high"]).default("high"),
    /** Environment variable holding the Incoming Webhook URL (wins over .crenel/secrets.json). */
    webhookUrlEnv: z.string().regex(/^[A-Z_][A-Z0-9_]*$/).default("CRENEL_SLACK_WEBHOOK_URL"),
  }).strict().optional(),
  webhooks: z.array(z.object({
    name: Name,
    url: z.string().url(),
    enabled: z.boolean().default(true),
    events: z.array(z.enum(WEBHOOK_EVENTS)).min(1).default(["finding.proven", "run.completed"]),
    minSeverity: z.enum(["critical", "high", "medium", "low", "info"]).default("low"),
    /** Environment variable holding the signing secret (wins over .crenel/secrets.json). */
    secretEnv: z.string().regex(/^[A-Z_][A-Z0-9_]*$/).optional(),
  }).strict()).default([]),
}).strict();

export type IntegrationsOptions = z.infer<typeof IntegrationsOptions>;
export type WebhookOptions = IntegrationsOptions["webhooks"][number];

export function integrationsOptions(config: Config): IntegrationsOptions {
  const r = IntegrationsOptions.safeParse(config.options.integrations ?? {});
  if (!r.success) throw new Error(`options.integrations: ${r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")}`);
  return r.data;
}

/** Default env var for a webhook's secret: CRENEL_WEBHOOK_SECRET_<NAME>. */
export const webhookSecretEnv = (w: Pick<WebhookOptions, "name" | "secretEnv">) =>
  w.secretEnv ?? `CRENEL_WEBHOOK_SECRET_${w.name.toUpperCase().replace(/-/g, "_")}`;

/** Key of a secret in .crenel/secrets.json. */
export const secretKey = { slack: "slack.webhookUrl", webhook: (name: string) => `webhooks.${name}.secret` } as const;
