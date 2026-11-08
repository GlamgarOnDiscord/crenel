// Integrations page data: GET /api/integrations from crenel serve, or a demo
// state when no server answers (the console's usual fallback). The server
// never returns a secret: only whether one is configured and where it comes
// from (env var or .crenel/secrets.json).

import { apiFetch } from "./api.ts";

export type SecretSource = "env" | "file" | null | `error: ${string}`;

export interface DeliveryRecord {
  at: string; integration: string; event: string; host: string; ok: boolean; status?: number; error?: string; ms?: number; run?: string;
}

export interface IntegrationsState {
  allowedHosts: string[];
  scanHosts: string[];
  slack: { enabled: boolean; minSeverity: "critical" | "high"; envVar: string; source: SecretSource; destination: string | null; configured: boolean };
  webhooks: { name: string; enabled: boolean; events: string[]; minSeverity: string; host: string; destination: string; envVar: string; source: SecretSource }[];
  secretsFile?: string;
  recent: DeliveryRecord[];
  /** Only on webhook creation: the signing secret, shown once. */
  secret?: string;
}

const t = (min: number) => new Date(Date.now() - min * 60_000).toISOString();

export const demoIntegrations: IntegrationsState = {
  allowedHosts: ["hooks.slack.com", "hooks.acme-app.com"],
  scanHosts: ["staging.acme-app.com"],
  slack: { enabled: true, minSeverity: "high", envVar: "CRENEL_SLACK_WEBHOOK_URL", source: "file", destination: "https://hooks.slack.com/…", configured: true },
  webhooks: [{ name: "ops", enabled: true, events: ["finding.proven", "run.completed"], minSeverity: "low", host: "hooks.acme-app.com", destination: "https://hooks.acme-app.com/…", envVar: "CRENEL_WEBHOOK_SECRET_OPS", source: "file" }],
  recent: [
    { at: t(12), integration: "slack", event: "finding.proven", host: "hooks.slack.com", ok: true, status: 200 },
    { at: t(12), integration: "webhook:ops", event: "finding.proven", host: "hooks.acme-app.com", ok: true, status: 204 },
    { at: t(12), integration: "webhook:ops", event: "run.completed", host: "hooks.acme-app.com", ok: true, status: 204 },
    { at: t(95), integration: "slack", event: "test", host: "hooks.slack.com", ok: false, status: 404, error: "no_service" },
  ],
};

export const getIntegrations = (signal?: AbortSignal) => apiFetch<IntegrationsState>("api/integrations", { signal });
export const saveSlack = (body: { webhookUrl?: string; enabled?: boolean; minSeverity?: "critical" | "high" }) => apiFetch<IntegrationsState>("api/integrations/slack", { method: "PUT", body });
export const removeSlack = () => apiFetch<IntegrationsState>("api/integrations/slack", { method: "DELETE" });
export const addWebhook = (body: { name: string; url: string }) => apiFetch<IntegrationsState>("api/integrations/webhooks", { method: "POST", body });
export const removeWebhook = (name: string) => apiFetch<IntegrationsState>(`api/integrations/webhooks/${encodeURIComponent(name)}`, { method: "DELETE" });
export const testIntegration = (target: "slack" | `webhook:${string}`) =>
  apiFetch<DeliveryRecord>(target === "slack" ? "api/integrations/slack/test" : `api/integrations/webhooks/${encodeURIComponent(target.slice(8))}/test`, { method: "POST", body: {} });

/** One line for a delivery, in the console's language. Host only, never a path. */
export function describeDelivery(r: DeliveryRecord): string {
  const what = r.event === "test" ? "test" : r.event === "run.completed" ? "fin de tâche" : "faille prouvée";
  const result = r.ok ? `envoyé${r.status ? ` (${r.status})` : ""}` : `non envoyé${r.status ? ` (${r.status})` : ""}${r.error ? `: ${r.error}` : ""}`;
  return `${what} vers ${r.host || "?"}, ${result}`;
}

/** Where a secret comes from, for the badge. */
export function sourceLabel(s: SecretSource): string {
  if (s === "env") return "variable d'environnement";
  if (s === "file") return ".crenel/secrets.json";
  if (s && s.startsWith("error:")) return s.slice(7);
  return "absent";
}
