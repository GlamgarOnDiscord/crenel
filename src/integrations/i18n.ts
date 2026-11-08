// Every human-readable string Crenel sends out (PR comment, Slack message,
// webhook summaries), in English and French. Keys and machine fields (event
// names, severities in JSON, finding ids) stay in English; only prose and
// labels are translated. A new language is one more entry in MESSAGES.
//
// options.integrations.locale: "auto" (default), "en" or "fr".
// "auto" has no documented per-user signal to read: GitHub exposes no
// language preference of a pull request's author or of a repository (the
// event payload and the REST user object carry none, and an Actions runner
// receives no Accept-Language). So "auto" reads, in order, CRENEL_LOCALE, then
// the locale of the process running Crenel (LC_ALL, LC_MESSAGES, LANG, then
// Intl), and falls back to English. On a CI runner that is the runner image's
// locale, not the author's: set locale explicitly there.

import type { Severity } from "../core/types.js";

export const LOCALES = ["en", "fr"] as const;
export type Locale = (typeof LOCALES)[number];
export type LocaleSetting = Locale | "auto";

export interface Messages {
  severity: Record<Severity, string>;
  plural(n: number, one: string, many: string): string;
  /** PR comment */
  prTitle(proven: number, project: string): string;
  prColumns: [string, string, string, string];
  prMore(n: number): string;
  prFooter(leads: number, codeScanningUrl?: string): string;
  prRunLink: string;
  /** Slack */
  slackText(n: number, bySeverity: string, project: string): string;
  slackHeader(n: number, project: string): string;
  slackFields: { severity: string; check: string; location: string };
  slackMore(n: number): string;
  slackContext(run?: string): string;
  slackTestText(project: string): string;
  slackTestBody(project: string): string;
  slackTestContext: string;
  /** Webhooks */
  hookFinding(severity: string, title: string, project: string): string;
  hookRun(proven: number, fresh: number, leads: number, project: string): string;
  hookTest(project: string): string;
}

const en: Messages = {
  severity: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
  plural: (n, one, many) => (n === 1 ? one : many),
  prTitle: (n, project) => (n ? `${n} proven ${n === 1 ? "finding" : "findings"} on ${project}` : `No proven finding on ${project}`),
  prColumns: ["Severity", "Check", "Finding", "Location"],
  prMore: (n) => `…and ${n} more.`,
  prFooter: (leads, url) => `Each proven finding has a replayable proof${url ? ` in [code scanning](${url})` : ""}. ${leads} ${leads === 1 ? "lead" : "leads"} not listed: a lead is not proven and never fails the build.`,
  prRunLink: "Workflow run",
  slackText: (n, by, project) => `Crenel: ${n} new proven ${n === 1 ? "finding" : "findings"} (${by}) on ${project}`,
  slackHeader: (n, project) => `${n} new proven ${n === 1 ? "finding" : "findings"}: ${project}`,
  slackFields: { severity: "Severity", check: "Check", location: "Location" },
  slackMore: (n) => `…and ${n} more in the Crenel console.`,
  slackContext: (run) => `Proven by Crenel with a replayable proof${run ? `, run ${run}` : ""}. Leads are never sent.`,
  slackTestText: (project) => `Crenel test message for ${project}`,
  slackTestBody: (project) => `*Crenel is connected* to this channel for ${project}.\nOnly new proven critical or high findings will be posted here.`,
  slackTestContext: "Test sent from Crenel.",
  hookFinding: (sev, title, project) => `New proven ${sev.toLowerCase()} finding on ${project}: ${title}`,
  hookRun: (proven, fresh, leads, project) => `Crenel run finished on ${project}: ${proven} proven (${fresh} new), ${leads} ${leads === 1 ? "lead" : "leads"}.`,
  hookTest: (project) => `Crenel test delivery for ${project}.`,
};

// French typography: a space before ":" and ";", "…" for an ellipsis.
const fr: Messages = {
  severity: { critical: "Critique", high: "Haute", medium: "Moyenne", low: "Basse", info: "Info" },
  plural: (n, one, many) => (n <= 1 ? one : many),
  prTitle: (n, project) => (n ? `${n} ${n === 1 ? "faille prouvée" : "failles prouvées"} sur ${project}` : `Aucune faille prouvée sur ${project}`),
  prColumns: ["Sévérité", "Contrôle", "Faille", "Emplacement"],
  prMore: (n) => `…et ${n} de plus.`,
  prFooter: (leads, url) => `Chaque faille prouvée a une preuve rejouable${url ? ` dans le [code scanning](${url})` : ""}. ${leads} ${leads <= 1 ? "piste non listée" : "pistes non listées"} : une piste n'est pas prouvée et ne casse jamais le build.`,
  prRunLink: "Exécution du workflow",
  slackText: (n, by, project) => `Crenel : ${n} ${n <= 1 ? "nouvelle faille prouvée" : "nouvelles failles prouvées"} (${by}) sur ${project}`,
  slackHeader: (n, project) => `${n} ${n <= 1 ? "nouvelle faille prouvée" : "nouvelles failles prouvées"} : ${project}`,
  slackFields: { severity: "Sévérité", check: "Contrôle", location: "Emplacement" },
  slackMore: (n) => `…et ${n} de plus dans la console Crenel.`,
  slackContext: (run) => `Prouvé par Crenel avec une preuve rejouable${run ? `, tâche ${run}` : ""}. Les pistes ne sont jamais envoyées.`,
  slackTestText: (project) => `Message de test Crenel pour ${project}`,
  slackTestBody: (project) => `*Crenel est connecté* à ce canal pour ${project}.\nSeules les nouvelles failles prouvées critiques ou hautes seront publiées ici.`,
  slackTestContext: "Test envoyé depuis Crenel.",
  hookFinding: (sev, title, project) => `Nouvelle faille prouvée (${sev.toLowerCase()}) sur ${project} : ${title}`,
  hookRun: (proven, fresh, leads, project) => `Tâche Crenel terminée sur ${project} : ${proven} ${proven <= 1 ? "prouvée" : "prouvées"} (${fresh} ${fresh <= 1 ? "nouvelle" : "nouvelles"}), ${leads} ${leads <= 1 ? "piste" : "pistes"}.`,
  hookTest: (project) => `Livraison de test Crenel pour ${project}.`,
};

const MESSAGES: Record<Locale, Messages> = { en, fr };

export const messages = (locale: Locale): Messages => MESSAGES[locale];

const isLocale = (s: string): s is Locale => (LOCALES as readonly string[]).includes(s);

/** "fr_FR.UTF-8", "fr-CA", "fr" -> "fr"; "C.UTF-8", "POSIX", unknown -> null. */
export function localeFromTag(tag: string | undefined): Locale | null {
  if (!tag) return null;
  const lang = tag.trim().toLowerCase().split(/[_.@-]/)[0] ?? "";
  return isLocale(lang) ? lang : null;
}

/** See the header: explicit setting, then CRENEL_LOCALE, then the process locale, then English. */
export function resolveLocale(setting: string | undefined, env: NodeJS.ProcessEnv = process.env, intl: () => string | undefined = () => Intl.DateTimeFormat().resolvedOptions().locale): Locale {
  if (setting && setting !== "auto") return localeFromTag(setting) ?? "en";
  const own = localeFromTag(env.CRENEL_LOCALE);
  if (own) return own;
  // POSIX precedence: the first of LC_ALL, LC_MESSAGES, LANG that is set wins,
  // even when it is "C" (which means English here).
  const posix = [env.LC_ALL, env.LC_MESSAGES, env.LANG].find((v) => v && v.trim());
  if (posix) return localeFromTag(posix) ?? "en";
  return localeFromTag(intl()) ?? "en";
}
