// Pure helpers for console pages that tell the user what to do where the
// console itself cannot act (revoking a key at its provider, CI policy that
// lives in a GitHub workflow). Tested in console.test.tsx.

/** Where to revoke a leaked key, from its kind (finding title) or its masked value. */
export interface RevokeHelp { provider: string; url: string }

const PROVIDERS: { provider: string; url: string; re: RegExp }[] = [
  { provider: "Stripe", url: "https://dashboard.stripe.com/apikeys", re: /stripe|\b[sr]k_(live|test)_/i },
  { provider: "AWS", url: "https://console.aws.amazon.com/iam/home#/security_credentials", re: /\baws\b|\bAKIA/i },
  // Anthropic before OpenAI: sk-ant- also starts with sk-.
  { provider: "Anthropic", url: "https://platform.claude.com/settings/keys", re: /anthropic|\bsk-ant-/i },
  { provider: "OpenAI", url: "https://platform.openai.com/api-keys", re: /openai|\bsk-proj-/i },
  { provider: "Google Cloud", url: "https://console.cloud.google.com/apis/credentials", re: /google|\bAIza|\bGOCSPX-/i },
  { provider: "GitHub", url: "https://github.com/settings/tokens", re: /github|\bgh[pousr]_|\bgithub_pat_/i },
  { provider: "Slack", url: "https://api.slack.com/apps", re: /slack|\bxox[baprs]-/i },
];

export function revokeHelp(kind: string, masked = ""): RevokeHelp | null {
  for (const p of PROVIDERS) if (p.re.test(kind) || p.re.test(masked)) return { provider: p.provider, url: p.url };
  return null;
}

/** What breaks the build: the GitHub Action's `fail-on` (proven findings only; leads never fail). */
export interface CiPolicy { critical: boolean; high: boolean }

/** `fail-on` for a policy: high covers critical; null means the job never fails on a finding. */
export function failOnOf(p: CiPolicy): "high" | "critical" | null {
  return p.high ? "high" : p.critical ? "critical" : null;
}

// The reference the README and docs/INTEGRATIONS.md give: no release tag is
// published, so the workflow pins a commit (replace <sha>).
const ACTION = "GlamgarOnDiscord/crenel";

/** A GitHub Actions workflow running Crenel with the chosen `fail-on` (input names from action.yml). */
export function ciWorkflowYaml(p: CiPolicy, schedule = SCHEDULE_CRON): string {
  const failOn = failOnOf(p);
  return [
    "name: Crenel",
    "on:",
    "  pull_request:",
    "  push:",
    "    branches: [main]",
    ...(schedule ? ["  schedule:", `    - cron: "${schedule}"`] : []),
    "permissions:",
    "  contents: read",
    "  security-events: write",
    "jobs:",
    "  crenel:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    `      - uses: ${ACTION}@<sha> # remplacez <sha> par un commit de crenel`,
    ...(failOn ? [] : ["        # Aucune faille ne fait échouer le job, le SARIF reste publié.", "        continue-on-error: true"]),
    "        with:",
    "          config: crenel.config.yaml",
    `          fail-on: ${failOn ?? "critical"}`,
    "",
  ].join("\n");
}

export const SCHEDULE_CRON = "0 6 * * *";

/** The schedule block for a workflow: GitHub runs the scan, not crenel serve. */
export const SCHEDULE_YAML = `on:\n  schedule:\n    - cron: "${SCHEDULE_CRON}" # tous les jours à 6 h UTC\n`;
