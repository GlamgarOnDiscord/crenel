// exposed-secrets: scan a built frontend bundle (or any directory) for secrets
// that should never ship to the browser. This is read-only and deterministic,
// which is exactly the kind of check that research says LLMs should NOT replace:
// a regex on known key shapes has near-zero false positives and no token cost.
//
// The classic SaaS mistake this catches: a server-side key (Stripe secret,
// service-role JWT, private API key) pulled into client code and bundled into
// dist/, where anyone can read it with view-source.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";

interface SecretPattern {
  id: string;
  title: string;
  regex: RegExp;
  severity: Finding["severity"];
  /** False for test-mode keys that are safe to expose; keeps messaging honest. */
  sensitive?: boolean;
}

// Patterns are intentionally specific. We match distinctive prefixes rather than
// generic "looks like a token", to keep false positives near zero. Stripe test
// keys (sk_test_/rk_test_) are published by design, so they are a low-severity
// note, not a critical "assume compromised" finding.
const PATTERNS: SecretPattern[] = [
  { id: "stripe-secret", title: "Stripe secret key (live)", regex: /\bsk_live_[A-Za-z0-9]{16,}/g, severity: "critical", sensitive: true },
  { id: "stripe-secret-test", title: "Stripe test secret key", regex: /\bsk_test_[A-Za-z0-9]{16,}/g, severity: "low", sensitive: false },
  { id: "stripe-restricted", title: "Stripe restricted key (live)", regex: /\brk_live_[A-Za-z0-9]{16,}/g, severity: "high", sensitive: true },
  { id: "stripe-restricted-test", title: "Stripe restricted test key", regex: /\brk_test_[A-Za-z0-9]{16,}/g, severity: "low", sensitive: false },
  { id: "aws-access-key", title: "AWS access key id", regex: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high", sensitive: true },
  { id: "google-api-key", title: "Google API key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g, severity: "high", sensitive: true },
  { id: "openai-project-key", title: "OpenAI project API key", regex: /\bsk-proj-[A-Za-z0-9_-]{32,}/g, severity: "high", sensitive: true },
  { id: "openai-key", title: "OpenAI API key", regex: /\bsk-[A-Za-z0-9]{32,}\b/g, severity: "high", sensitive: true },
  { id: "anthropic-key", title: "Anthropic API key", regex: /\bsk-ant-[A-Za-z0-9\-_]{20,}/g, severity: "high", sensitive: true },
  { id: "github-pat", title: "GitHub personal access token", regex: /\bghp_[A-Za-z0-9]{36}\b/g, severity: "high", sensitive: true },
  { id: "github-fine-grained-pat", title: "GitHub fine-grained token", regex: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g, severity: "high", sensitive: true },
  { id: "github-oauth", title: "GitHub OAuth/app token", regex: /\bgh[ousr]_[A-Za-z0-9]{36}\b/g, severity: "high", sensitive: true },
  { id: "slack-token", title: "Slack token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, severity: "high", sensitive: true },
  { id: "npm-token", title: "npm access token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "high", sensitive: true },
  { id: "google-oauth-secret", title: "Google OAuth client secret", regex: /\bGOCSPX-[A-Za-z0-9_-]{20,}/g, severity: "high", sensitive: true },
  { id: "sendgrid-key", title: "SendGrid API key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: "high", sensitive: true },
  { id: "private-key-block", title: "Private key block", regex: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: "critical", sensitive: true },
  { id: "supabase-service-role", title: "Supabase service_role JWT", regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*role[A-Za-z0-9_-]*service_role[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+/g, severity: "critical", sensitive: true },
];

// Only scan text-like files, and skip anything large or binary.
const TEXT_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json", ".html", ".css", ".map", ".txt", ".env"]);
const MAX_BYTES = 8 * 1024 * 1024;
const SKIP_DIRS = new Set(["node_modules", ".git"]);

function* walk(dir: string): Generator<string> {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      yield* walk(full);
    } else if (e.isFile()) {
      const dot = e.name.lastIndexOf(".");
      const ext = dot >= 0 ? e.name.slice(dot) : "";
      if (TEXT_EXT.has(ext)) yield full;
    }
  }
}

function redact(secret: string): string {
  if (secret.length <= 10) return secret.slice(0, 2) + "***";
  return `${secret.slice(0, 6)}...${secret.slice(-4)} (${secret.length} chars)`;
}

export const exposedSecrets: Check = {
  name: "exposed-secrets",
  title: "Secrets and private keys shipped to the client bundle",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const root = ctx.projectDir;
    for (const file of walk(root)) {
      let size = 0;
      try {
        size = statSync(file).size;
      } catch {
        continue;
      }
      if (size > MAX_BYTES) continue;
      let content: string;
      try {
        content = readFileSync(file, "utf8");
      } catch {
        continue;
      }
      const rel = relative(root, file);
      for (const p of PATTERNS) {
        p.regex.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = p.regex.exec(content)) !== null) {
          const line = content.slice(0, m.index).split("\n").length;
          const sensitive = p.sensitive !== false;
          findings.push({
            id: `exposed-secrets:${p.id}:${rel}:${line}`,
            check: "exposed-secrets",
            title: sensitive ? `${p.title} exposed in ${rel}` : `${p.title} in ${rel}`,
            severity: p.severity,
            state: "proven", // a deterministic regex match on a key shape is proof enough to act
            location: `${rel}:${line}`,
            description: sensitive
              ? `A ${p.title} appears in a file under the scanned directory. If this directory is a ` +
                `client bundle, the secret is readable by anyone who opens the page.`
              : `A ${p.title} appears in ${rel}. Test-mode keys are safe to expose, so this is not an ` +
                `incident, but shipping any key to the client is a habit worth breaking.`,
            remediation: sensitive
              ? `Rotate this credential now (assume it is compromised), then move it server-side. ` +
                `Client code should only ever hold publishable keys.`
              : `No rotation needed for a test key. Prefer a publishable key in client code, and keep ` +
                `even test secrets out of the bundle.`,
            proof: {
              method: "deterministic regex match on a known key format",
              replay: `grep -nE '${p.regex.source}' "${rel}"`,
              evidence: redact(m[0]),
            },
            regressionHint:
              `Add a CI step that greps the build output for ${p.id} and fails if present.`,
          });
        }
      }
    }
    ctx.log(`exposed-secrets: scanned ${root}, ${findings.length} match(es)`);
    return findings;
  },
};
