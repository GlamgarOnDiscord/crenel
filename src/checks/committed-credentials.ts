// committed-credentials: package-manager and registry credential files that end
// up committed. These hold auth tokens and passwords that no key-shape scanner
// recognises and that are not .env, so they are their own high-signal, low-FP
// category: the file name plus a credential field is the signal. Deterministic
// and offline.

import { readFileSync, statSync } from "node:fs";
import { relative, basename } from "node:path";
import type { Check, CheckContext, Finding, Severity } from "../core/types.js";
import { walkFiles } from "../core/walk.js";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);

interface Rule { file: (name: string) => boolean; secret: RegExp; what: string; sev: Severity }
const RULES: Rule[] = [
  { file: (n) => n === ".npmrc", secret: /(?:_authToken|_auth|_password)\s*=\s*\S+/i, what: "npm auth token", sev: "critical" },
  { file: (n) => n === ".pypirc", secret: /(?:password|token)\s*[:=]\s*\S+/i, what: "PyPI credential", sev: "critical" },
  { file: (n) => n === ".netrc" || n === "_netrc", secret: /\bpassword\s+\S+/i, what: "netrc password", sev: "critical" },
  { file: (n) => n === ".dockercfg" || n === "config.json", secret: /"auth"\s*:\s*"[A-Za-z0-9+/=]+"/, what: "Docker registry auth", sev: "high" },
  { file: (n) => n === ".git-credentials", secret: /https?:\/\/[^:]+:[^@]+@/i, what: "git credential", sev: "critical" },
];

export const committedCredentials: Check = {
  name: "committed-credentials",
  title: "Committed package-manager / registry credential files",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    // Only read files that match one of the credential file names.
    const accept = (name: string) => RULES.some((r) => r.file(name));
    for (const file of walkFiles(ctx.projectDir, { skipDirs: SKIP, accept })) {
      const base = basename(file);
      const rule = RULES.find((r) => r.file(base));
      if (!rule) continue;
      let text: string;
      try {
        if (statSync(file).size > 1024 * 1024) continue;
        text = readFileSync(file, "utf8");
      } catch { continue; }
      if (!rule.secret.test(text)) continue; // the file name alone is not enough; it must carry a credential
      const rel = relative(ctx.projectDir, file) || file;
      findings.push({
        id: `committed-credentials:${rel}`,
        check: "committed-credentials",
        title: `Committed credential file: ${rel} (${rule.what})`,
        severity: rule.sev,
        state: "proven", // a credential field in a known credential file is a concrete, replayable match
        location: rel,
        description: `${rel} carries a ${rule.what}. It is committed, so anyone with repo access has the credential, and it is not the kind of secret a key-shape scanner would catch.`,
        remediation: "Remove it from the repo and from git history, rotate the credential, and keep credential files out of version control (gitignore them; use env or a secret manager in CI).",
        proof: { method: "credential field in a known credential file", replay: `grep -nE '${rule.secret.source}' "${rel}"` },
        regressionHint: "CI: fail if a .npmrc/.pypirc/.netrc/.git-credentials with a credential is tracked.",
      });
    }
    ctx.log(`committed-credentials: ${findings.length} finding(s)`);
    return findings;
  },
};
