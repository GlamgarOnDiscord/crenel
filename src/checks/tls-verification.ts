// tls-verification: catch code or config that turns off TLS certificate
// verification. Disabling it (globally with NODE_TLS_REJECT_UNAUTHORIZED=0, or
// per-request with rejectUnauthorized:false / strictSSL:false) silently accepts
// any certificate, so a network attacker can read and alter "HTTPS" traffic.
// Deterministic and offline: distinctive patterns, near-zero false positives.

import { readFileSync, statSync } from "node:fs";

import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, extOf, isCommentedAt, relative } from "../core/walk.js";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);
const SCAN = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".env", ".sh", ".yml", ".yaml"]);

interface Rule { id: string; re: RegExp; title: string; remediation: string }
const RULES: Rule[] = [
  {
    id: "node-tls-reject",
    re: /NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0/,
    title: "NODE_TLS_REJECT_UNAUTHORIZED=0 (TLS verification disabled process-wide)",
    remediation: "Never set this to 0. Fix the certificate chain (add the CA) instead; it disables TLS verification for the whole process.",
  },
  {
    id: "reject-unauthorized",
    re: /rejectUnauthorized\s*:\s*false/,
    title: "rejectUnauthorized: false (TLS certificate not verified)",
    remediation: "Remove it, or pass the trusted CA via the `ca` option. false accepts any certificate, enabling MITM.",
  },
  {
    id: "strict-ssl",
    re: /strictSSL\s*:\s*false/,
    title: "strictSSL: false (TLS certificate not verified)",
    remediation: "Remove it and trust the proper CA; false disables certificate validation.",
  },
];

const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;

export const tlsVerification: Check = {
  name: "tls-verification",
  title: "Disabled TLS certificate verification (MITM risk)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const accept = (name: string) => SCAN.has(extOf(name)) || name.startsWith(".env");
    for (const file of walkFiles(ctx.projectDir, { skipDirs: SKIP, accept })) {
      let text: string;
      try {
        if (statSync(file).size > 4 * 1024 * 1024) continue;
        text = readFileSync(file, "utf8");
      } catch { continue; }
      const rel = relative(ctx.projectDir, file) || file;
      for (const r of RULES) {
        const re = new RegExp(r.re, "g");
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          if (isCommentedAt(text, m.index)) continue;
          const line = lineOf(text, m.index);
          findings.push({
            id: `tls-verification:${r.id}:${rel}:${line}`,
            check: "tls-verification",
            title: r.title,
            severity: "high",
            state: "unproven",
            location: `${rel}:${line}`,
            description: `${rel} disables TLS certificate verification, so any server (or a network attacker) can present a forged certificate and the connection is still trusted.`,
            remediation: r.remediation,
            proof: { method: "distinctive pattern for disabled TLS verification", replay: `grep -nE '${r.re.source}' "${rel}"` },
            regressionHint: "CI: fail if the codebase disables TLS verification.",
          });
        }
      }
    }
    ctx.log(`tls-verification: ${findings.length} finding(s)`);
    return findings;
  },
};
