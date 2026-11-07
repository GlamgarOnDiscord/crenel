// public-env: a secret behind a client-exposed env prefix. Frameworks inline any
// var named NEXT_PUBLIC_*, VITE_*, REACT_APP_* (and friends) into the browser
// bundle by design. So a var that carries such a prefix AND is named like a
// secret is a near-certain leak to the client, whatever its value looks like.
// This is distinct from exposed-secrets (which matches key shapes) and from
// committed-env (which flags the file): here the prefix+name combination is the
// signal. Deterministic and offline.

import { readFileSync, statSync } from "node:fs";
import { relative } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, extOf, isCommentedAt } from "../core/walk.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);
const SCAN_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".env", ".sh", ".yml", ".yaml"]);

// Prefixes frameworks expose to the client bundle.
const PUBLIC_PREFIXES = ["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_", "GATSBY_", "VUE_APP_", "NUXT_PUBLIC_"];
const SECRETISH = "(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|API[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET|SERVICE[_-]?ROLE)";
// Matches e.g. a public-prefixed var whose name ends in SECRET/TOKEN/KEY, in
// .env, source and shell files.
const RE = new RegExp(`\\b((?:${PUBLIC_PREFIXES.join("|")})[A-Z0-9_]*${SECRETISH}[A-Z0-9_]*)\\b`, "g");

const walk = (dir: string) =>
  walkFiles(dir, { skipDirs: SKIP_DIRS, accept: (name) => SCAN_EXT.has(extOf(name)) || name.startsWith(".env") });

export const publicEnv: Check = {
  name: "public-env",
  title: "Secret behind a client-exposed env prefix (NEXT_PUBLIC_, VITE_, ...)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const file of walk(ctx.projectDir)) {
      let text: string;
      try {
        if (statSync(file).size > 4 * 1024 * 1024) continue;
        text = readFileSync(file, "utf8");
      } catch { continue; }
      const rel = relative(ctx.projectDir, file) || file;
      RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = RE.exec(text)) !== null) {
        if (isCommentedAt(text, m.index)) continue;
        const name = m[1]!;
        const line = text.slice(0, m.index).split("\n").length;
        const key = `${name}:${rel}:${line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: `public-env:${rel}:${line}:${name}`,
          check: "public-env",
          title: `Secret-named var with a client-exposed prefix: ${name}`,
          severity: "high",
          state: "unproven",
          location: `${rel}:${line}`,
          description:
            `${name} carries a framework "public" prefix, so its value is inlined into the client bundle and readable ` +
            `by anyone, yet its name says it holds a secret. If it has a real value, that secret is exposed.`,
          remediation:
            "Remove the public prefix and read the secret only server-side (API route, server action, edge function). The client gets a publishable value or a server endpoint, never the secret.",
          proof: { method: "client-exposed env prefix on a secret-named var", replay: `grep -nE '${RE.source}' "${rel}"` },
          regressionHint: "CI: fail if a NEXT_PUBLIC_/VITE_/REACT_APP_ var is named like a secret.",
        });
      }
    }
    ctx.log(`public-env: ${findings.length} client-exposed secret-named var(s)`);
    return findings;
  },
};
