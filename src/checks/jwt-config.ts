// jwt-config: catch JWT configuration that defeats signature verification. The
// classic is the "none" algorithm (a token with no signature is accepted), a
// well-known authentication bypass. Deterministic and offline, near-zero FP:
// nobody legitimately configures alg "none".

import { readFileSync, statSync } from "node:fs";
import { relative } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, extOf } from "../core/walk.js";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);
const SCAN = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".yml", ".yaml"]);

// algorithm: "none"  |  algorithms: ["none", ...]  |  alg: 'none'
const NONE_ALG = /\b(?:algorithm|alg)\s*:\s*['"]none['"]/i;
const NONE_IN_LIST = /\balgorithms\s*:\s*\[[^\]]*['"]none['"]/i;
// verify(token, ...) with a null/empty secret is also a bypass shape.
const EMPTY_SECRET_VERIFY = /\.verify\s*\(\s*[^,]+,\s*(?:null|undefined|['"]['"])/;

const lineOf = (t: string, i: number) => t.slice(0, i).split("\n").length;

export const jwtConfig: Check = {
  name: "jwt-config",
  title: "JWT configuration that defeats signature verification (alg none)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const accept = (name: string) => SCAN.has(extOf(name));
    for (const file of walkFiles(ctx.projectDir, { skipDirs: SKIP, accept })) {
      let text: string;
      try {
        if (statSync(file).size > 4 * 1024 * 1024) continue;
        text = readFileSync(file, "utf8");
      } catch { continue; }
      const rel = relative(ctx.projectDir, file) || file;
      const check = (re: RegExp, id: string, what: string) => {
        const g = new RegExp(re, "gi");
        let m: RegExpExecArray | null;
        while ((m = g.exec(text)) !== null) {
          findings.push({
            id: `jwt-config:${id}:${rel}:${lineOf(text, m.index)}`,
            check: "jwt-config",
            title: `JWT ${what} in ${rel}`,
            severity: "high",
            state: "unproven",
            location: `${rel}:${lineOf(text, m.index)}`,
            description: `${rel} ${what}. A token can then be accepted without a valid signature, which is an authentication bypass.`,
            remediation: "Pin a strong algorithm (e.g. RS256/ES256 or HS256), never 'none', and always verify with the real secret/public key.",
            proof: { method: "distinctive JWT misconfiguration pattern", replay: `grep -niE '${re.source}' "${rel}"` },
          });
        }
      };
      check(NONE_ALG, "alg-none", "sets algorithm 'none'");
      check(NONE_IN_LIST, "alg-none-list", "allows 'none' in its algorithms list");
      check(EMPTY_SECRET_VERIFY, "empty-secret", "verifies a token with an empty/null secret");
    }
    ctx.log(`jwt-config: ${findings.length} finding(s)`);
    return findings;
  },
};
