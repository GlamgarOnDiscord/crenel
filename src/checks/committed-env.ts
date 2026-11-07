// committed-env: flag committed .env files. This sits right under the tool's
// headline (exposed secrets) but catches what exposed-secrets cannot: a .env
// conventionally holds secrets (DB URLs, custom tokens, passwords) that do not
// match any known key prefix, so the committed FILE is the signal, not its
// contents. Deterministic and offline. A lead: the fix is to gitignore it and
// rotate anything it held.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);

// Example/template variants are meant to be committed and hold no secrets.
const SAFE_SUFFIXES = [".example", ".sample", ".template", ".dist", ".tpl"];

function isEnvFile(name: string): boolean {
  if (!/^\.env(\.|$)/.test(name)) return false; // .env, .env.production, .env.local ...
  const lower = name.toLowerCase();
  if (lower.endsWith(".example") || lower === ".env.example") return false;
  return !SAFE_SUFFIXES.some((s) => lower.endsWith(s)) && !lower.includes("example") && !lower.includes("sample") && !lower.includes("template");
}

function* walk(dir: string, depth = 0): Generator<string> {
  if (depth > 8) return;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      yield* walk(full, depth + 1);
    } else if (e.isFile() && isEnvFile(e.name)) {
      yield full;
    }
  }
}

// Count non-empty, non-comment KEY=VALUE lines that actually assign a value.
function assignedVars(text: string): number {
  let n = 0;
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const m = t.match(/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+)$/);
    if (m && m[1]!.trim() !== "" && m[1]!.trim() !== '""' && m[1]!.trim() !== "''") n++;
  }
  return n;
}

export const committedEnv: Check = {
  name: "committed-env",
  title: "Committed .env files (conventionally secret-bearing)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of walk(ctx.projectDir)) {
      let vars = 0;
      try {
        if (statSync(file).size < 256 * 1024) vars = assignedVars(readFileSync(file, "utf8"));
      } catch { /* unreadable: still report the file's presence */ }
      const rel = relative(ctx.projectDir, file) || file;
      findings.push({
        id: `committed-env:${rel}`,
        check: "committed-env",
        title: `Committed env file: ${rel}`,
        severity: vars > 0 ? "medium" : "low",
        state: "unproven",
        location: rel,
        description:
          `${rel} is committed${vars > 0 ? ` and assigns ${vars} variable(s)` : ""}. A .env conventionally holds ` +
          `secrets (database URLs, tokens, passwords) that no key-shape scanner would recognise, so the committed file ` +
          `itself is the risk.`,
        remediation:
          "Add it to .gitignore, remove it from the repo (and from git history), rotate anything it held, and commit only a .env.example with empty values.",
        proof: { method: "committed env file detected by name", replay: `git ls-files | grep -nE '(^|/)\\.env(\\.|$)'` },
        regressionHint: "CI: fail if a tracked file matches .env (excluding .env.example).",
      });
    }
    ctx.log(`committed-env: ${findings.length} committed env file(s)`);
    return findings;
  },
};
