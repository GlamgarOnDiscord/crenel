// committed-env: flag committed .env files. This sits right under the tool's
// headline (exposed secrets) but catches what exposed-secrets cannot: a .env
// conventionally holds secrets (DB URLs, custom tokens, passwords) that do not
// match any known key prefix, so the committed FILE is the signal, not its
// contents. Deterministic and offline. A lead: the fix is to gitignore it and
// rotate anything it held.

import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";

import type { Check, CheckContext, Finding } from "../core/types.js";
import { walkFiles, relative } from "../core/walk.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);

// Example/template variants are meant to be committed and hold no secrets.
const SAFE_SUFFIXES = [".example", ".sample", ".template", ".dist", ".tpl"];

function isEnvFile(name: string): boolean {
  if (!/^\.env(\.|$)/.test(name)) return false; // .env, .env.production, .env.local ...
  const lower = name.toLowerCase();
  if (lower.endsWith(".example") || lower === ".env.example") return false;
  return !SAFE_SUFFIXES.some((s) => lower.endsWith(s)) && !lower.includes("example") && !lower.includes("sample") && !lower.includes("template");
}

const walk = (dir: string) => walkFiles(dir, { skipDirs: SKIP_DIRS, accept: (name) => isEnvFile(name) });

// Count non-empty, non-comment KEY=VALUE lines that actually assign a value.
function assignedVars(text: string): number {
  let n = 0;
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const m = t.match(/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+)$/);
    if (m && m[1]!.trim() !== "" && m[1]!.trim() !== '""' && m[1]!.trim() !== "''") n++;
  }
  return n;
}

/**
 * In a git work tree, which of `files` git tracks and which it ignores. Null
 * when projectDir is not a work tree or git is unavailable: then every env file
 * found counts, as before (a deploy folder, an unpacked archive). Read-only:
 * ls-files and check-ignore, no lock taken.
 */
export function gitStatusOf(dir: string, files: string[]): { tracked: Set<string>; ignored: Set<string> } | null {
  if (!files.length) return null;
  const git = (args: string[], input?: string) => execFileSync("git", ["-C", dir, ...args], {
    encoding: "utf8", input, timeout: 15_000, maxBuffer: 16 * 1024 * 1024, stdio: ["pipe", "pipe", "ignore"],
    env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" },
  });
  try {
    if (git(["rev-parse", "--is-inside-work-tree"]).trim() !== "true") return null;
  } catch { return null; }
  const rels = files.map((f) => relative(dir, f) || f);
  const tracked = new Set<string>();
  const ignored = new Set<string>();
  try {
    for (const r of git(["ls-files", "-z", "--", ...rels]).split("\0")) if (r) tracked.add(r);
  } catch { return null; }
  try {
    // check-ignore exits 1 when nothing is ignored: that is not an error here.
    for (const r of git(["check-ignore", "--no-index", "-z", "--stdin"], rels.join("\0") + "\0").split("\0")) if (r) ignored.add(r);
  } catch (err) {
    const out = (err as { stdout?: string }).stdout ?? "";
    for (const r of out.split("\0")) if (r) ignored.add(r);
  }
  return { tracked, ignored };
}

export const committedEnv: Check = {
  name: "committed-env",
  title: "Committed .env files (conventionally secret-bearing)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = [...walk(ctx.projectDir)];
    // In a git repository only a TRACKED .env is committed. An ignored one is the
    // recommended setup (a local file next to .env.example); an untracked one that
    // nothing ignores is one `git add .` away, so it stays a low lead.
    const git = gitStatusOf(ctx.projectDir, files);
    for (const file of files) {
      const relPath = relative(ctx.projectDir, file) || file;
      if (git && !git.tracked.has(relPath)) {
        if (git.ignored.has(relPath)) continue;
        findings.push({
          id: `committed-env:${relPath}`,
          check: "committed-env",
          title: `Env file not ignored by git: ${relPath}`,
          severity: "low",
          state: "unproven",
          location: relPath,
          description: `${relPath} is not committed, but no .gitignore rule covers it: the next \`git add .\` commits it.`,
          remediation: "Add .env* (keeping !.env.example) to .gitignore.",
          proof: { method: "git check-ignore finds no rule for the file", replay: `git check-ignore -v '${relPath}' || echo 'not ignored'` },
        });
        continue;
      }
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
        proof: git
          ? { method: "env file tracked by git", replay: `git ls-files --error-unmatch '${rel}'` }
          : { method: "committed env file detected by name", replay: `git ls-files | grep -nE '(^|/)\\.env(\\.|$)'` },
        regressionHint: "CI: fail if a tracked file matches .env (excluding .env.example).",
      });
    }
    ctx.log(`committed-env: ${findings.length} committed env file(s)`);
    return findings;
  },
};
