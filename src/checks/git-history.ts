// git-history: a key deleted from the code is still in every clone, in the
// commit that added it. Rotating is the only fix, and this check finds those
// keys: it reads the added lines of the repository's history (git log -p, last
// 500 commits by default) with the same detectors as exposed-secrets, and
// reports keys that are no longer in the working tree. Offline, read-only.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { PATTERNS, isPlaceholder } from "./exposed-secrets.js";

function repoRoot(start: string): string | null {
  let dir = start;
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, ".git"))) return dir;
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
  return null;
}

const redact = (s: string) => (s.length <= 12 ? "…" : `${s.slice(0, 8)}…${s.slice(-4)}`);

export const gitHistory: Check = {
  name: "git-history",
  title: "Secrets still in the Git history after being removed from the code",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const root = repoRoot(ctx.projectDir);
    if (!root) { ctx.log("git-history: no Git repository above the scanned directory"); return []; }
    const max = ((ctx.options["git-history"] ?? {}) as { maxCommits?: number }).maxCommits ?? 500;
    const log = spawnSync("git", ["-C", root, "log", "--all", "-p", "--no-color", "--no-ext-diff", "--unified=0", `-n${max}`, "--format=commit %H%nauthored %aI"], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
    if (log.status !== 0) { ctx.log(`git-history: git log failed: ${log.stderr.slice(0, 200)}`); return []; }
    const findings: Finding[] = [];
    const seen = new Set<string>();
    let commit = "", date = "", file = "";
    for (const line of log.stdout.split("\n")) {
      if (line.startsWith("commit ")) { commit = line.slice(7, 19); continue; }
      if (line.startsWith("authored ")) { date = line.slice(9, 19); continue; }
      if (line.startsWith("+++ b/")) { file = line.slice(6); continue; }
      if (!line.startsWith("+") || line.startsWith("+++")) continue;
      for (const p of PATTERNS) {
        if (p.sensitive === false) continue;
        p.regex.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = p.regex.exec(line)) !== null) {
          if (p.accept && !p.accept(m[0], line, m.index)) continue;
          if (isPlaceholder(m[0]) || seen.has(m[0])) continue;
          seen.add(m[0]);
          const stillThere = spawnSync("git", ["-C", root, "grep", "-q", "-F", m[0], "HEAD"]).status === 0;
          if (stillThere) continue; // exposed-secrets reports what is in the tree today
          findings.push({
            id: `git-history:${p.id}:${commit}:${file}`,
            check: "git-history",
            title: `${p.title} in Git history (${file}, commit ${commit.slice(0, 7)}), removed from the code but not from the history`,
            severity: p.severity,
            state: "proven",
            location: `${file} @ ${commit.slice(0, 7)}`,
            description: `Commit ${commit.slice(0, 7)} (${date}) added a ${p.title} to ${file}. It is gone from the current code, but every clone of the repository still has it.`,
            remediation: "Rotate the key now: removing it from the history (git filter-repo) does not reach existing clones, forks or caches.",
            proof: { method: "detector match on a line added in the Git history", replay: `git show ${commit.slice(0, 7)} -- '${file}' | grep -n '${redact(m[0]).slice(0, 8)}'`, evidence: redact(m[0]) },
          });
        }
      }
    }
    ctx.log(`git-history: ${findings.length} key(s) only in the history (last ${max} commits)`);
    return findings;
  },
};
