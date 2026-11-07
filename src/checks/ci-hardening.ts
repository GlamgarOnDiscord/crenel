// ci-hardening: read the project's GitHub Actions workflows and flag the
// patterns that turn a dependency or a pull request into code execution on your
// secrets. Deterministic and offline. This is the direct lesson of the
// @tanstack supply-chain incident, where the entry point was a workflow.
//
//   - pull_request_target: runs with repo secrets on a fork's code. High.
//   - an action pinned to a tag/branch instead of a commit SHA: a moved tag
//     changes what runs. Medium.
//   - install without --ignore-scripts: a dependency's install hook runs in CI.
//     Medium.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import type { Check, CheckContext, Finding } from "../core/types.js";

function findWorkflowsDir(start: string): string | null {
  let dir = start;
  for (let i = 0; i < 8; i++) {
    const wf = join(dir, ".github", "workflows");
    if (existsSync(wf)) return wf;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split("\n").length;
}

export const ciHardening: Check = {
  name: "ci-hardening",
  title: "Risky GitHub Actions workflows (pull_request_target, unpinned actions, install scripts)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const wfDir = findWorkflowsDir(ctx.projectDir);
    if (!wfDir) {
      ctx.log("ci-hardening: no .github/workflows found");
      return findings;
    }
    let files: string[];
    try {
      files = readdirSync(wfDir).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"));
    } catch {
      return findings;
    }
    const root = dirname(dirname(wfDir)); // repo root, for nice relative paths
    for (const file of files) {
      const full = join(wfDir, file);
      const rel = relative(root, full);
      let text: string;
      try { text = readFileSync(full, "utf8"); } catch { continue; }

      // pull_request_target
      for (const m of text.matchAll(/pull_request_target/g)) {
        findings.push({
          id: `ci-hardening:prt:${rel}:${lineOf(text, m.index!)}`,
          check: "ci-hardening",
          title: `Workflow utilise pull_request_target (${file})`,
          severity: "high", state: "unproven",
          location: `${rel}:${lineOf(text, m.index!)}`,
          description: "pull_request_target s'exécute avec les secrets du dépôt sur le code d'une fork. C'est le vecteur d'exfiltration de secrets le plus courant en CI.",
          remediation: "Préférer pull_request, ne jamais checkout puis exécuter le code de la PR avec les secrets, et séparer la partie privilégiée.",
          proof: { method: "match déterministe dans le workflow", replay: `grep -n pull_request_target "${rel}"` },
          regressionHint: "Interdire pull_request_target par une règle de lint de workflows.",
        });
      }

      // unpinned third-party actions (uses: owner/repo@tag, not @<40-hex>)
      for (const m of text.matchAll(/uses:\s*([\w.-]+\/[\w.-]+)@([^\s#]+)/g)) {
        const ref = m[2]!;
        const pinned = /^[0-9a-f]{40}$/.test(ref);
        if (!pinned) {
          findings.push({
            id: `ci-hardening:unpinned:${rel}:${lineOf(text, m.index!)}`,
            check: "ci-hardening",
            title: `Action non épinglée à un SHA: ${m[1]}@${ref} (${file})`,
            severity: "medium", state: "unproven",
            location: `${rel}:${lineOf(text, m.index!)}`,
            description: `L'action ${m[1]} est épinglée à "${ref}". Un tag ou une branche peut être déplacé, ce qui change le code exécuté dans votre CI.`,
            remediation: `Épingler à un commit SHA complet: ${m[1]}@<sha40>.`,
            proof: { method: "match déterministe", replay: `grep -n '${m[1]}@${ref}' "${rel}"` },
          });
        }
      }

      // install without --ignore-scripts
      for (const m of text.matchAll(/((?:pnpm|npm|yarn)\s+(?:install|ci|i)\b[^\n]*)/g)) {
        const cmd = m[1]!;
        if (!/--ignore-scripts/.test(cmd)) {
          findings.push({
            id: `ci-hardening:install-scripts:${rel}:${lineOf(text, m.index!)}`,
            check: "ci-hardening",
            title: `Install sans --ignore-scripts en CI (${file})`,
            severity: "medium", state: "unproven",
            location: `${rel}:${lineOf(text, m.index!)}`,
            description: `"${cmd.trim()}" laisse s'exécuter les scripts d'installation des dépendances dans la CI.`,
            remediation: "Installer avec --ignore-scripts et autoriser au cas par cas les paquets de confiance.",
            proof: { method: "match déterministe", replay: `grep -n 'install' "${rel}"` },
          });
        }
      }
    }
    ctx.log(`ci-hardening: ${files.length} workflow(s), ${findings.length} finding(s)`);
    return findings;
  },
};
