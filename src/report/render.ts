// Report rendering. Two outputs: a human summary for the terminal, and a JSON
// document for CI and for diffing runs over time.

import pc from "picocolors";
import type { RunResult } from "../core/runner.js";
import type { Finding, Severity } from "../core/types.js";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function colorSev(s: Severity, text: string): string {
  switch (s) {
    case "critical": return pc.bgRed(pc.white(` ${text} `));
    case "high": return pc.red(text);
    case "medium": return pc.yellow(text);
    case "low": return pc.cyan(text);
    default: return pc.dim(text);
  }
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    if (a.state !== b.state) return a.state === "proven" ? -1 : 1;
    return SEV_RANK[a.severity] - SEV_RANK[b.severity];
  });
}

export function renderText(result: RunResult): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(pc.bold(`Bastion report  ${pc.dim("·")}  ${result.project}`));
  lines.push(pc.dim(`${result.startedAt}  ·  checks: ${result.checksRun.join(", ") || "none"}`));
  lines.push("");

  const proven = result.findings.filter((f) => f.state === "proven");
  const unproven = result.findings.filter((f) => f.state === "unproven");

  // Count line, by severity, for proven findings (the ones that should gate).
  const counts = SEV_ORDER.map((s) => {
    const n = proven.filter((f) => f.severity === s).length;
    return n > 0 ? colorSev(s, `${n} ${s}`) : null;
  }).filter(Boolean);
  lines.push(
    counts.length > 0
      ? `Proven: ${counts.join("  ")}`
      : pc.green("Proven: none"),
  );
  if (unproven.length > 0) lines.push(pc.dim(`Leads (unproven): ${unproven.length}`));
  lines.push("");

  if (result.findings.length === 0 && result.errors.length === 0) {
    lines.push(pc.green("No findings. Nothing proven, no leads."));
    lines.push("");
  }

  for (const f of sortFindings(result.findings)) {
    const tag = f.state === "proven" ? colorSev(f.severity, f.severity.toUpperCase()) : pc.dim("LEAD");
    lines.push(`${tag}  ${pc.bold(f.title)}`);
    lines.push(`      ${pc.dim(f.location)}`);
    lines.push(`      ${f.description}`);
    if (f.proof) lines.push(`      ${pc.dim("proof:")} ${f.proof.replay}`);
    lines.push(`      ${pc.dim("fix:")} ${f.remediation}`);
    lines.push("");
  }

  if (result.errors.length > 0) {
    lines.push(pc.yellow("Checks that errored:"));
    for (const e of result.errors) lines.push(`  - ${e.check}: ${e.message}`);
    lines.push("");
  }

  return lines.join("\n");
}

export function renderJson(result: RunResult): string {
  return JSON.stringify(result, null, 2);
}

export function renderDiff(d: import("../core/baseline.js").Diff): string {
  const lines: string[] = [];
  lines.push(pc.bold("Depuis la baseline"));
  const added = d.added.length;
  const fixed = d.fixed.length;
  lines.push(
    `  ${added > 0 ? pc.red(`+${added} nouveau(x)`) : pc.dim("+0 nouveau")}` +
      `   ${fixed > 0 ? pc.green(`-${fixed} corrigé(s)`) : pc.dim("-0 corrigé")}` +
      `   ${pc.dim(`${d.persisting.length} persistant(s)`)}`,
  );
  for (const f of sortFindings(d.added)) {
    const tag = f.state === "proven" ? colorSev(f.severity, f.severity.toUpperCase()) : pc.dim("LEAD");
    lines.push(`  ${pc.red("NOUVEAU")} ${tag}  ${f.title}  ${pc.dim(f.location)}`);
  }
  for (const e of d.fixed) {
    lines.push(`  ${pc.green("CORRIGÉ")}  ${e.title}`);
  }
  lines.push("");
  return lines.join("\n");
}

/** Exit code policy: non-zero only when a proven finding is high or critical. */
export function exitCode(result: RunResult): number {
  const gating = result.findings.some(
    (f) => f.state === "proven" && (f.severity === "high" || f.severity === "critical"),
  );
  return gating ? 1 : 0;
}
