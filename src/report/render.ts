// Report rendering. Two outputs: a human summary for the terminal, and a JSON
// document for CI and for diffing runs over time.

import pc from "picocolors";
import type { RunResult } from "../core/runner.js";
import type { Finding, Severity } from "../core/types.js";

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Brand colours. Amber is the only accent; red is reserved for what is proven
// or critical; everything else is grey. Truecolor when the terminal says it
// supports it, the nearest ANSI colour otherwise, nothing when colour is off.
const TRUECOLOR = /truecolor|24bit/i.test(process.env.COLORTERM ?? "");
const rgb = (r: number, g: number, b: number, fallback: (s: string) => string) => (s: string) =>
  !pc.isColorSupported ? s : TRUECOLOR ? `\x1b[38;2;${r};${g};${b}m${s}\x1b[39m` : fallback(s);
const amber = rgb(246, 168, 33, pc.yellow);
const red = rgb(239, 68, 68, pc.red);
const grey = pc.dim;

const SEV_LABEL: Record<Severity, string> = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", info: "INFO" };

function colorSev(s: Severity, text: string): string {
  switch (s) {
    case "critical": return pc.bold(red(text));
    case "high": return red(text);
    case "medium": return amber(text);
    default: return grey(text);
  }
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    if (a.state !== b.state) return a.state === "proven" ? -1 : 1;
    return SEV_RANK[a.severity] - SEV_RANK[b.severity];
  });
}

// Wrap plain text to the terminal width, every line after the first indented.
function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if (line && (line + " " + w).length > width) { lines.push(line); line = w; }
    else line = line ? line + " " + w : w;
  }
  if (line) lines.push(line);
  return lines.join("\n" + indent);
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

function duration(ms?: number): string | null {
  if (ms === undefined) return null;
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1).replace(".", ",")} s`;
}

export function renderText(result: RunResult): string {
  const cols = Math.max(60, Math.min(process.stdout.columns ?? 100, 110));
  const pad = "  ";
  const body = cols - 10;
  const out: string[] = [""];

  // Header: the wordmark (crenel + amber square), the project, then the run facts.
  const facts = [plural(result.checksRun.length, "check", "checks"), duration(result.durationMs), result.startedAt.slice(0, 16).replace("T", " ")]
    .filter(Boolean).join(grey("  ·  "));
  out.push(`${pad}${pc.bold("crenel")}${amber("■")}  ${grey("·")}  ${pc.bold(result.project)}`);
  out.push(`${pad}${grey(facts)}`);
  out.push("");

  const proven = sortFindings(result.findings.filter((f) => f.state === "proven"));
  const leads = sortFindings(result.findings.filter((f) => f.state !== "proven"));

  // Summary line: proven in red, leads in grey.
  const crit = proven.filter((f) => f.severity === "critical").length;
  out.push(
    pad +
      (proven.length ? red(`● ${proven.length} proven`) + (crit ? red(`, ${crit} critical`) : "") : grey("● 0 proven")) +
      grey("   ○ ") + grey(plural(leads.length, "lead", "leads")),
  );
  out.push("");

  if (result.findings.length === 0 && result.errors.length === 0) {
    out.push(`${pad}${amber("✓")} Nothing to report: no proven finding, no lead.`);
    out.push("");
  }

  const section = (title: string, color: (s: string) => string, list: Finding[]) => {
    if (!list.length) return;
    out.push(`${pad}${color(pc.bold(title))} ${grey("─".repeat(Math.max(4, body - title.length)))}`);
    out.push("");
    for (const f of list) {
      const tag = f.state === "proven" ? colorSev(f.severity, SEV_LABEL[f.severity].padEnd(5)) : grey(SEV_LABEL[f.severity].padEnd(5));
      const ind = pad + "       ";
      out.push(`${pad}${tag}  ${pc.bold(f.title)}`);
      out.push(`${ind}${grey(f.location + "  ·  " + f.check)}`);
      out.push(`${ind}${wrap(f.description, body, ind)}`);
      if (f.proof) out.push(`${ind}${amber("proof")}   ${f.proof.replay}`);
      out.push(`${ind}${grey("fix")}     ${wrap(f.remediation, body - 8, ind + "        ")}`);
      out.push("");
    }
  };
  section("Proven", red, proven);
  section("Leads", grey, leads);

  if (result.errors.length > 0) {
    out.push(`${pad}${amber(pc.bold("Checks that errored"))}`);
    for (const e of result.errors) out.push(`${pad}  ${amber("!")} ${e.check}: ${e.message}`);
    out.push("");
  }

  // Verdict: what CI would do with this run.
  const gating = result.findings.filter((f) => f.state === "proven" && (f.severity === "high" || f.severity === "critical")).length;
  out.push(
    gating
      ? `${pad}${red("✕")} ${pc.bold("CI fails")}${grey(`: ${plural(gating, "proven finding", "proven findings")} of high or critical severity.`)}`
      : `${pad}${amber("✓")} ${pc.bold("CI passes")}${grey(": no proven high or critical finding.")}`,
  );
  if (proven.length) out.push(`${pad}${grey("→ run crenel generate-tests to keep them out for good, in CI")}`);
  out.push("");
  return out.join("\n");
}

export function renderJson(result: RunResult): string {
  return JSON.stringify(result, null, 2);
}

export function renderDiff(d: import("../core/baseline.js").Diff): string {
  const lines: string[] = [];
  lines.push(pc.bold("Since the baseline"));
  const added = d.added.length;
  const fixed = d.fixed.length;
  lines.push(
    `  ${added > 0 ? red(`+${added} new`) : pc.dim("+0 new")}` +
      `   ${fixed > 0 ? amber(`-${fixed} fixed`) : pc.dim("-0 fixed")}` +
      `   ${pc.dim(`${d.persisting.length} persisting`)}`,
  );
  for (const f of sortFindings(d.added)) {
    const tag = f.state === "proven" ? colorSev(f.severity, SEV_LABEL[f.severity]) : grey("LEAD");
    lines.push(`  ${red("NEW")} ${tag}  ${f.title}  ${pc.dim(f.location)}`);
  }
  for (const e of d.fixed) {
    lines.push(`  ${amber("FIXED")}  ${e.title}`);
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
