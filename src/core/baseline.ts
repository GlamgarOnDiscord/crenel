// Baseline and diff. A scan on its own answers "what is wrong now". A baseline
// answers the question that keeps a team honest over time: "what is NEW since we
// last looked, and what did we actually fix". This is the backbone of the
// "every finding becomes a regression you can prove stays fixed" idea.
//
// The baseline is a small, readable JSON snapshot of finding ids and their
// state. We diff by id, so a finding keeps its identity across runs.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import type { Finding } from "./types.js";
import type { RunResult } from "./runner.js";

export interface BaselineEntry {
  id: string;
  check: string;
  severity: Finding["severity"];
  state: Finding["state"];
  title: string;
}

export interface Baseline {
  savedAt: string;
  findings: BaselineEntry[];
}

export interface Diff {
  /** In this run, not in the baseline. The regressions to watch. */
  added: Finding[];
  /** Proven in the baseline, absent now. What the team fixed. */
  fixed: BaselineEntry[];
  /** Present in both. */
  persisting: Finding[];
}

export function toBaseline(result: RunResult): Baseline {
  return {
    savedAt: result.startedAt,
    findings: result.findings.map((f) => ({
      id: f.id,
      check: f.check,
      severity: f.severity,
      state: f.state,
      title: f.title,
    })),
  };
}

export function loadBaseline(path: string): Baseline | null {
  if (!existsSync(path)) return null;
  try {
    const data = JSON.parse(readFileSync(path, "utf8")) as Baseline;
    if (!Array.isArray(data.findings)) return null;
    return data;
  } catch {
    return null;
  }
}

export function saveBaseline(path: string, result: RunResult): void {
  writeFileSync(path, JSON.stringify(toBaseline(result), null, 2));
}

export function diff(result: RunResult, baseline: Baseline): Diff {
  const baseIds = new Map(baseline.findings.map((e) => [e.id, e]));
  const nowIds = new Set(result.findings.map((f) => f.id));
  const added = result.findings.filter((f) => !baseIds.has(f.id));
  const persisting = result.findings.filter((f) => baseIds.has(f.id));
  // Only things that were PROVEN before and are gone now count as "fixed": a
  // lead that merely stopped showing is not a verified fix.
  const fixed = baseline.findings.filter((e) => e.state === "proven" && !nowIds.has(e.id));
  return { added, fixed, persisting };
}

/** A regression is a NEW proven finding at high or critical severity. */
export function hasRegression(d: Diff): boolean {
  return d.added.some((f) => f.state === "proven" && (f.severity === "high" || f.severity === "critical"));
}
