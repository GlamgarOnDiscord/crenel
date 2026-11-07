export type Severity = "crit" | "high" | "med" | "low" | "info";
export type FindingState = "proven" | "lead" | "fixed";

export interface Finding {
  id: string;
  sev: Severity;
  title: string;
  location: string;
  state: FindingState;
  seen: string;
  check: string;
  description: string;
  remediation: string;
  proof?: { method: string; replay: string; evidence?: string };
  regression?: string;
}

export interface Target {
  id: string;
  name: string;
  url: string;
  env: string;
  findings: number;
  proven: number;
  lastScan: string;
}

export interface Activity {
  kind: "bad" | "good" | "brand" | "info";
  title: string;
  meta: string;
}

export type StepKind = "think" | "tool" | "assistant";
export interface ScanStep {
  kind: StepKind;
  label: string;
  dur?: string;
  tool?: string;
  body?: string;
  status?: "ok" | "run";
}

export const SEV_LABEL: Record<Severity, string> = {
  crit: "crit", high: "high", med: "med", low: "low", info: "info",
};
export const SEV_RANK: Record<Severity, number> = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
