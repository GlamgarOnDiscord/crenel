export type Severity = "crit" | "high" | "med" | "low" | "info";
// proven: a replayable request proves it (danger). lead: a "piste", not proven.
// fixed: corrected. "Gardé" (a regression test in CI) is tracked separately.
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
  guarded?: boolean;
  /** The model's advice (POST /api/findings/:uid/triage), kept by the server. Advice only. */
  advice?: string;
  /** Ignored in the console by the user (accepted risk, false positive): shown apart, never deleted. */
  ignored?: { at: string; reason: string };
}

export interface Target {
  id: string;
  name: string;
  url: string;
  kind: "site" | "repo";
  env: string;
  findings: number;
  proven: number;
  lastScan: string;
}

export type TaskStatus = "running" | "waiting" | "done" | "stopped";
export interface Task {
  id: string;
  title: string;
  target: string;
  when: string;
  trigger: string;
  dur?: string;
  status: TaskStatus;
  proven?: number;
  guarded?: number;
  leads?: number;
  fixed?: number;
  archived?: boolean;
}

export interface InlineFinding { sev: Severity; text: string; state: FindingState; id?: string }

export interface Source { label: string; href: string; kind: string }

export type AgentEvent =
  | { kind: "user"; text: string }
  | { kind: "say"; text: string; sources?: Source[] }
  | { kind: "think"; text: string; dur: string }
  | { kind: "plan"; steps: { tool: string; label: string }[] }
  | {
      kind: "tool"; tool: string; args: string; input: string; lines: string[]; findings?: InlineFinding[]; dur: string;
      code?: { file: string; body: string };
    }
  | { kind: "permission"; tool: string; host: string; requests: string[]; id?: string }
  | { kind: "note"; text: string; tone?: "warn" | "muted" };

export const SEV_LABEL: Record<Severity, string> = {
  crit: "crit", high: "haute", med: "moy.", low: "basse", info: "info",
};
export const SEV_NAME: Record<Severity, string> = {
  crit: "critique", high: "haute", med: "moyenne", low: "basse", info: "information",
};
export const SEV_RANK: Record<Severity, number> = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
