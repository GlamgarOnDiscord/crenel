// Core domain types shared across the harness.
//
// A Bastion run turns a declared target into a list of Findings. Every finding
// that claims a real weakness must carry Proof: something a human (or CI) can
// replay. Findings without proof are reported as "unproven" and never gate a
// build, because the research is clear that un-validated agent findings are
// mostly false positives.

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type FindingState =
  | "proven" // validated by a deterministic check or a replayable probe
  | "unproven" // surfaced, but no proof was produced; treat as a lead, not a fact
  | "fixed"; // previously proven, now no longer reproducible

export interface Proof {
  /** How the finding was confirmed, in one line. */
  method: string;
  /** A command, request, or file:line a human can replay to see it. */
  replay: string;
  /** Raw evidence captured at detection time (truncated for the report). */
  evidence?: string;
}

export interface Finding {
  /** Stable id, so the same issue keeps its identity across runs. */
  id: string;
  check: string;
  title: string;
  severity: Severity;
  state: FindingState;
  /** Where it lives: a file path, a URL, a resource name. */
  location: string;
  description: string;
  remediation: string;
  proof?: Proof;
  /** Maps to a regression test the team should add once the fix lands. */
  regressionHint?: string;
}

export interface CheckContext {
  /** The validated, scope-guarded target for this run. */
  readonly scope: import("./scope.js").Scope;
  /** Absolute path of the project being scanned (for filesystem checks). */
  readonly projectDir: string;
  /** Opt-in network base URL (staging only); undefined means offline. */
  readonly stagingUrl?: string;
  /** Per-check options from the config file, keyed by check name. */
  readonly options: Record<string, unknown>;
  /** Logger that respects the CLI verbosity. */
  log: (msg: string) => void;
}

export interface Check {
  /** Short machine name, e.g. "exposed-secrets". */
  name: string;
  /** One-line human description, shown in --list. */
  title: string;
  /**
   * True when this check only reads (files, HTTP GET of own assets). A check
   * that is not read-only must declare it, and the scope guard blocks it unless
   * the config explicitly allows active testing.
   */
  readOnly: boolean;
  run(ctx: CheckContext): Promise<Finding[]>;
}
