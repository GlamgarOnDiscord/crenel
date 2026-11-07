// Goals, like /goal in Claude Code: the user sets an objective and the agent
// keeps working on its own (scan again, probe, generate tests) until the
// objective is met, a budget runs out, the work stalls, or the user stops it.
//
// The objective is checked by deterministic code whenever it can be (conditions
// on findings and generated tests). A free-text goal can only be judged by a
// model, and is then reported as met-but-"unverified", never as verified.
// A goal that needs a human (a code fix) does not spin: two iterations with no
// change in state end it as "stalled", with the state and what is left.

export type GoalKind = "no-proven-critical" | "authz-isolation" | "all-proven-tested" | "free";

export interface GoalBudget {
  /** Agent iterations (one iteration = one plan run). */
  maxIterations: number;
  /** Requests sent through the scoped client, over the whole goal. */
  maxProbes: number;
  /** Wall clock, over the whole goal. */
  maxMs: number;
  /** Model tokens (estimated), over the whole goal. */
  maxTokens: number;
}

export const DEFAULT_BUDGET: GoalBudget = { maxIterations: 5, maxProbes: 300, maxMs: 15 * 60_000, maxTokens: 60_000 };

export interface GoalSpec {
  text: string;
  kind: GoalKind;
  budget: GoalBudget;
}

export interface GoalCheck {
  met: boolean;
  /** True when deterministic code decided; false when a model did (or nothing could). */
  verified: boolean;
  detail: string;
  /** A fingerprint of the state, to detect iterations that change nothing. */
  state: string;
}

export type GoalOutcome = "met" | "met-unverified" | "budget" | "stalled" | "stopped" | "unverifiable";

export interface GoalUsage { probes: number; tokens: number }

/** Map the user's words to a goal kind. Deterministic and boring on purpose. */
export function parseGoal(text: string, budget: Partial<GoalBudget> = {}): GoalSpec {
  const t = text.toLowerCase();
  const kind: GoalKind =
    /critique|critical/.test(t) ? "no-proven-critical"
    : /isolation|entre comptes|cross-tenant|tenant|authz|autorisation/.test(t) ? "authz-isolation"
    : /gard|\bci\b|test/.test(t) ? "all-proven-tested"
    : "free";
  return { text: text.trim(), kind, budget: { ...DEFAULT_BUDGET, ...budget } };
}

export const GOAL_LABEL: Record<GoalKind, string> = {
  "no-proven-critical": "aucun finding critique prouvé",
  "authz-isolation": "isolation entre comptes prouvée sur toutes les ressources déclarées",
  "all-proven-tested": "un test de régression généré pour chaque faille prouvée",
  free: "objectif libre (jugé par le modèle, non vérifié)",
};

export interface GoalLoopDeps {
  goal: GoalSpec;
  /** Run one iteration of work (a plan run). */
  iterate: (i: number) => Promise<void>;
  /** Check the objective against the current state. */
  evaluate: () => Promise<GoalCheck>;
  /** Usage so far (probes sent, tokens spent), read after each iteration. */
  usage: () => GoalUsage;
  signal: AbortSignal;
  emit: (type: string, data: Record<string, unknown>) => void;
  now?: () => number;
}

/** The loop. Returns how it ended; every step is emitted for the journal and the stream. */
export async function runGoal(d: GoalLoopDeps): Promise<{ outcome: GoalOutcome; iterations: number; last?: GoalCheck }> {
  const now = d.now ?? Date.now;
  const t0 = now();
  const b = d.goal.budget;
  let last: GoalCheck | undefined;
  let unchanged = 0;
  const remaining = (i: number) => {
    const u = d.usage();
    return { iterations: b.maxIterations - i, probes: b.maxProbes - u.probes, ms: b.maxMs - (now() - t0), tokens: b.maxTokens - u.tokens };
  };
  const end = (outcome: GoalOutcome, iterations: number) => {
    d.emit("goal.end", { outcome, iterations, verified: !!last?.verified && outcome === "met", detail: last?.detail ?? "", remaining: remaining(iterations) });
    return { outcome, iterations, last };
  };
  d.emit("goal.start", { text: d.goal.text, kind: d.goal.kind, label: GOAL_LABEL[d.goal.kind], budget: { ...b } });

  // Already met before doing anything? Then there is nothing to do.
  last = await d.evaluate();
  d.emit("goal.check", { iteration: 0, ...last, remaining: remaining(0) });
  if (last.met) return end(last.verified ? "met" : "met-unverified", 0);

  for (let i = 1; ; i++) {
    if (d.signal.aborted) return end("stopped", i - 1);
    const r = remaining(i - 1);
    if (r.iterations <= 0 || r.probes <= 0 || r.ms <= 0 || r.tokens <= 0) return end("budget", i - 1);
    d.emit("goal.iteration", { iteration: i, remaining: r });
    await d.iterate(i);
    if (d.signal.aborted) return end("stopped", i);
    const prev = last;
    last = await d.evaluate();
    d.emit("goal.check", { iteration: i, ...last, remaining: remaining(i) });
    if (last.met) return end(last.verified ? "met" : "met-unverified", i);
    if (d.goal.kind === "free" && !last.verified && last.detail.startsWith("no model")) return end("unverifiable", i);
    unchanged = prev && prev.state === last.state ? unchanged + 1 : 0;
    if (unchanged >= 2) return end("stalled", i);
  }
}
