import { test } from "node:test";
import assert from "node:assert/strict";
import { parseGoal, runGoal, type GoalCheck } from "./goal.js";

function harness(checks: GoalCheck[], opts: { probesPerIter?: number; abortAt?: number; budget?: Parameters<typeof parseGoal>[1] } = {}) {
  const ac = new AbortController();
  const events: string[] = [];
  let probes = 0;
  let iters = 0;
  let evals = 0;
  return {
    events,
    get iters() { return iters; },
    run: () => runGoal({
      goal: parseGoal("aucun finding critique prouvé", opts.budget),
      signal: ac.signal,
      emit: (t) => events.push(t),
      usage: () => ({ probes, tokens: 0 }),
      iterate: async (i) => {
        iters = i;
        probes += opts.probesPerIter ?? 0;
        if (opts.abortAt === i) ac.abort();
      },
      evaluate: async () => checks[Math.min(evals++, checks.length - 1)]!,
    }),
  };
}
const c = (met: boolean, state: string): GoalCheck => ({ met, verified: true, detail: state, state });

test("parses the built-in goals deterministically", () => {
  assert.equal(parseGoal("aucun finding critique prouvé sur acme-app").kind, "no-proven-critical");
  assert.equal(parseGoal("prouver l'isolation entre comptes sur toutes les ressources").kind, "authz-isolation");
  assert.equal(parseGoal("100 % des failles prouvées gardées en CI").kind, "all-proven-tested");
  assert.equal(parseGoal("rendre le site plus sûr").kind, "free");
});

test("stops as soon as the objective is met, verified", async () => {
  const h = harness([c(false, "a"), c(false, "b"), c(true, "c")]);
  const r = await h.run();
  assert.equal(r.outcome, "met");
  assert.equal(r.iterations, 2);
  assert.deepEqual(h.events.filter((e) => e === "goal.iteration").length, 2);
  assert.equal(h.events.at(-1), "goal.end");
});

test("does nothing when the objective already holds", async () => {
  const h = harness([c(true, "x")]);
  assert.deepEqual((await h.run()).outcome, "met");
  assert.equal(h.iters, 0);
});

test("stops when the iteration budget runs out", async () => {
  const h = harness([c(false, "1"), c(false, "2"), c(false, "3"), c(false, "4")], { budget: { maxIterations: 3 } });
  const r = await h.run();
  assert.equal(r.outcome, "budget");
  assert.equal(r.iterations, 3);
});

test("stops when the probe budget runs out", async () => {
  const h = harness([c(false, "1"), c(false, "2"), c(false, "3")], { probesPerIter: 60, budget: { maxProbes: 100, maxIterations: 10 } });
  const r = await h.run();
  assert.equal(r.outcome, "budget");
  assert.equal(r.iterations, 2);
});

test("stops when interrupted, without another iteration", async () => {
  const h = harness([c(false, "1"), c(false, "2"), c(false, "3")], { abortAt: 1, budget: { maxIterations: 10 } });
  const r = await h.run();
  assert.equal(r.outcome, "stopped");
  assert.equal(h.iters, 1);
});

test("a goal that needs a human fix stalls instead of spinning", async () => {
  const h = harness([c(false, "same")], { budget: { maxIterations: 10 } });
  const r = await h.run();
  assert.equal(r.outcome, "stalled");
  assert.equal(r.iterations, 2);
});

test("a model's 'met' is reported as unverified", async () => {
  const h = harness([{ met: true, verified: false, detail: "model says so", state: "m" }]);
  assert.equal((await h.run()).outcome, "met-unverified");
});
