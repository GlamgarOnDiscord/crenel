import { test } from "node:test";
import assert from "node:assert/strict";
import { score, seededOrder, summarize } from "./scorer.mjs";

const finding = (over = {}) => ({ id: "broad", check: "authz", title: "two flaws", location: "/a/b", state: "proven", severity: "critical", ...over });

test("one finding cannot satisfy two ground-truth flaws", () => {
  const c = { mustFind: [{ id: "a", check: "authz", state: "proven" }, { id: "b", check: "authz", state: "proven" }] };
  const rows = score([finding()], c).rows;
  assert.equal(rows.filter((r) => r.ok).length, 1);
  assert.equal(score([finding({ id: "a" }), finding({ id: "b" })], c).rows.filter((r) => r.ok).length, 2);
});

test("closed-world cases penalize unknown proven high findings, not review leads", () => {
  const c = { mustFind: [], mustNotFlag: [], maxUnknownHigh: 0 };
  assert.equal(score([finding()], c).rows[0].ok, false);
  assert.equal(score([finding({ state: "unproven", severity: "medium" })], c).rows[0].ok, true);
});

test("seeded order is reproducible and replay validation is outside discovery recall", () => {
  assert.deepEqual(seededOrder(["a", "b", "c", "d"], "seed"), seededOrder(["d", "c", "b", "a"], "seed"));
  const s = summarize([
    { name: "direct", replayed: false, rows: [{ kind: "find", ok: true }] },
    { name: "script", replayed: true, rows: [{ kind: "find", ok: true }] },
  ]);
  assert.deepEqual(s.discovered, { found: 1, flaws: 1 });
  assert.deepEqual(s.replay, { found: 1, flaws: 1 });
  assert.equal(s.found, 2);
});
