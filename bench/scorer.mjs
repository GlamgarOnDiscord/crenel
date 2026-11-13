// Tool-neutral benchmark scorer. Ground-truth rules are matched one-to-one: a
// broad finding cannot earn credit for several distinct flaws.

export const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export const textOf = (f) => [f.id, f.title, f.location, f.check, f.description, f.proof?.evidence].filter(Boolean).join("\n");
export function matches(f, rule) {
  if (rule.check && !new RegExp(rule.check, "i").test(f.check ?? "")) return false;
  if (rule.where && !new RegExp(rule.where, "i").test((f.location ?? "").replace(/\\/g, "/"))) return false;
  if (rule.text && !new RegExp(rule.text, "i").test(textOf(f))) return false;
  return true;
}

const qualifies = (f, rule) => (rule.state !== "proven" || f.state === "proven")
  && (SEV[f.severity] ?? 0) >= (SEV[rule.minSeverity ?? "info"] ?? 0);

/** Maximum one-to-one assignment between mustFind rules and qualifying findings. */
function assign(findings, rules) {
  const eligible = rules.map((rule) => findings.map((f, i) => matches(f, rule) && qualifies(f, rule) ? i : -1).filter((i) => i >= 0));
  const findingToRule = new Map();
  const ruleToFinding = new Map();
  const visit = (rule, seen) => {
    for (const finding of eligible[rule]) {
      if (seen.has(finding)) continue;
      seen.add(finding);
      const occupied = findingToRule.get(finding);
      if (occupied === undefined || visit(occupied, seen)) {
        findingToRule.set(finding, rule);
        ruleToFinding.set(rule, finding);
        return true;
      }
    }
    return false;
  };
  for (let rule = 0; rule < rules.length; rule++) visit(rule, new Set());
  return ruleToFinding;
}

export function score(findings, c) {
  const rows = [], mustFind = c.mustFind ?? [], used = assign(findings, mustFind);
  for (let i = 0; i < mustFind.length; i++) {
    const r = mustFind[i], hits = findings.filter((f) => matches(f, r));
    rows.push({ kind: "find", id: r.id, ok: used.has(i), got: hits.map((f) => `${f.state}/${f.severity}`).join(", ") || "rien", why: r.why });
  }
  for (const r of c.mustNotFlag ?? []) {
    const bad = findings.filter((f) => matches(f, r) && (r.forbid === "any" || (r.forbid === "proven" && f.state === "proven") || (r.forbid === "high" && (SEV[f.severity] ?? 0) >= SEV.high)));
    rows.push({ kind: "decoy", id: r.id, ok: bad.length === 0, got: bad.map((f) => `${f.state}/${f.severity}`).join(", ") || "rien", why: r.why });
  }
  const known = (f) => mustFind.some((r) => matches(f, r)) || (c.mustNotFlag ?? []).some((r) => matches(f, r));
  const unknown = findings.filter((f) => !known(f));
  const unknownHigh = unknown.filter((f) => f.state === "proven" && (SEV[f.severity] ?? 0) >= SEV.high);
  if (Number.isInteger(c.maxUnknownHigh)) rows.push({
    kind: "spam", id: "unknown-high-findings", ok: unknownHigh.length <= c.maxUnknownHigh,
    got: `${unknownHigh.length}/${c.maxUnknownHigh}`, why: "High/critical proven findings outside this case's closed ground truth are penalized.",
  });
  return { rows, unknown: unknown.length, unknownHigh: unknownHigh.length };
}

function hash(seed, value) {
  let h = 2166136261;
  for (const ch of `${seed}\0${value}`) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619); }
  return h >>> 0;
}

/** Reproducible randomized case order. The seed is always written to the report. */
export function seededOrder(names, seed) {
  return [...names].sort((a, b) => hash(seed, a) - hash(seed, b) || a.localeCompare(b));
}

export function summarize(cases) {
  const rows = cases.flatMap((c) => c.rows ?? []);
  const stats = (selected) => {
    const selectedRows = selected.flatMap((c) => c.rows ?? []);
    const finds = selectedRows.filter((r) => r.kind === "find");
    return { found: finds.filter((r) => r.ok).length, flaws: finds.length };
  };
  const discovered = stats(cases.filter((c) => !c.replayed));
  const replay = stats(cases.filter((c) => c.replayed));
  const total = stats(cases);
  const decoys = rows.filter((r) => r.kind === "decoy"), spam = rows.filter((r) => r.kind === "spam");
  return {
    ...total, discovered, replay,
    falsePositives: decoys.filter((r) => !r.ok).length + spam.filter((r) => !r.ok).length,
    decoys: decoys.length, spamPenalties: spam.filter((r) => !r.ok).length,
    unknown: cases.reduce((n, c) => n + (c.unknown ?? 0), 0),
    unknownHigh: cases.reduce((n, c) => n + (c.unknownHigh ?? 0), 0),
    replayed: cases.filter((c) => c.replayed).map((c) => c.name),
    crashed: cases.filter((c) => (c.errors ?? []).some((e) => e.check === "bench")).map((c) => c.name),
    errored: cases.filter((c) => (c.errors ?? []).length > 0).map((c) => c.name),
  };
}
