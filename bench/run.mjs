#!/usr/bin/env node
// Crenel bench: small multi-tenant targets with ground truth. For every case it
// starts the target (live cases), runs a tool through its adapter, and scores
// the findings against case.json:
//   mustFind     a real flaw the tool should report (with a minimum state/severity)
//   mustNotFlag  a decoy that must not be reported at the forbidden level
// Usage: node bench/run.mjs [--tool crenel] [--case name] [--json out.json]

import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : undefined; };
const tool = await import(pathToFileURL(join(HERE, "adapters", `${opt("tool") ?? "crenel"}.mjs`)).href);

const textOf = (f) => [f.id, f.title, f.location, f.check, f.proof?.evidence].filter(Boolean).join("\n");
const isProven = (f) => f.state === "proven";

function matches(f, rule) {
  if (rule.check && !new RegExp(rule.check, "i").test(f.check ?? "")) return false;
  if (rule.where && !new RegExp(rule.where, "i").test((f.location ?? "").replace(/\\/g, "/"))) return false;
  if (rule.text && !new RegExp(rule.text, "i").test(textOf(f))) return false;
  return true;
}

function score(findings, c) {
  const rows = [];
  for (const r of c.mustFind ?? []) {
    const hits = findings.filter((f) => matches(f, r));
    const ok = hits.some((f) => (r.state !== "proven" || isProven(f)) && (SEV[f.severity] ?? 0) >= (SEV[r.minSeverity ?? "info"]));
    rows.push({ kind: "find", id: r.id, ok, got: hits.map((f) => `${f.state}/${f.severity}`).join(", ") || "rien", why: r.why });
  }
  for (const r of c.mustNotFlag ?? []) {
    const bad = findings.filter((f) => matches(f, r) && (r.forbid === "any" || (r.forbid === "proven" && isProven(f)) || (r.forbid === "high" && (SEV[f.severity] ?? 0) >= SEV.high)));
    rows.push({ kind: "decoy", id: r.id, ok: bad.length === 0, got: bad.map((f) => `${f.state}/${f.severity}`).join(", ") || "rien", why: r.why });
  }
  return rows;
}

const only = opt("case");
const cases = readdirSync(join(HERE, "cases")).filter((n) => !only || n === only).sort();
const report = { tool: tool.name, at: new Date().toISOString(), cases: [] };

for (const name of cases) {
  const dir = join(HERE, "cases", name);
  const c = JSON.parse(readFileSync(join(dir, "case.json"), "utf8"));
  const tmp = mkdtempSync(join(tmpdir(), `crenel-bench-${name}-`));
  let server, baseUrl;
  try {
    if (c.type === "live") {
      const mod = await import(pathToFileURL(join(dir, "server.mjs")).href);
      server = mod.default();
      await new Promise((r) => server.listen(0, "127.0.0.1", r));
      baseUrl = `http://127.0.0.1:${server.address().port}`;
    }
    // Copy the project so {{BASE}} can point at this run's live target.
    const projectDir = join(tmp, "project");
    if (existsSync(join(dir, "project"))) {
      cpSync(join(dir, "project"), projectDir, { recursive: true });
      if (baseUrl) for (const f of walk(projectDir)) {
        const t = readFileSync(f, "utf8");
        if (t.includes("{{BASE}}")) writeFileSync(f, t.replaceAll("{{BASE}}", baseUrl));
      }
    } else cpSync(join(HERE, "empty"), projectDir, { recursive: true });
    const { findings, errors } = await tool.run({ projectDir, baseUrl, caseConfig: c.config ?? {}, tmp });
    report.cases.push({ name, title: c.title, rows: score(findings, c), errors, findings: findings.length });
  } catch (err) {
    report.cases.push({ name, title: c.title, rows: [], errors: [{ check: "bench", message: err.message }] });
  } finally {
    server?.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

function* walk(d) {
  for (const e of readdirSync(d, { withFileTypes: true })) {
    const p = join(d, e.name);
    if (e.isDirectory()) yield* walk(p); else yield p;
  }
}

// Summary: recall on real flaws, false positives on decoys.
const all = report.cases.flatMap((c) => c.rows);
const finds = all.filter((r) => r.kind === "find"), decoys = all.filter((r) => r.kind === "decoy");
report.summary = { found: finds.filter((r) => r.ok).length, flaws: finds.length, falsePositives: decoys.filter((r) => !r.ok).length, decoys: decoys.length };
if (opt("json")) writeFileSync(opt("json"), JSON.stringify(report, null, 2));

for (const c of report.cases) {
  console.log(`\n${c.name}  ${c.title}`);
  for (const r of c.rows) console.log(`  ${r.ok ? "✓" : "✕"} ${r.kind === "find" ? "faille " : "leurre "} ${r.id.padEnd(24)} ${r.got}`);
  for (const e of c.errors ?? []) console.log(`  ! ${e.check}: ${e.message}`);
}
const s = report.summary;
console.log(`\n${tool.name}: ${s.found}/${s.flaws} failles trouvées, ${s.falsePositives}/${s.decoys} leurres signalés à tort`);
