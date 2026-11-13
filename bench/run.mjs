#!/usr/bin/env node
// Crenel bench: small multi-tenant targets with ground truth. For every case it
// starts the target (live cases), runs a tool through its adapter, and scores
// the findings against case.json:
//   mustFind     a real flaw the tool should report (with a minimum state/severity)
//   mustNotFlag  a decoy that must not be reported at the forbidden level
// Usage: node bench/run.mjs [--tool crenel] [--case name] [--json out.json]

import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { arch, platform } from "node:process";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { score, seededOrder, summarize } from "./scorer.mjs";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : undefined; };
const has = (k) => args.includes(`--${k}`);
const tool = await import(pathToFileURL(join(HERE, "adapters", `${opt("tool") ?? "crenel"}.mjs`)).href);

const only = opt("case");
const seed = opt("seed") ?? process.env.CRENEL_BENCH_SEED ?? randomBytes(8).toString("hex");
const timeoutMs = Number(opt("timeout-ms") ?? 120_000);
if (!Number.isFinite(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 900_000) throw new Error("--timeout-ms must be between 1000 and 900000");
const cases = seededOrder(readdirSync(join(HERE, "cases")).filter((n) => !only || n === only), seed);
const report = {
  schemaVersion: 2, tool: tool.name, at: new Date().toISOString(), seed, order: cases,
  environment: { node: process.version, platform: platform, arch: arch, ci: !!process.env.CI, commit: process.env.GITHUB_SHA ?? null },
  timeoutMs, cases: [],
};

for (const name of cases) {
  const dir = join(HERE, "cases", name);
  const c = JSON.parse(readFileSync(join(dir, "case.json"), "utf8"));
  const tmp = mkdtempSync(join(tmpdir(), `crenel-bench-${name}-`));
  let server, baseUrl;
  const caseStarted = Date.now();
  const controller = new AbortController();
  const caseTimeoutMs = c.timeoutMs ?? timeoutMs;
  const timeout = setTimeout(() => controller.abort(new Error(`benchmark case timed out after ${caseTimeoutMs} ms`)), caseTimeoutMs);
  try {
    // Setup is inside the deadline too. Adapters receive the same signal and
    // must resolve after terminating children; on timeout we briefly await that
    // cleanup before deleting their temporary directory.
    const operation = (async () => {
      if (c.type === "live") {
        const mod = await import(pathToFileURL(join(dir, "server.mjs")).href);
        server = mod.default();
        await new Promise((r) => server.listen(0, "127.0.0.1", r));
        baseUrl = `http://127.0.0.1:${server.address().port}`;
      }
      const projectDir = join(tmp, "project");
      if (existsSync(join(dir, "project"))) {
        cpSync(join(dir, "project"), projectDir, { recursive: true });
        if (baseUrl) for (const f of walk(projectDir)) {
          const t = readFileSync(f, "utf8");
          if (t.includes("{{BASE}}")) writeFileSync(f, t.replaceAll("{{BASE}}", baseUrl));
        }
      } else cpSync(join(HERE, "empty"), projectDir, { recursive: true });
      return tool.run({ projectDir, baseUrl, caseConfig: c.config ?? {}, tmp, signal: controller.signal });
    })();
    let result;
    try {
      result = await Promise.race([
        operation,
        new Promise((_, reject) => controller.signal.addEventListener("abort", () => reject(controller.signal.reason), { once: true })),
      ]);
    } catch (err) {
      controller.abort(err);
      await Promise.race([operation.catch(() => {}), new Promise((resolve) => setTimeout(resolve, 1_500))]);
      throw err;
    }
    const { findings, errors, metadata, replayed = false } = result;
    // A recorded exploration replays an answer the case's author wrote: it checks
    // that the harness turns those moves into a proof, not that anything was
    // discovered. Kept in the score, and named in the summary.
    const scored = score(findings, c);
    report.cases.push({ name, title: c.title, rows: scored.rows, errors, findings: findings.length, unknown: scored.unknown, unknownHigh: scored.unknownHigh, replayed, durationMs: Date.now() - caseStarted, metadata });
  } catch (err) {
    // A case that crashes still counts: every flaw it holds is a miss. Dropping
    // its rows would shrink the denominator and raise the recall. Its decoys
    // are left out (nothing ran, so nothing was flagged or cleared).
    const rows = (c.mustFind ?? []).map((r) => ({ kind: "find", id: r.id, ok: false, got: "erreur", why: r.why }));
    report.cases.push({ name, title: c.title, rows, errors: [{ check: "bench", message: err.message }], replayed: false, durationMs: Date.now() - caseStarted });
  } finally {
    clearTimeout(timeout);
    controller.abort();
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
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
report.summary = summarize(report.cases);
if (opt("json")) writeFileSync(opt("json"), JSON.stringify(report, null, 2));

for (const c of report.cases) {
  console.log(`\n${c.name}  ${c.title}`);
  for (const r of c.rows) console.log(`  ${r.ok ? "✓" : "✕"} ${r.kind === "find" ? "faille " : r.kind === "spam" ? "pénalité" : "leurre "} ${r.id.padEnd(24)} ${r.got}`);
  for (const e of c.errors ?? []) console.log(`  ! ${e.check}: ${e.message}`);
}
const s = report.summary;
console.log(`\n${tool.name}: découverte ${s.discovered.found}/${s.discovered.flaws}, validation rejouée ${s.replay.found}/${s.replay.flaws}, ${s.falsePositives - s.spamPenalties}/${s.decoys} leurres, ${s.spamPenalties} pénalité(s) spam`);
console.log(`  total audit : ${s.found}/${s.flaws}; findings hors vérité terrain : ${s.unknown} (${s.unknownHigh} proven high/critical); seed : ${seed}`);
if (s.replayed.length) console.log(`  dont rejoué depuis une exploration enregistrée (pas une découverte) : ${s.replayed.join(", ")}`);
if (s.crashed.length) console.log(`  cas en erreur, comptés comme ratés : ${s.crashed.join(", ")}`);
// A crash is a failure of the bench run itself, so CI sees it.
if (s.crashed.length || (has("strict") && (s.found !== s.flaws || s.falsePositives > 0 || s.errored.length > 0))) process.exitCode = 1;
