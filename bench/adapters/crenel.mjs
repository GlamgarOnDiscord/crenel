// Adapter for Crenel itself: runs the CLI from this repo against one case and
// returns its findings unchanged. Other tools get their own adapter with the
// same signature, so every tool is scored by the same truth files.
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("../..", import.meta.url));

export const name = "crenel";

export async function run({ projectDir, baseUrl, caseConfig, tmp, signal }) {
  const started = Date.now();
  const host = baseUrl ? new URL(baseUrl).hostname : "127.0.0.1";
  const config = {
    project: "bench",
    projectDir,
    scope: {
      allowedHosts: [host],
      allowActiveTesting: !!baseUrl,
      allowPrivate: !!baseUrl, // the targets are local bench servers we own
      ...(baseUrl ? { stagingUrl: baseUrl } : {}),
    },
    checks: [],
    options: caseConfig.options ?? {},
  };
  const cfgPath = join(tmp, "crenel.config.yaml");
  writeFileSync(cfgPath, JSON.stringify(config, null, 2)); // JSON is valid YAML
  // A case may set env vars for its own fixture accounts (a login's passwordEnv): never in the config.
  const env = caseConfig.env ?? {};
  const out = await exec(process.execPath, ["--import", "tsx", join(REPO, "src/cli.ts"), "scan", "--config", cfgPath, "--json"], REPO, env, signal);
  const start = out.stdout.indexOf("{");
  if (start < 0) throw new Error(`crenel produced no JSON (exit ${out.code}): ${out.stderr.slice(0, 400)}`);
  const result = JSON.parse(out.stdout.slice(start));
  const findings = result.findings ?? [];
  const errors = result.errors ?? [];
  let explorationRequests = 0;
  // A case with a recorded exploration (explore.script) also runs `crenel explore`
  // on it, replaying the model's moves: the validators decide, as with a live model.
  if (caseConfig.explore?.script) {
    const script = join(tmp, "explore.script.json");
    writeFileSync(script, JSON.stringify(caseConfig.explore.script));
    const ex = await exec(process.execPath, ["--import", "tsx", join(REPO, "src/cli.ts"), "explore", "--config", cfgPath, "--json", "--llm-script", script, "--state", join(tmp, "state")], REPO, env, signal);
    const at = ex.stdout.indexOf("{");
    if (at < 0) errors.push({ check: "explore", message: `no JSON (exit ${ex.code}): ${ex.stderr.slice(0, 300)}` });
    else {
      const explored = JSON.parse(ex.stdout.slice(at));
      findings.push(...(explored.findings ?? []));
      explorationRequests = explored.requests ?? 0;
    }
  }
  const scanRequests = result.requests ?? 0;
  return { findings, errors, metadata: { durationMs: Date.now() - started, scanDurationMs: result.durationMs, requests: scanRequests + explorationRequests, scanRequests, explorationRequests, checksRun: result.checksRun?.length } };
}

function exec(cmd, args, cwd, env = {}, signal) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { cwd, env: { ...process.env, ...env, NO_COLOR: "1" } });
    let stdout = "", stderr = "";
    const abort = () => { p.kill("SIGTERM"); setTimeout(() => { if (p.exitCode === null) p.kill("SIGKILL"); }, 1_000).unref(); };
    if (signal?.aborted) abort(); else signal?.addEventListener("abort", abort, { once: true });
    p.stdout.on("data", (d) => (stdout += d));
    p.stderr.on("data", (d) => (stderr += d));
    p.on("close", (code) => { signal?.removeEventListener("abort", abort); resolve({ code, stdout, stderr }); });
  });
}
