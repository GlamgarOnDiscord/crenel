// Adapter for Crenel itself: runs the CLI from this repo against one case and
// returns its findings unchanged. Other tools get their own adapter with the
// same signature, so every tool is scored by the same truth files.
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("../..", import.meta.url));

export const name = "crenel";

export async function run({ projectDir, baseUrl, caseConfig, tmp }) {
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
  const out = await exec(process.execPath, ["--import", "tsx", join(REPO, "src/cli.ts"), "scan", "--config", cfgPath, "--json"], REPO);
  const start = out.stdout.indexOf("{");
  if (start < 0) throw new Error(`crenel produced no JSON (exit ${out.code}): ${out.stderr.slice(0, 400)}`);
  const result = JSON.parse(out.stdout.slice(start));
  return { findings: result.findings ?? [], errors: result.errors ?? [] };
}

function exec(cmd, args, cwd) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { cwd, env: { ...process.env, NO_COLOR: "1" } });
    let stdout = "", stderr = "";
    p.stdout.on("data", (d) => (stdout += d));
    p.stderr.on("data", (d) => (stderr += d));
    p.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}
