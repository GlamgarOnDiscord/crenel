// "Claude Code seul": a plain `claude -p` (model CRENEL_BENCH_MODEL) with no
// extra tools, one pass per case, source + live black-box. Same scorer as every tool.
import { assertIsolatedConfig, buildPrompt, runClaude, parseFindings } from "./_llm.mjs";

export const name = "base";

export async function run({ projectDir, baseUrl, tmp, signal }) {
  assertIsolatedConfig();
  const prompt = buildPrompt({ projectDir, baseUrl });
  const r = await runClaude({ prompt, cwd: projectDir, tmp, tool: "base", signal });
  const findings = parseFindings(r.stdout);
  const errors = [];
  if (r.timedOut) errors.push({ check: "base", message: "claude timed out" });
  // A refusal is not "found nothing": it is reported, so a low score from a
  // safety classifier is not read as a weak model.
  if (r.refused) errors.push({ check: "base", message: `refused by the model (${r.subtype || "refusal text"})` });
  else if (r.isError) errors.push({ check: "base", message: `claude reported an error (${r.subtype || "is_error"})` });
  if (r.status !== 0 && !findings.length) errors.push({ check: "base", message: `claude exit ${r.status}: ${r.stderr.slice(0, 200)}` });
  return { findings, errors };
}
