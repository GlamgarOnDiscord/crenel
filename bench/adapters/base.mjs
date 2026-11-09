// "Claude Code seul": a plain `claude -p --model sonnet` with no extra tools,
// one pass per case, source + live black-box. Same scorer as every tool.
import { buildPrompt, runClaude, parseFindings } from "./_llm.mjs";

export const name = "base";

export async function run({ projectDir, baseUrl, tmp }) {
  const prompt = buildPrompt({ projectDir, baseUrl });
  const r = runClaude({ prompt, cwd: projectDir, tmp, tool: "base" });
  const findings = parseFindings(r.stdout);
  const errors = [];
  if (r.timedOut) errors.push({ check: "base", message: "claude timed out" });
  if (r.status !== 0 && !findings.length) errors.push({ check: "base", message: `claude exit ${r.status}: ${r.stderr.slice(0, 200)}` });
  return { findings, errors };
}
