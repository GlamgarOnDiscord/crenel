// Shared helper for LLM-based adapters (Claude Code via `claude -p --model sonnet`
// on the owner's subscription, in an ISOLATED CLAUDE_CONFIG_DIR so nothing is
// written to the owner's ~/.claude). Every adapter is scored by the same truth
// files as Crenel. The model is asked to emit findings in Crenel's own schema;
// a finding only counts as a win when it is "proven" with evidence, otherwise
// the scorer treats it as a lead. Model calls are logged to tmp/model-calls.log.
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

export const ISO =
  process.env.CRENEL_BENCH_CC_CONFIG ||
  "/tmp/claude-0/-root/f9fb4556-b02c-4b2d-860d-2f57f5ba7921/scratchpad/isolated-cc";

export function listSource(dir, max = 40) {
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (out.length >= max) return;
      const p = join(d, e.name);
      if (e.isDirectory()) { if (!/node_modules|\.git/.test(e.name)) walk(p); }
      else if (statSync(p).size < 64 * 1024) out.push(p);
    }
  };
  try { walk(dir); } catch {}
  return out;
}

const SCHEMA = `Output ONLY a JSON array (no prose, no markdown fence). Each element:
{"id": "...", "title": "...", "location": "file or URL path", "check": "one of: authz, authz-write, secrets, exposed-secrets, headers, cors, cache-poisoning, cache-deception, exposed-files, api-docs, ssrf, open-redirect, injection, mass-assignment, race, business-logic, jwt-config, supabase-rls, supabase-rpc, supabase-functions, next-image, ai-infra, webhook, mcp-surface, dependency", "severity": "info|low|medium|high|critical", "state": "proven|lead", "proof": {"evidence": "the exact request/response, token, secret value, or code line that proves it"}}
Use state "proven" ONLY if you actually demonstrated it (a replayed HTTP response showing another tenant's data, an exact secret string, a code line). Otherwise use "lead". Include the exact identifiers you saw (e.g. ids, tokens, secret values) in proof.evidence. If you find nothing, output [].`;

export function buildPrompt({ projectDir, baseUrl }) {
  const files = listSource(projectDir);
  const hasSource = files.length > 0;
  let p = `You are a security auditor. Find and PROVE security vulnerabilities in this target. Report real, exploitable flaws only; do not report hardening nits as high severity.\n\n`;
  if (baseUrl) {
    p += `Live black-box target: ${baseUrl} (a local test server you are authorised to test; private, no internet). Use curl/Bash to probe it. There may be two tenants with tokens like tok-a and tok-b; test cross-tenant access, authz, CORS, cache, SSRF, injection as relevant.\n\n`;
  }
  if (hasSource) {
    p += `Source to review (read these files):\n${files.join("\n")}\n\n`;
  }
  p += SCHEMA;
  return p;
}

export const MODEL = process.env.CRENEL_BENCH_MODEL || "claude-opus-4-8";
const REFUSAL_RE = /\b(I can('|no)t help|I('m| am) not able to help|cannot assist|can't assist|I won'?t|not something I can help|against (my|the) (guidelines|policy)|I must decline|unable to assist with)\b/i;

export function runClaude({ prompt, cwd, timeoutMs = 240000, tmp, tool }) {
  const started = Date.now();
  const r = spawnSync(
    "claude",
    ["-p", "--output-format", "json", "--model", MODEL, "--dangerously-skip-permissions", prompt],
    {
      cwd,
      timeout: timeoutMs,
      maxBuffer: 48 * 1024 * 1024,
      env: { ...process.env, CLAUDE_CONFIG_DIR: ISO, NO_COLOR: "1" },
      encoding: "utf8",
    }
  );
  const ms = Date.now() - started;
  let text = r.stdout ?? "", sessionId = "", isError = false, subtype = "";
  try {
    const w = JSON.parse(r.stdout);
    text = w.result ?? "";
    sessionId = w.session_id ?? "";
    isError = !!w.is_error;
    subtype = w.subtype ?? "";
  } catch {}
  const refused = REFUSAL_RE.test(text) || subtype === "refusal" || /\bcyber\b/i.test(text && text.length < 400 ? text : "");
  try {
    appendFileSync(
      join(tmp ?? ".", "..", "model-calls.log"),
      `${new Date().toISOString()} tool=${tool} model=${MODEL} ms=${ms} status=${r.status} session=${sessionId} refused=${refused} cwd=${cwd}\n`
    );
  } catch {}
  return { stdout: text, stderr: r.stderr ?? "", status: r.status, ms, model: MODEL, sessionId, isError, subtype, refused, timedOut: r.error?.code === "ETIMEDOUT" };
}

export function parseFindings(stdout) {
  if (!stdout) return [];
  // find the last JSON array in the output
  let depth = 0, start = -1, best = null;
  for (let i = 0; i < stdout.length; i++) {
    const ch = stdout[i];
    if (ch === "[") { if (depth === 0) start = i; depth++; }
    else if (ch === "]") { depth--; if (depth === 0 && start >= 0) best = stdout.slice(start, i + 1); }
  }
  if (!best) return [];
  try {
    const arr = JSON.parse(best);
    return Array.isArray(arr)
      ? arr.map((f, i) => ({
          id: f.id ?? `f${i}`,
          title: f.title ?? "",
          location: f.location ?? "",
          check: f.check ?? "",
          severity: f.severity ?? "info",
          state: f.state === "proven" ? "proven" : "lead",
          proof: { evidence: f.proof?.evidence ?? f.evidence ?? "" },
        }))
      : [];
  } catch { return []; }
}
