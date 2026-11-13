// Shared helper for LLM-based adapters (Claude Code via `claude -p`, model
// CRENEL_BENCH_MODEL, Opus 4.8 by default, on the owner's subscription, in an
// ISOLATED CLAUDE_CONFIG_DIR so nothing is written to the owner's ~/.claude). Every adapter is scored by the same truth
// files as Crenel. The model is asked to emit findings in Crenel's own schema;
// a finding only counts as a win when it is "proven" with evidence, otherwise
// the scorer treats it as a lead. Model calls are logged to tmp/model-calls.log.
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// The isolated Claude Code config directory (logged in once with
// `CLAUDE_CONFIG_DIR=<dir> claude`). Required: a default path would point at a
// directory that is not logged in on any other machine, and every case would
// then "find nothing" instead of failing.
export const ISO = process.env.CRENEL_BENCH_CC_CONFIG;
export function assertIsolatedConfig() {
  if (!ISO) throw new Error("set CRENEL_BENCH_CC_CONFIG to a logged-in Claude Code config directory (CLAUDE_CONFIG_DIR=<dir> claude, then /login)");
  if (!existsSync(ISO)) throw new Error(`CRENEL_BENCH_CC_CONFIG=${ISO} does not exist`);
}

export function listSource(dir, max = 40) {
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (out.length >= max) return;
      const p = join(d, e.name);
      if (e.isDirectory()) { if (!/node_modules|\.git/.test(e.name)) walk(p); }
      else { try { if (statSync(p).size < 64 * 1024) out.push(p); } catch { /* a dangling symlink: skip it, keep listing */ } }
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

// What the model may run. By default: read the case and curl, nothing else, so a
// prompt-injected case cannot run arbitrary commands on the host. A full shell
// (--dangerously-skip-permissions) only with CRENEL_BENCH_ALLOW_SHELL=1, inside a
// sandbox (container or VM with egress limited to the bench targets).
export function permissionArgs(env = process.env) {
  if (env.CRENEL_BENCH_ALLOW_SHELL === "1") return ["--dangerously-skip-permissions"];
  return ["--allowedTools", "Read,Grep,Glob,Bash(curl:*)"];
}

// Asynchronous: the live targets are served by this same process, so a blocking
// spawn would leave the model's curl probes without an answer.
function spawnAsync(cmd, args, { cwd, timeout, env, maxBuffer, signal }) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"], detached: process.platform !== "win32" });
    let stdout = "", stderr = "", timedOut = false, size = 0;
    const killTree = (kind) => {
      if (!child.pid) return;
      if (process.platform === "win32") spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], { stdio: "ignore", windowsHide: true }).unref();
      else { try { process.kill(-child.pid, kind); } catch { child.kill(kind); } }
    };
    const take = (which) => (d) => { size += d.length; if (size > maxBuffer) { killTree("SIGKILL"); return; } if (which === "out") stdout += d; else stderr += d; };
    child.stdout.on("data", take("out"));
    child.stderr.on("data", take("err"));
    const abort = () => { killTree("SIGTERM"); setTimeout(() => { if (child.exitCode === null) killTree("SIGKILL"); }, 1_000).unref(); };
    if (signal?.aborted) abort(); else signal?.addEventListener("abort", abort, { once: true });
    const t = setTimeout(() => { timedOut = true; killTree("SIGKILL"); }, timeout);
    child.on("error", (e) => { clearTimeout(t); signal?.removeEventListener("abort", abort); resolve({ stdout, stderr: stderr + String(e.message), status: null, timedOut }); });
    child.on("close", (status) => { clearTimeout(t); signal?.removeEventListener("abort", abort); resolve({ stdout, stderr, status, timedOut }); });
  });
}

export async function runClaude({ prompt, cwd, timeoutMs = 240000, tmp, tool, signal }) {
  const started = Date.now();
  const r = await spawnAsync(
    "claude",
    ["-p", "--output-format", "json", "--model", MODEL, ...permissionArgs(), prompt],
    { cwd, timeout: timeoutMs, maxBuffer: 48 * 1024 * 1024, env: { ...process.env, CLAUDE_CONFIG_DIR: ISO, NO_COLOR: "1" }, signal }
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
  return { stdout: text, stderr: r.stderr ?? "", status: r.status, ms, model: MODEL, sessionId, isError, subtype, refused, timedOut: r.timedOut };
}

export function parseFindings(stdout) {
  if (!stdout) return [];
  // Find the last top-level JSON array in the output. Brackets inside JSON
  // strings (an evidence line quoting "[x" or a regex) are skipped, otherwise
  // one unbalanced bracket in a proof dropped every finding of the case.
  let depth = 0, start = -1, best = null, inStr = false, esc = false;
  for (let i = 0; i < stdout.length; i++) {
    const ch = stdout[i];
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') { if (depth > 0) inStr = true; continue; }
    if (ch === "[") { if (depth === 0) start = i; depth++; }
    else if (ch === "]" && depth > 0) { depth--; if (depth === 0 && start >= 0) best = stdout.slice(start, i + 1); }
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
          // "proven" with no evidence is only a claim: scored as a lead, as the header says.
          state: f.state === "proven" && String(f.proof?.evidence ?? f.evidence ?? "").trim() ? "proven" : "lead",
          proof: { evidence: f.proof?.evidence ?? f.evidence ?? "" },
        }))
      : [];
  } catch { return []; }
}
