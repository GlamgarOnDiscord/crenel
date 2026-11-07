// Optional model access through the local Claude CLI (`claude -p`), the same
// path as triage.ts. Crenel never needs it: without a model, every scan, probe,
// validator and goal check still runs, because none of them depends on one.
//
// Portable on purpose: the prompt goes on stdin (no shell quoting, no argv
// length limit), and on Windows the CLI is the `claude.cmd` shim, which Node
// only spawns through a shell; stdin keeps the prompt out of that command line.

import { spawn } from "node:child_process";

export interface LlmCall {
  signal?: AbortSignal;
  timeoutMs?: number;
}
export interface Llm {
  /** Short name shown in the UI, e.g. "claude -p (opus)". */
  label: string;
  ask(prompt: string, call?: LlmCall): Promise<string>;
}

const WIN = process.platform === "win32";

function runCli(args: string[], input: string, call: LlmCall = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(WIN ? "claude.cmd" : "claude", args, {
      shell: WIN, // .cmd shims need a shell on Windows; args here are fixed flags, never user text
      stdio: ["pipe", "pipe", "pipe"],
      signal: call.signal,
      timeout: call.timeoutMs ?? 120_000,
      windowsHide: true,
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => { if (out.length < 1_000_000) out += d; });
    child.stderr.on("data", (d) => { if (err.length < 10_000) err += d; });
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(out.trim()) : reject(new Error(`claude exited ${code}: ${err.trim().slice(0, 200)}`))));
    child.stdin.end(input);
  });
}

// Only Claude models go through claude -p. Other entries of the console's
// model menu are not wired: asking for them returns null and the run says so.
const CLAUDE_MODELS = new Set(["opus", "sonnet", "haiku"]);

export function claudeCli(model = "opus"): Llm | null {
  if (!CLAUDE_MODELS.has(model)) return null;
  return {
    label: `claude -p (${model})`,
    ask: (prompt, call) => runCli(["-p", "--model", model], prompt, call),
  };
}

/** True when the Claude CLI answers `--version` within a few seconds. */
export async function detectClaude(): Promise<boolean> {
  try {
    await runCli(["--version"], "", { timeoutMs: 5000 });
    return true;
  } catch {
    return false;
  }
}

/** Rough token estimate for budgets (4 characters per token). */
export const estimateTokens = (s: string) => Math.ceil(s.length / 4);
