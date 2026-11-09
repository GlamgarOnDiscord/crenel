// Optional model access through the local Claude CLI (`claude -p`), the same
// path as triage.ts. Crenel never needs it: without a model, every scan, probe,
// validator and goal check still runs, because none of them depends on one.
//
// Portable on purpose: the prompt goes on stdin (no shell quoting, no argv
// length limit), and on Windows the CLI is the `claude.cmd` shim, which Node
// only spawns through a shell; stdin keeps the prompt out of that command line.

import { spawn } from "node:child_process";
import { z } from "zod";

export interface LlmCall {
  signal?: AbortSignal;
  timeoutMs?: number;
}
export interface Llm {
  /** Short name shown in the UI, e.g. "claude -p (opus-4-8)". */
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
    // The CLI prints some errors (API errors, refused input) on stdout: keep its tail too.
    child.on("close", (code) => (code === 0 ? resolve(out.trim()) : reject(new Error(`claude exited ${code}: ${(err.trim() || out.trim().slice(-300)).slice(0, 300)}`))));
    child.stdin.end(input);
  });
}

// Only Claude models go through claude -p. Other entries of the console's
// model menu are not wired: asking for them returns null and the run says so.
// Each console id maps to what `claude --model` receives: an alias for the
// latest of a line, or a full model id when a specific version is pinned.
// Opus 4.8 is the default: Opus 5.5 runs broader safety classifiers (cyber
// among them), which a security tool trips more often.
export const DEFAULT_MODEL = "opus-4-8";
const CLAUDE_MODELS: Record<string, string> = {
  "opus-4-8": "claude-opus-4-8",
  opus: "opus",
  sonnet: "sonnet",
  haiku: "haiku",
};

export function claudeCli(model = DEFAULT_MODEL): Llm | null {
  const cliModel = CLAUDE_MODELS[model];
  if (!cliModel) return null;
  return {
    label: `claude -p (${model})`,
    ask: (prompt, call) => runCli(["-p", "--model", cliModel], prompt, call),
  };
}

/* ---------------- custom / local model providers ---------------- */
//
// Same `Llm` interface as claude -p, so the exploration loop never changes. All
// three speak HTTP with the global fetch (Node 22). Keys come ONLY from the
// environment (never the config, never argv, never a log): a provider reads
// process.env[apiKeyEnv] at call time and puts it in a header, nowhere else.

// An env var name, upper case. The config may name the var that holds a key, it
// may never hold the key itself (same discipline as scope.access in config.ts).
const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/;
const DEFAULT_OLLAMA_BASE = "http://127.0.0.1:11434";
const DEFAULT_ANTHROPIC_BASE = "https://api.anthropic.com";
const ANTHROPIC_VERSION = "2023-06-01";

// One AbortSignal that fires on the caller's signal OR after timeoutMs, mirroring
// runCli's `timeout`. Manual (no AbortSignal.any) so typing stays on @types/node.
function withTimeout(call: LlmCall): { signal: AbortSignal; done: () => void } {
  const ctrl = new AbortController();
  const onAbort = () => ctrl.abort((call.signal as AbortSignal & { reason?: unknown })?.reason);
  if (call.signal) {
    if (call.signal.aborted) ctrl.abort((call.signal as AbortSignal & { reason?: unknown }).reason);
    else call.signal.addEventListener("abort", onAbort, { once: true });
  }
  const t = setTimeout(() => ctrl.abort(new Error("timed out")), call.timeoutMs ?? 120_000);
  return { signal: ctrl.signal, done: () => { clearTimeout(t); call.signal?.removeEventListener("abort", onAbort); } };
}

// POST JSON and parse JSON back, with the same clear-error discipline as runCli:
// a non-2xx, a connection failure, or a body that is not JSON each throw a short
// labelled message; the response body is truncated and never assumed well-formed.
async function postJson(url: string, headers: Record<string, string>, body: unknown, call: LlmCall, label: string): Promise<unknown> {
  const { signal, done } = withTimeout(call);
  let res: Response;
  try {
    res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body), signal });
  } catch (e) {
    throw new Error(`${label} request failed: ${(e as Error).message}`);
  } finally { done(); }
  const text = await res.text();
  if (!res.ok) throw new Error(`${label} HTTP ${res.status}: ${text.trim().slice(0, 300)}`);
  try { return JSON.parse(text); } catch { throw new Error(`${label} returned invalid JSON: ${text.trim().slice(0, 200)}`); }
}

const pick = (o: unknown, ...keys: (string | number)[]): unknown => keys.reduce<unknown>((v, k) => (v == null ? v : (v as Record<string | number, unknown>)[k]), o);

/**
 * OpenAI-compatible chat endpoint: POST <baseUrl><path> with {model,messages,...},
 * reads choices[0].message.content. Covers Ollama, LM Studio, vLLM, llama.cpp
 * server, OpenRouter and local gateways. apiKeyEnv (optional): name of the env var
 * holding a Bearer key; local servers need none. Default base: Ollama's port.
 */
export function openAiCompatibleLlm(model: string, opts: { baseUrl?: string; apiKeyEnv?: string; path?: string; temperature?: number } = {}): Llm {
  const base = (opts.baseUrl ?? DEFAULT_OLLAMA_BASE).replace(/\/+$/, "");
  const url = base + (opts.path ?? "/v1/chat/completions");
  return {
    label: `openai (${model} @ ${base})`,
    async ask(prompt, call = {}) {
      const headers: Record<string, string> = {};
      const key = opts.apiKeyEnv ? process.env[opts.apiKeyEnv] : undefined;
      if (key) headers.authorization = `Bearer ${key}`;
      const body: Record<string, unknown> = { model, messages: [{ role: "user", content: prompt }], stream: false };
      if (opts.temperature !== undefined) body.temperature = opts.temperature;
      const json = await postJson(url, headers, body, call, "openai-compatible");
      const content = pick(json, "choices", 0, "message", "content");
      if (typeof content !== "string") throw new Error("openai-compatible: no choices[0].message.content in the response");
      return content.trim();
    },
  };
}

/** Native Ollama generate endpoint: POST <baseUrl>/api/generate, reads .response. */
export function ollamaLlm(model: string, opts: { baseUrl?: string } = {}): Llm {
  const base = (opts.baseUrl ?? DEFAULT_OLLAMA_BASE).replace(/\/+$/, "");
  const url = base + "/api/generate";
  return {
    label: `ollama (${model} @ ${base})`,
    async ask(prompt, call = {}) {
      const json = await postJson(url, {}, { model, prompt, stream: false }, call, "ollama");
      const resp = pick(json, "response");
      if (typeof resp !== "string") throw new Error("ollama: no .response in the response");
      return resp.trim();
    },
  };
}

/**
 * Anthropic Messages API directly (not the CLI): POST <baseUrl>/v1/messages with
 * x-api-key + anthropic-version, reads content[0].text. Key via env only
 * (apiKeyEnv, default ANTHROPIC_API_KEY); a missing var throws before any request.
 */
export function anthropicApiLlm(model: string, opts: { apiKeyEnv?: string; baseUrl?: string; maxTokens?: number } = {}): Llm {
  const base = (opts.baseUrl ?? DEFAULT_ANTHROPIC_BASE).replace(/\/+$/, "");
  const url = base + "/v1/messages";
  const keyEnv = opts.apiKeyEnv ?? "ANTHROPIC_API_KEY";
  return {
    label: `anthropic-api (${model})`,
    async ask(prompt, call = {}) {
      const key = process.env[keyEnv];
      if (!key) throw new Error(`anthropic-api: environment variable ${keyEnv} is not set`);
      const headers = { "x-api-key": key, "anthropic-version": ANTHROPIC_VERSION };
      const body = { model, max_tokens: opts.maxTokens ?? 4096, messages: [{ role: "user", content: prompt }] };
      const json = await postJson(url, headers, body, call, "anthropic-api");
      const text = pick(json, "content", 0, "text");
      if (typeof text !== "string") throw new Error("anthropic-api: no content[0].text in the response");
      return text.trim();
    },
  };
}

/** options.llm in the config: provider, model and connection, never a key value. */
export const LlmOptions = z.object({
  provider: z.enum(["claude-cli", "openai", "ollama", "anthropic-api"]).optional(),
  model: z.string().min(1).optional(),
  baseUrl: z.string().url().optional(),
  apiKeyEnv: z.string().regex(ENV_NAME, "nom de variable d'environnement attendu (ex. CRENEL_LLM_API_KEY), jamais la valeur").optional(),
  temperature: z.number().min(0).max(2).optional(),
  path: z.string().max(256).optional(),
  maxTokens: z.number().int().min(1).max(200_000).optional(),
}).strict();
export type LlmConfig = z.infer<typeof LlmOptions>;

/**
 * Turn a `--model` spec into an Llm, without touching the exploration loop.
 * No ":" -> the claude CLI (opus|sonnet|haiku), unchanged; unknown CLI model -> null.
 * "openai:<m>" / "ollama:<m>" / "anthropic-api:<m>" -> the matching provider.
 * Unknown provider or empty model -> null. Keys never come through `opts`, only
 * the NAME of their env var (apiKeyEnv).
 */
export function resolveLlm(spec: string, opts: { baseUrl?: string; apiKeyEnv?: string; temperature?: number; path?: string; maxTokens?: number } = {}): Llm | null {
  const idx = spec.indexOf(":");
  if (idx < 0) return claudeCli(spec);
  const provider = spec.slice(0, idx);
  const model = spec.slice(idx + 1);
  if (!model) return null;
  switch (provider) {
    case "openai": return openAiCompatibleLlm(model, { baseUrl: opts.baseUrl, apiKeyEnv: opts.apiKeyEnv ?? "CRENEL_LLM_API_KEY", path: opts.path, temperature: opts.temperature });
    case "ollama": return ollamaLlm(model, { baseUrl: opts.baseUrl });
    case "anthropic-api": return anthropicApiLlm(model, { apiKeyEnv: opts.apiKeyEnv ?? "ANTHROPIC_API_KEY", baseUrl: opts.baseUrl, maxTokens: opts.maxTokens });
    default: return null;
  }
}

/**
 * The explore command's model choice: the `--model` spec (and `--model-base-url`,
 * `--model-api-key-env`) win, falling back to options.llm from the config. Returns
 * the Llm (or null when the spec is unrecognised), whether it is the CLI path (the
 * caller then checks the CLI is installed), and a config error when options.llm is
 * malformed. Default, when nothing is set: the claude CLI with `sonnet`.
 */
export function selectLlm(input: { spec?: string; baseUrl?: string; apiKeyEnv?: string; config?: unknown }): { llm: Llm | null; usesCli: boolean; error?: string } {
  let cfg: LlmConfig = {};
  if (input.config !== undefined) {
    const r = LlmOptions.safeParse(input.config);
    if (!r.success) return { llm: null, usesCli: false, error: `options.llm: ${r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")}` };
    cfg = r.data;
  }
  let spec = input.spec;
  if (!spec) {
    if (cfg.provider && cfg.provider !== "claude-cli") {
      if (!cfg.model) return { llm: null, usesCli: false, error: `options.llm: provider ${cfg.provider} requires a model` };
      spec = `${cfg.provider}:${cfg.model}`;
    } else spec = cfg.model ?? "sonnet"; // claude CLI
  }
  const opts = { baseUrl: input.baseUrl ?? cfg.baseUrl, apiKeyEnv: input.apiKeyEnv ?? cfg.apiKeyEnv, temperature: cfg.temperature, path: cfg.path, maxTokens: cfg.maxTokens };
  return { llm: resolveLlm(spec, opts), usesCli: spec.indexOf(":") < 0 };
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

/**
 * A recorded model: answers with `responses` in order, then `{"calls":[],"done":true}`.
 * For tests and the bench (a scripted exploration replayed deterministically, so
 * the harness's tools and validators are measured without spending a model).
 * Every prompt it received is kept in `prompts`.
 */
export function scriptedLlm(responses: string[], label = "scripted"): Llm & { prompts: string[] } {
  const prompts: string[] = [];
  let i = 0;
  return {
    label,
    prompts,
    async ask(prompt, call) {
      call?.signal?.throwIfAborted();
      prompts.push(prompt);
      return responses[i++] ?? '{"calls":[],"done":true}';
    },
  };
}
