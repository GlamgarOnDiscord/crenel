// One toolbox tool, end to end: options -> confined run -> adapter -> validators.
//
// Used by `crenel tools <name>` and by the agent loop. Returns leads, the
// verdicts of the validators that could replay some of them, and the egress
// events of the proxy (each one also appended to the audit JSONL by the caller).

import { z } from "zod";
import type { Config } from "../core/config.js";
import { Scope } from "../core/scope.js";
import type { ProxyEvent } from "../core/egress-proxy.js";
import type { Check, Finding } from "../core/types.js";
import { validateClaim, type Claim, type ClaimVerdict } from "../agent/validators.js";
import type { Untrusted } from "../agent/untrusted.js";
import { TOOLBOX_IMAGE } from "./docker.js";
import { backendFor, type Backend, type BackendStatus } from "./backend.js";
import { BACKENDS, TOOL_NAMES, type ToolName } from "./names.js";
import { DEFAULT_DISTRO, DISTRO_RE, type WslExec } from "./wsl.js";
import { katanaFindings, parseKatana, parseNuclei, parseTrufflehog, suggestResources, type SuggestedResource, type Route } from "./adapters.js";
import { ALLOWED_TAGS, DENIED_TAGS } from "../../toolbox/nuclei-filter.mjs";

export { TOOL_NAMES, type ToolName } from "./names.js";

export const ToolboxOptions = z.object({
  /** Include the tools in agent runs (full scan). The CLI command works either way. */
  enabled: z.boolean().default(false),
  /** Where the tools run: the Docker image (default) or a WSL distribution (Windows). */
  backend: z.enum(BACKENDS).default("docker"),
  image: z.string().default(TOOLBOX_IMAGE),
  wsl: z.object({
    distro: z.string().regex(DISTRO_RE, "a WSL distribution name (letters, digits, . _ -)").default(DEFAULT_DISTRO),
    /** Address the proxy listens on and the tools dial; auto-detected when omitted. */
    proxyHost: z.string().optional(),
  }).strict().default({ distro: DEFAULT_DISTRO }),
  ratePerSec: z.number().positive().max(50).default(10),
  maxRequests: z.number().int().positive().max(50_000).default(10_000),
  timeoutSec: z.number().int().positive().max(7200).default(1200),
  memory: z.string().regex(/^\d+[mg]$/).default("1g"),
  nuclei: z.object({
    /** Narrow the run to these tags. Must be a subset of Crenel's allowlist: it can only narrow. */
    tags: z.array(z.string()).default([]).refine((t) => t.every((x) => ALLOWED_TAGS.includes(x.toLowerCase())), { message: `tags must be among ${ALLOWED_TAGS.join(", ")}` }),
    /** Extra tags to exclude, on top of Crenel's denylist. Cannot re-allow a denied tag. */
    excludeTags: z.array(z.string()).default([]),
    concurrency: z.number().int().min(1).max(25).default(10),
  }).strict().default({ tags: [], excludeTags: [], concurrency: 10 }),
  katana: z.object({
    depth: z.number().int().min(1).max(5).default(2),
    durationSec: z.number().int().min(10).max(1800).default(120),
  }).strict().default({ depth: 2, durationSec: 120 }),
  trufflehog: z.object({
    /** Deprecated, ignored: trufflehog never verifies. Its leads are replayed by
     *  exposed-secrets, whose opt-in liveness (options.exposed-secrets.verify)
     *  makes one read-only GET per key through Crenel's scoped client. */
    verify: z.boolean().default(false),
    verifyHosts: z.array(z.string().trim().min(1)).default([]),
  }).strict().default({ verify: false, verifyHosts: [] }),
}).strict();
export type ToolboxOptions = z.infer<typeof ToolboxOptions>;

export function toolboxOptions(config: Config): ToolboxOptions {
  const r = ToolboxOptions.safeParse(config.options.toolbox ?? {});
  if (!r.success) throw new Error(`options.toolbox: ${r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")}`);
  return r.data;
}

export interface ToolRunInput {
  tool: ToolName;
  config: Config;
  /** Absolute project directory (mounted read-only for trufflehog). */
  projectDir: string;
  /** The run's scope: hosts, allowPrivate, kill switch, observer. */
  scope: Scope;
  checks: Check[];
  onEvent?: (e: ProxyEvent) => void;
  signal?: AbortSignal;
  /** Overrides for tests (and to reuse a status already read). */
  status?: BackendStatus;
  backend?: Backend;
  wslExec?: WslExec;
}

export interface ToolRunOutput {
  tool: ToolName;
  ran: boolean;
  /** Why it did not run, for a human. */
  reason?: string;
  findings: Finding[];
  verdicts: ClaimVerdict[];
  suggestions: SuggestedResource[];
  routes: Route[];
  raw?: Untrusted;
  exit?: number;
  timedOut?: boolean;
  network?: "none" | "internal+proxy" | "wsl+proxy";
  backend?: "docker" | "wsl";
  proxy?: { requests: number; refused: number };
  stderrTail?: string;
}

export function nucleiArgv(target: string, proxy: string, o: ToolboxOptions, templatesDir = "/opt/nuclei-templates"): string[] {
  const exclude = [...new Set([...DENIED_TAGS, ...o.nuclei.excludeTags.map((t) => t.toLowerCase())])];
  return [
    "nuclei", "-u", target, "-t", `${templatesDir}/http`,
    "-tags", (o.nuclei.tags.length ? o.nuclei.tags.map((t) => t.toLowerCase()) : ALLOWED_TAGS).join(","), "-etags", exclude.join(","), "-pt", "http",
    "-jsonl", "-silent", "-nc", "-omit-raw", "-duc", "-ni", "-no-stdin",
    "-proxy", proxy, "-rl", String(Math.max(1, Math.floor(o.ratePerSec))), "-c", String(o.nuclei.concurrency),
    "-timeout", "10", "-retries", "0", "-mhe", "10",
  ];
}

export function katanaArgv(target: string, proxy: string, o: ToolboxOptions): string[] {
  return [
    "katana", "-u", target, "-d", String(o.katana.depth), "-ct", String(o.katana.durationSec),
    "-fs", "fqdn", "-jsonl", "-silent", "-nc", "-duc", "-ob",
    "-proxy", proxy, "-rl", String(Math.max(1, Math.floor(o.ratePerSec))), "-c", "2", "-p", "1",
    "-timeout", "10", "-retry", "0",
  ];
}

export function trufflehogArgv(projectRoot = "/project"): string[] {
  return ["trufflehog", "filesystem", projectRoot, "--json", "--no-update", "--no-verification"];
}

/** Run one tool. Never throws: a missing Docker or a failed container setup returns ran=false with the reason. */
export async function runTool(i: ToolRunInput): Promise<ToolRunOutput> {
  try {
    return await runToolInner(i);
  } catch (err) {
    return { tool: i.tool, ran: false, reason: `toolbox error: ${(err as Error).message}`, findings: [], verdicts: [], suggestions: [], routes: [] };
  }
}

async function runToolInner(i: ToolRunInput): Promise<ToolRunOutput> {
  const base: ToolRunOutput = { tool: i.tool, ran: false, findings: [], verdicts: [], suggestions: [], routes: [] };
  let o: ToolboxOptions;
  try { o = toolboxOptions(i.config); } catch (err) { return { ...base, reason: (err as Error).message }; }
  const backend = i.backend ?? backendFor(o, { wslExec: i.wslExec });
  const st = i.status ?? (await backend.status());
  base.backend = st.backend;
  const t = st.tools[i.tool];
  if (!st.ready || !t?.ready) return { ...base, reason: t?.reason ?? `toolbox off: ${st.reason}` };
  const target = i.config.scope.stagingUrl;
  if (i.tool !== "trufflehog" && !target) return { ...base, reason: "no scope.stagingUrl: nothing to point the tool at" };
  const common = { tool: i.tool, scope: i.scope, projectDir: undefined as string | undefined, limits: { timeoutMs: o.timeoutSec * 1000, memory: o.memory }, proxy: { ratePerSec: o.ratePerSec, maxRequests: o.maxRequests }, signal: i.signal };
  const meta = (r: { code: number; timedOut: boolean; network: ToolRunOutput["network"]; proxy?: { requests: number; refused: number }; stderr: string }) =>
    ({ exit: r.code, timedOut: r.timedOut, network: r.network, proxy: r.proxy, stderrTail: tail(r.stderr) });

  if (i.tool === "trufflehog") {
    // No network: liveness, when asked for, is exposed-secrets' job on replay.
    const r = await backend.run({ ...common, network: false, projectDir: i.projectDir, onEvent: i.onEvent, build: (p) => trufflehogArgv(p.projectRoot) }, st);
    const p = parseTrufflehog(r.stdout, r.projectRoot);
    const verdicts = await replay(p.claims, i);
    return finish({ ...base, ran: true, raw: p.raw, ...meta(r) }, p.findings, verdicts);
  }

  if (i.tool === "nuclei") {
    // Thousands of templates, some of them sending payloads: active testing, never by default.
    if (!i.config.scope.allowActiveTesting) return { ...base, reason: "nuclei is active testing: set scope.allowActiveTesting: true for your own staging" };
    const r = await backend.run({ ...common, network: true, onEvent: i.onEvent, build: (p) => nucleiArgv(target!, p.proxy, o, p.templatesDir) }, st);
    const p = parseNuclei(r.stdout, i.scope, target);
    const verdicts = await replay(p.claims, i);
    return finish({ ...base, ran: true, raw: p.raw, ...meta(r) }, p.findings, verdicts);
  }

  // katana's own JSON output drops responses it deems duplicates (two 401s
  // with the same body), so the routes also come from what the proxy actually
  // forwarded for plain HTTP: deterministic, and observed by Crenel itself.
  const seen: Route[] = [];
  const onEvent = (e: ProxyEvent) => {
    i.onEvent?.(e);
    if (e.via === "http" && !e.refused && e.status !== undefined) {
      try { const u = new URL(e.target); seen.push({ method: e.method, url: e.target, path: u.pathname, status: e.status }); } catch { /* ignore */ }
    }
  };
  const r = await backend.run({ ...common, network: true, onEvent, build: (p) => katanaArgv(target!, p.proxy, o) }, st);
  const p = parseKatana(r.stdout, i.scope);
  const routes = mergeRoutes(p.routes, seen);
  const declared = ((i.config.options["authz-matrix"] ?? {}) as { resources?: { path: string }[] }).resources ?? [];
  const suggestions = suggestResources(routes, declared);
  return { ...base, ran: true, raw: p.raw, ...meta(r), routes, suggestions, findings: katanaFindings(suggestions) };
}

/** Union of routes, one per method + origin + path. */
export function mergeRoutes(a: Route[], b: Route[]): Route[] {
  const out = new Map<string, Route>();
  for (const r of [...a, ...b]) {
    let key = `${r.method} ${r.url}`;
    try { const u = new URL(r.url); key = `${r.method} ${u.origin}${u.pathname}`; } catch { /* keep */ }
    if (!out.has(key)) out.set(key, r);
  }
  return [...out.values()];
}

const tail = (s: string) => s.trim().split("\n").slice(-5).join("\n").slice(-800);

async function replay(claims: Claim[], i: ToolRunInput): Promise<ClaimVerdict[]> {
  const env = { scope: i.scope, projectDir: i.projectDir, options: i.config.options, stagingUrl: i.config.scope.stagingUrl, checks: i.checks };
  const out: ClaimVerdict[] = [];
  for (const c of claims) {
    if (i.signal?.aborted) break;
    out.push(await validateClaim(c, env));
  }
  return out;
}

/** Apply verdicts: a lead whose claim a validator proved becomes proven, with the validator's proof. */
export function applyVerdicts(findings: Finding[], verdicts: ClaimVerdict[]): Finding[] {
  const byLead = new Map<string, ClaimVerdict>();
  for (const v of verdicts) byLead.set(v.claimId.replace(/^claim:/, ""), v);
  return findings.map((f) => {
    const v = byLead.get(f.id);
    if (!v || v.state !== "proven") return f;
    return {
      ...f, state: "proven" as const,
      description: `${f.description} Prouvé par ${v.validator}: ${v.reason}.`,
      proof: { method: v.validator ?? "validator", replay: v.evidence?.request.replace(/\n/g, " | ") ?? "", evidence: v.evidence?.response.split("\n")[0] },
    };
  });
}

function finish(out: ToolRunOutput, findings: Finding[], verdicts: ClaimVerdict[]): ToolRunOutput {
  return { ...out, findings: applyVerdicts(findings, verdicts), verdicts };
}
