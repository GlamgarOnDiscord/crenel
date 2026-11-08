// `crenel serve`: a local HTTP server for the web console, on Node's own
// node:http (no framework, nothing to audit but this file).
//
// Local by construction:
//   - binds 127.0.0.1 by default;
//   - every /api call needs the random token printed at startup (as a Bearer
//     header, or the HttpOnly SameSite=Strict cookie set when you open the
//     printed link), compared in constant time;
//   - the Host header must be the address we listen on (DNS rebinding);
//   - writes need a JSON body and, when the browser sends an Origin, our own
//     origin (CSRF);
//   - static files only from the web build directory, no path escape.
//
// The API (JSON):
//   GET  /api/state                 everything the console renders, in one call
//   GET  /api/config  PUT /api/config        crenel.config.yaml (validated before write)
//   GET  /api/targets POST /api/targets  DELETE /api/targets/:host   allowedHosts
//   POST /api/runs  {prompt, mode, model, goal?, explore?}   start a run (scan, authz, chat, goal, explore)
//   GET  /api/runs  GET /api/runs/:id  GET /api/runs/:id/events (SSE, ?after=seq)
//   POST /api/runs/:id/decision {id, decision}   POST /api/runs/:id/stop
//   POST /api/goals {text, mode, budget?}  GET /api/goals  POST /api/goals/:id/stop
//   POST /api/kill                   the global switch: stops every run
//   GET  /api/findings  GET /api/findings/:uid  POST /api/findings/:uid/triage (advice only)
//   GET  /api/baseline/diff  POST /api/baseline
//   GET  /api/authz  GET /api/tests (+ ?format=file)  GET /api/audit
//   GET  /api/toolbox  PUT /api/toolbox {backend: docker|wsl, distro?}   optional toolbox
//   GET  /api/integrations           destinations and their state (never a secret)
//   PUT  /api/integrations/slack {webhookUrl?, enabled?, minSeverity?}   DELETE /api/integrations/slack
//   POST /api/integrations/webhooks {name, url, events?, minSeverity?}   (returns a new secret once)
//   DELETE /api/integrations/webhooks/:name
//   POST /api/integrations/slack/test  POST /api/integrations/webhooks/:name/test

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, statSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseDocument } from "yaml";
import { ConfigSchema, loadConfig, type Config } from "../core/config.js";
import { REGISTRY } from "../core/registry.js";
import { diff, loadBaseline } from "../core/baseline.js";
import type { RunResult } from "../core/runner.js";
import { AgentRun, type Decision } from "../agent/run.js";
import { readJournal, replayRun, type JournalEntry, type RunSummary } from "../agent/journal.js";
import { GrantSet, StateStore } from "../agent/state.js";
import { claudeCli, selectLlm, type Llm } from "../agent/llm.js";
import { EXPLORE_MODES, resolveExploreMode, type ExploreMode } from "../agent/explore.js";
import { parseGoal, type GoalBudget } from "../agent/goal.js";
import type { Mode } from "../agent/gate.js";
import { triageFinding } from "../agent/triage.js";
import { generateRegressionFile } from "../generate/tests.js";
import { embeddedAsset, embeddedKeys, isEmbedded } from "../core/embedded.js";

export interface ServeOptions {
  configPath: string;
  host?: string;
  port?: number;
  /** Built console directory (web/dist). Without it, only the API is served. */
  webDir?: string | null;
  /** Fixed token (tests). Random by default. */
  token?: string;
  /** "auto": use claude -p when present; "off": never call a model. */
  llm?: "auto" | "off";
  /** Result of the claude -p detection (injected so tests never spawn it). */
  claudeAvailable?: boolean;
  /** Override model access (tests). */
  llmFactory?: (model: string) => Llm | null;
  /** Override checks (tests). */
  checks?: import("../core/types.js").Check[];
  /** Outbound HTTP for integrations (tests mock it). */
  fetch?: import("../integrations/deliver.js").FetchLike;
  /** Environment for integration secrets (tests). */
  env?: NodeJS.ProcessEnv;
}

export interface CrenelServer {
  server: Server;
  url: string;
  token: string;
  close(): Promise<void>;
  runs: Map<string, AgentRun>;
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json", ".ico": "image/x-icon",
  ".woff2": "font/woff2", ".webp": "image/webp", ".mp4": "video/mp4", ".webm": "video/webm",
};
// The console loads its type from Fontshare and Google Fonts; everything else is self.
const CSP = [
  "default-src 'self'", "script-src 'self'", "connect-src 'self'", "img-src 'self' data: blob:", "media-src 'self'",
  "style-src 'self' 'unsafe-inline' https://api.fontshare.com",
  "font-src 'self' data: https://cdn.fontshare.com",
  "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'",
].join("; ");
const MODES = new Set<Mode>(["ask", "readonly", "bypass"]);
const MAX_BODY = 256 * 1024;
// A custom model spec names a provider ("openai:gpt-4o-mini", "ollama:llama3.1",
// "anthropic-api:claude-…"); a plain name (no ":") is the claude CLI. These are
// the provider prefixes the engine understands (reported by /api/state).
const CUSTOM_PROVIDERS = ["openai", "ollama", "anthropic-api"];
// An env var NAME, upper case (same discipline as llm.ts): only the name of the
// variable travels, never the key value.
const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/;

class HttpError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const data = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
    "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
    ...headers,
  });
  res.end(data);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const type = req.headers["content-type"] ?? "";
  if (!type.startsWith("application/json")) throw new HttpError(415, "JSON body required");
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, "body too large");
    chunks.push(c as Buffer);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "invalid JSON");
  }
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function cookie(req: IncomingMessage, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return undefined;
}

/** Locate web/dist next to the package (works from src/ with tsx and from dist/). */
export function findWebDir(): string | null {
  // The standalone executable serves the console embedded in itself (serveStatic).
  if (isEmbedded()) return null;
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    const cand = join(dir, "web", "dist");
    if (existsSync(join(cand, "index.html"))) return cand;
    dir = dirname(dir);
  }
  return null;
}

function runResultOf(project: string, items: { id: string; check: string; title: string; severity: RunResult["findings"][number]["severity"]; state: RunResult["findings"][number]["state"] }[], checksRun: string[]): RunResult {
  return { project, startedAt: new Date().toISOString(), findings: items as RunResult["findings"], errors: [], checksRun };
}

export async function startServer(opts: ServeOptions): Promise<CrenelServer> {
  const configPath = resolve(opts.configPath);
  const host = opts.host ?? "127.0.0.1";
  const token = opts.token ?? randomBytes(24).toString("base64url");
  const store = new StateStore(join(dirname(configPath), ".crenel"));
  const grants = new GrantSet(store.grantsPath);
  const runs = new Map<string, AgentRun>();
  const webDir = opts.webDir === undefined ? findWebDir() : opts.webDir;
  const llmOn = opts.llm !== "off" && (opts.claudeAvailable ?? false);
  const llmFor = (model: string): Llm | null => (llmOn ? (opts.llmFactory ?? claudeCli)(model) : null);
  const config = (): Config => loadConfig(configPath);

  // Resolve the model for a run. A plain name is the claude CLI (unchanged, and
  // it still honours the test seam and the claude-available gate). A spec with a
  // provider ("openai:…", "ollama:…", "anthropic-api:…") is an HTTP provider,
  // which does not need the CLI: it is resolved by selectLlm. Keys are never in
  // the body — only the NAME of an env var (apiKeyEnv); the value is read from
  // process.env inside the provider at call time. A bad spec/connection -> 4xx.
  function runLlm(model: string, baseUrl: string | undefined, apiKeyEnv: string | undefined, cfg: Config): Llm | null {
    if (!model.includes(":")) return llmFor(model);
    if (opts.llm === "off") throw new HttpError(400, "model access is off on this server (crenel serve --llm off)");
    if (apiKeyEnv !== undefined && !ENV_NAME.test(apiKeyEnv)) throw new HttpError(400, "modelApiKeyEnv must be the NAME of an environment variable (A-Z, 0-9, _), never a key");
    if (baseUrl !== undefined) { try { new URL(baseUrl); } catch { throw new HttpError(400, "modelBaseUrl must be a valid URL"); } }
    const { llm, error } = selectLlm({ spec: model, baseUrl, apiKeyEnv, config: (cfg.options as Record<string, unknown>).llm });
    if (error) throw new HttpError(400, error);
    if (!llm) throw new HttpError(400, `unknown model spec: ${model.split(":")[0]}:…`);
    return llm;
  }

  // Journals of runs from earlier sessions: their state is rebuilt from disk.
  // A run that was still going when the server died is reported as stopped.
  function summaries(): RunSummary[] {
    const out: RunSummary[] = [];
    for (const id of store.runIds()) {
      const live = runs.get(id);
      const s = replayRun(readJournal(store.runPath(id)));
      if (!s) continue;
      if (!live && (s.status === "running" || s.status === "waiting")) { s.status = "stopped"; s.outcome = "interrupted (server restarted)"; }
      if (live) s.status = live.status;
      out.push(s);
    }
    return out.sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  }

  function startRun(body: Record<string, unknown>): AgentRun {
    const prompt = String(body.prompt ?? "").trim().slice(0, 4000);
    if (!prompt) throw new HttpError(400, "prompt required");
    const mode = (MODES.has(body.mode as Mode) ? body.mode : "ask") as Mode;
    const model = typeof body.model === "string" && body.model.trim() ? body.model.trim() : "opus";
    const modelBaseUrl = typeof body.modelBaseUrl === "string" && body.modelBaseUrl.trim() ? body.modelBaseUrl.trim() : undefined;
    const modelApiKeyEnv = typeof body.modelApiKeyEnv === "string" && body.modelApiKeyEnv.trim() ? body.modelApiKeyEnv.trim() : undefined;
    // The console's exploration toggle; the config's choice when absent. Safety does not depend on it.
    const explore = (EXPLORE_MODES as readonly unknown[]).includes(body.explore) ? (body.explore as ExploreMode) : undefined;
    let cfg: Config;
    try { cfg = config(); } catch (err) { throw new HttpError(422, (err as Error).message); }
    const llm = runLlm(model, modelBaseUrl, modelApiKeyEnv, cfg);
    const goalText = typeof body.goal === "string" ? body.goal : undefined;
    const goal = goalText ? parseGoal(goalText, (body.budget ?? {}) as Partial<GoalBudget>) : undefined;
    const notify = async (findings: import("../core/types.js").Finding[], run: string, counts: { proven: number; leads: number; fixed: number }) => {
      const { notify: send } = await import("../integrations/notify.js");
      const r = await send({ config: cfg, stateDir: store.dir, findings, run, counts, fetch: opts.fetch, env: opts.env });
      for (const rec of r.records) store.appendAudit({ ...rec });
      return { records: r.records as unknown as Record<string, unknown>[], skipped: r.skipped };
    };
    const run = new AgentRun({ config: cfg, configPath, store, grants, llm, checks: opts.checks, notify }, { prompt: goal ? `/goal ${goal.text}` : prompt, mode, model, goal, explore });
    runs.set(run.id, run);
    void run.start();
    return run;
  }

  function state() {
    let cfg: Config | null = null;
    let configError: string | undefined;
    try { cfg = config(); } catch (err) { configError = (err as Error).message; }
    const f = store.findings();
    return {
      project: cfg?.project ?? null, configPath, configError,
      scope: cfg?.scope ?? null,
      llm: llmOn ? "claude -p" : null,
      // Provider prefixes the engine can reach over HTTP (names only, no secret).
      customProviders: opts.llm === "off" ? [] : CUSTOM_PROVIDERS,
      explore: cfg ? resolveExploreMode(cfg, llmOn) : "off",
      grants: [...grants],
      checks: REGISTRY.map((c) => ({ name: c.name, title: c.title, readOnly: c.readOnly })),
      findings: f.items, checksRun: f.checksRun, scannedAt: f.updatedAt ?? null,
      runs: summaries().slice(0, 50),
      authz: store.authz(),
      authzResources: ((cfg?.options["authz-matrix"] ?? {}) as { resources?: { name: string; path: string; methods?: string[] }[] }).resources ?? [],
      // Each generated test with its own code, for the finding page.
      tests: store.tests().map((t) => {
        const fd = f.items.find((x) => x.uid === t.uid);
        const file = fd ? generateRegressionFile([fd]) : "";
        return { ...t, code: file.includes("test(") ? file.slice(file.indexOf("test(")).trim() : undefined };
      }),
      // Egress events of the toolbox proxy can number thousands per run: they
      // are served by /api/toolbox and /api/audit, not mixed into the state.
      audit: store.audit().filter((e) => e.kind !== "egress").slice(-200),
    };
  }

  function writeConfigText(text: string): Config {
    let parsed: unknown;
    try { parsed = parseDocument(text).toJS(); } catch (err) { throw new HttpError(422, `YAML: ${(err as Error).message}`); }
    const r = ConfigSchema.safeParse(parsed);
    if (!r.success) throw new HttpError(422, r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; "));
    if (existsSync(configPath)) copyFileSync(configPath, configPath + ".bak");
    writeFileSync(configPath, text);
    return r.data;
  }

  function editHosts(fn: (hosts: string[]) => string[]): Config {
    const doc = parseDocument(readFileSync(configPath, "utf8"));
    const hosts = ((doc.getIn(["scope", "allowedHosts"]) as { toJSON?: () => string[] } | undefined)?.toJSON?.() ?? []) as string[];
    doc.setIn(["scope", "allowedHosts"], fn(hosts));
    return writeConfigText(doc.toString());
  }

  async function api(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const method = req.method ?? "GET";
    const p = url.pathname.replace(/\/+$/, "");
    const seg = p.split("/").slice(2); // after /api
    const body = method === "POST" || method === "PUT" ? ((await readBody(req)) as Record<string, unknown>) : {};

    if (p === "/api/health") return send(res, 200, { ok: true, name: "crenel" });
    if (p === "/api/state" && method === "GET") return send(res, 200, state());

    if (p === "/api/config") {
      if (method === "GET") return send(res, 200, { path: configPath, text: readFileSync(configPath, "utf8"), config: config() });
      if (method === "PUT") return send(res, 200, { config: writeConfigText(String(body.text ?? "")) });
    }
    if (seg[0] === "targets") {
      if (method === "GET") return send(res, 200, config().scope);
      if (method === "POST") {
        const raw = String(body.host ?? "").trim().toLowerCase();
        const h = (() => { try { return new URL(raw.includes("://") ? raw : `https://${raw}`).hostname; } catch { return ""; } })();
        if (!h || !/^[a-z0-9.-]+$|^\[?[0-9a-f:.]+\]?$/.test(h)) throw new HttpError(400, "a hostname is required");
        if (body.owner !== true) throw new HttpError(400, "declare that you own this target (owner: true)");
        store.appendAudit({ at: new Date().toISOString(), kind: "target-added", host: h, owner: true });
        return send(res, 200, { scope: editHosts((hs) => [...new Set([...hs, h])]).scope });
      }
      if (method === "DELETE" && seg[1]) {
        const h = decodeURIComponent(seg[1]).toLowerCase();
        store.appendAudit({ at: new Date().toISOString(), kind: "target-removed", host: h });
        grants.delete(h);
        return send(res, 200, { scope: editHosts((hs) => hs.filter((x) => x.toLowerCase() !== h)).scope });
      }
    }

    if (seg[0] === "runs" || seg[0] === "goals") {
      const isGoal = seg[0] === "goals";
      if (!seg[1]) {
        if (method === "POST") {
          const run = startRun(isGoal ? { ...body, prompt: String(body.text ?? ""), goal: String(body.text ?? "") } : body);
          return send(res, 201, { id: run.id, intent: run.intent, title: run.title });
        }
        const list = summaries();
        return send(res, 200, isGoal ? list.filter((s) => s.goal) : list);
      }
      const id = seg[1];
      const run = runs.get(id);
      const path = store.runPath(id);
      if (!/^r-[0-9a-z-]+$/.test(id) || (!run && !existsSync(path))) throw new HttpError(404, "no such run");
      if (seg[2] === "stop" && method === "POST") { run?.stop(); return send(res, 200, { stopped: !!run }); }
      if (seg[2] === "decision" && method === "POST") {
        const d = body.decision as Decision;
        if (!["once", "always", "deny"].includes(d)) throw new HttpError(400, "decision must be once, always or deny");
        return send(res, run?.decide(String(body.id ?? ""), d) ? 200 : 409, { ok: true });
      }
      if (seg[2] === "events" && method === "GET") return sse(req, res, id, Number(url.searchParams.get("after") ?? req.headers["last-event-id"] ?? 0));
      if (!seg[2]) return send(res, 200, { ...replayRun(readJournal(path)), status: run?.status, entries: readJournal(path).length });
    }
    if (p === "/api/kill" && method === "POST") {
      let n = 0;
      for (const r of runs.values()) if (r.status === "running" || r.status === "waiting") { r.stop("kill switch"); n++; }
      return send(res, 200, { stopped: n });
    }

    if (seg[0] === "findings") {
      const items = store.findings().items;
      if (!seg[1]) return send(res, 200, items);
      const f = items.find((x) => x.uid === seg[1]);
      if (!f) throw new HttpError(404, "no such finding");
      if (seg[2] === "triage" && method === "POST") {
        if (!llmOn) throw new HttpError(503, "no model: start with claude -p available, or keep the deterministic verdict");
        const model = typeof body.model === "string" ? body.model : "opus";
        const advice = (await triageFinding(f, model)).advice;
        store.setAdvice(f.uid, advice);
        return send(res, 200, { uid: f.uid, advice, state: f.state, note: "advice only: the state is decided by validators" });
      }
      return send(res, 200, f);
    }
    if (seg[0] === "baseline") {
      const f = store.findings();
      const result = runResultOf(config().project, f.items, f.checksRun);
      if (method === "POST") { writeFileSync(store.baselinePath, JSON.stringify({ savedAt: new Date().toISOString(), findings: f.items.map(({ id, check, severity, state, title }) => ({ id, check, severity, state, title })) }, null, 2)); return send(res, 200, { saved: true }); }
      const base = loadBaseline(store.baselinePath);
      if (!base) return send(res, 200, { baseline: null });
      const d = diff(result, base);
      return send(res, 200, { baseline: base.savedAt, added: d.added.map((x) => x.id), fixed: d.fixed.map((x) => x.id), persisting: d.persisting.map((x) => x.id) });
    }
    if (p === "/api/authz") return send(res, 200, store.authz());
    if (p === "/api/tests") {
      if (url.searchParams.get("format") === "file") return send(res, 200, existsSync(store.regressionPath) ? readFileSync(store.regressionPath, "utf8") : "");
      return send(res, 200, store.tests());
    }
    if (p === "/api/audit") return send(res, 200, store.audit());
    // Optional toolbox: status for the console. The backend (docker or wsl)
    // is a config change: PUT /api/toolbox writes options.toolbox.backend (and
    // wsl.distro) into the YAML, validated like PUT /api/config.
    if (p === "/api/toolbox" && method === "GET") {
      const { backendFor } = await import("../toolbox/backend.js");
      const { toolboxOptions, TOOL_NAMES } = await import("../toolbox/run.js");
      let options: ReturnType<typeof toolboxOptions> | null = null;
      let optionsError: string | undefined;
      try { options = toolboxOptions(config()); } catch (err) { optionsError = (err as Error).message; }
      const st = await backendFor(options ?? toolboxOptions({ ...config(), options: {} })).status();
      const egress = store.audit().filter((e) => e.kind === "egress").slice(-200);
      // Docker fields stay at the top level for older consoles.
      return send(res, 200, { ...(st.docker ?? {}), ...st, tools: TOOL_NAMES, toolStatus: st.tools, options, optionsError, egress });
    }
    if (p === "/api/toolbox" && method === "PUT") {
      const backend = body.backend;
      if (backend !== "docker" && backend !== "wsl") throw new HttpError(400, "backend must be docker or wsl");
      const doc = parseDocument(readFileSync(configPath, "utf8"));
      doc.setIn(["options", "toolbox", "backend"], backend);
      if (typeof body.distro === "string" && body.distro.trim()) doc.setIn(["options", "toolbox", "wsl", "distro"], body.distro.trim());
      const { ToolboxOptions } = await import("../toolbox/run.js");
      const checked = ToolboxOptions.safeParse(((doc.toJS() as { options?: { toolbox?: unknown } } | null)?.options?.toolbox) ?? {});
      if (!checked.success) throw new HttpError(422, `options.toolbox: ${checked.error.issues.map((x) => `${x.path.join(".") || "(root)"}: ${x.message}`).join("; ")}`);
      const next = writeConfigText(doc.toString());
      store.appendAudit({ at: new Date().toISOString(), kind: "toolbox-backend", backend, distro: typeof body.distro === "string" ? body.distro.trim() : undefined });
      return send(res, 200, { options: (next.options as Record<string, unknown>).toolbox });
    }
    if (seg[0] === "integrations") return integrations(method, seg.slice(1), body, res);
    throw new HttpError(404, "not found");
  }

  // Integrations: destinations the user declares (Slack, signed webhooks).
  // Non-secret settings go to options.integrations in the YAML (validated);
  // secrets go to .crenel/secrets.json (0600) and are never sent back.
  async function integrations(method: string, rest: string[], body: Record<string, unknown>, res: ServerResponse): Promise<void> {
    const I = await import("../integrations/cli.js");
    const { IntegrationsOptions, secretKey } = await import("../integrations/options.js");
    const { SecretStore } = await import("../integrations/secrets.js");
    const { isSlackWebhookUrl } = await import("../integrations/slack.js");
    const { newWebhookSecret, MIN_SECRET_LENGTH } = await import("../integrations/webhook.js");
    const secrets = new SecretStore(store.dir, opts.env);
    const status = () => {
      const recent = store.audit().filter((e) => e.kind === "integration").slice(-20).reverse();
      return { ...I.integrationsStatus(config(), store.dir, opts.env), recent };
    };
    // Edit options.integrations in the YAML, validated before it is written.
    const edit = (fn: (cur: Record<string, unknown>) => Record<string, unknown>) => {
      const doc = parseDocument(readFileSync(configPath, "utf8"));
      const cur = ((doc.toJS() as { options?: { integrations?: Record<string, unknown> } } | null)?.options?.integrations) ?? {};
      const next = fn(structuredClone(cur));
      const checked = IntegrationsOptions.safeParse(next);
      if (!checked.success) throw new HttpError(422, `options.integrations: ${checked.error.issues.map((x) => `${x.path.join(".") || "(root)"}: ${x.message}`).join("; ")}`);
      doc.setIn(["options", "integrations"], next);
      writeConfigText(doc.toString());
    };
    const allowHost = (cur: Record<string, unknown>, host: string) => {
      const hosts = Array.isArray(cur.allowedHosts) ? (cur.allowedHosts as string[]) : [];
      if (config().scope.allowedHosts.some((h) => h.toLowerCase() === host)) throw new HttpError(422, `${host} is a scan target (scope.allowedHosts): it cannot also be a destination`);
      cur.allowedHosts = [...new Set([...hosts, host])];
    };
    const audit = (e: Record<string, unknown>) => store.appendAudit({ at: new Date().toISOString(), ...e });

    if (!rest[0] && method === "GET") return send(res, 200, status());

    if (rest[0] === "slack") {
      if (rest[1] === "test" && method === "POST") {
        const r = await I.testIntegration("slack", config(), store.dir, { fetch: opts.fetch, env: opts.env });
        store.appendAudit({ ...r });
        return send(res, 200, r);
      }
      if (method === "PUT") {
        const url = typeof body.webhookUrl === "string" ? body.webhookUrl.trim() : "";
        if (url && !isSlackWebhookUrl(url)) throw new HttpError(400, "not a Slack Incoming Webhook URL (https://hooks.slack.com/services/…)");
        const min = body.minSeverity;
        if (min !== undefined && min !== "critical" && min !== "high") throw new HttpError(400, "minSeverity must be critical or high");
        edit((cur) => {
          const slack = { ...(cur.slack as Record<string, unknown> | undefined) };
          if (typeof body.enabled === "boolean") slack.enabled = body.enabled;
          else if (url) slack.enabled = true;
          if (min) slack.minSeverity = min;
          if (url) allowHost(cur, new URL(url).hostname);
          cur.slack = slack;
          return cur;
        });
        if (url) secrets.set(secretKey.slack, url);
        audit({ kind: "integration-configured", integration: "slack", enabled: body.enabled, webhookUrlSaved: !!url });
        return send(res, 200, status());
      }
      if (method === "DELETE") {
        secrets.delete(secretKey.slack);
        edit((cur) => { cur.slack = { ...(cur.slack as Record<string, unknown> | undefined), enabled: false }; return cur; });
        audit({ kind: "integration-removed", integration: "slack" });
        return send(res, 200, status());
      }
    }

    if (rest[0] === "webhooks") {
      const name = rest[1] ? decodeURIComponent(rest[1]) : undefined;
      if (name && rest[2] === "test" && method === "POST") {
        const r = await I.testIntegration(`webhook:${name}`, config(), store.dir, { fetch: opts.fetch, env: opts.env });
        store.appendAudit({ ...r });
        return send(res, 200, r);
      }
      if (!name && method === "POST") {
        const hookName = String(body.name ?? "").trim().toLowerCase();
        const url = String(body.url ?? "").trim();
        let u: URL;
        try { u = new URL(url); } catch { throw new HttpError(400, "a URL is required"); }
        const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
        if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) throw new HttpError(400, "https required (plain http only to localhost)");
        const given = typeof body.secret === "string" ? body.secret : "";
        if (given && given.length < MIN_SECRET_LENGTH) throw new HttpError(400, `a signing secret needs at least ${MIN_SECRET_LENGTH} characters`);
        edit((cur) => {
          const hooks = (Array.isArray(cur.webhooks) ? cur.webhooks : []) as Record<string, unknown>[];
          if (hooks.some((h) => h.name === hookName)) throw new HttpError(409, `a webhook named ${hookName} exists`);
          allowHost(cur, u.hostname.toLowerCase());
          hooks.push({ name: hookName, url, ...(Array.isArray(body.events) ? { events: body.events } : {}), ...(typeof body.minSeverity === "string" ? { minSeverity: body.minSeverity } : {}) });
          cur.webhooks = hooks;
          return cur;
        });
        const secret = given || newWebhookSecret();
        secrets.set(secretKey.webhook(hookName), secret);
        audit({ kind: "integration-configured", integration: `webhook:${hookName}`, host: u.hostname });
        // The only time the secret leaves the machine's disk: shown once to the user who created it.
        return send(res, 201, { ...status(), secret: given ? undefined : secret });
      }
      if (name && !rest[2] && method === "DELETE") {
        edit((cur) => { cur.webhooks = ((Array.isArray(cur.webhooks) ? cur.webhooks : []) as Record<string, unknown>[]).filter((h) => h.name !== name); return cur; });
        secrets.delete(secretKey.webhook(name));
        audit({ kind: "integration-removed", integration: `webhook:${name}` });
        return send(res, 200, status());
      }
    }
    throw new HttpError(404, "not found");
  }

  // Server-sent events: replay the journal after `after`, then follow it live.
  function sse(req: IncomingMessage, res: ServerResponse, id: string, after: number): void {
    res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store", connection: "keep-alive", "x-content-type-options": "nosniff" });
    const write = (e: JournalEntry) => res.write(`id: ${e.seq}\nevent: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`);
    const run = runs.get(id);
    const past = run ? run.journal.since(after) : readJournal(store.runPath(id)).filter((e) => e.seq > after);
    past.forEach(write);
    const ended = past.some((e) => e.type === "run.end") || (!run);
    if (ended) { res.write("event: eof\ndata: {}\n\n"); res.end(); return; }
    const unsub = run!.journal.subscribe((e) => {
      write(e);
      if (e.type === "phase" && (e.data as { phase: string }).phase === "idle" && run!.status !== "running" && run!.status !== "waiting") {
        res.write("event: eof\ndata: {}\n\n");
        res.end();
      }
    });
    const ping = setInterval(() => res.write(": ping\n\n"), 15_000);
    req.on("close", () => { unsub(); clearInterval(ping); });
  }

  function serveStatic(res: ServerResponse, pathname: string): void {
    if (!webDir && embeddedKeys().has("web/index.html")) return serveEmbedded(res, pathname);
    if (!webDir) return send(res, 404, "Console not built: run `pnpm build` in web/ (the API is up).");
    const root = resolve(webDir);
    let file = resolve(root, "." + decodeURIComponent(pathname));
    if (file !== root && !file.startsWith(root + sep)) return send(res, 403, "forbidden");
    if (!existsSync(file) || statSync(file).isDirectory()) file = join(root, "index.html");
    res.writeHead(200, {
      "content-type": MIME[extname(file)] ?? "application/octet-stream",
      "content-security-policy": CSP, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
      "cache-control": file.endsWith("index.html") ? "no-store" : "public, max-age=3600",
    });
    res.end(readFileSync(file));
  }

  // Same rules as serveStatic, from the executable's embedded web/dist: a path
  // is only ever a lookup key, so nothing outside the console can be read.
  function serveEmbedded(res: ServerResponse, pathname: string): void {
    let key: string;
    try { key = "web/" + decodeURIComponent(pathname).replace(/^\/+/, ""); } catch { return send(res, 400, "bad path"); }
    if (!embeddedKeys().has(key)) key = "web/index.html";
    const body = embeddedAsset(key);
    if (!body) return send(res, 404, "not found");
    res.writeHead(200, {
      "content-type": MIME[extname(key)] ?? "application/octet-stream",
      "content-security-policy": CSP, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
      "cache-control": key.endsWith("index.html") ? "no-store" : "public, max-age=3600",
    });
    res.end(body);
  }

  let port = opts.port ?? 4100;
  const allowedHosts = () => new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`, `${host}:${port}`]);

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://${host}`);
      if (!allowedHosts().has(String(req.headers.host ?? ""))) return send(res, 421, "unexpected Host header");
      // Opening the printed link: trade the token in the URL for a cookie, then drop it from the URL.
      if (req.method === "GET" && url.searchParams.has("token") && !url.pathname.startsWith("/api/")) {
        if (!safeEqual(url.searchParams.get("token") ?? "", token)) return send(res, 401, "bad token");
        // Back to the same page without the token (the desktop app opens /app/...);
        // never a "//host" or backslash path, which a browser would read as another site.
        const back = /^\/(?![/\\])[^\\]*$/.test(url.pathname) ? url.pathname : "/";
        res.writeHead(302, { location: back, "set-cookie": `crenel_token=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/`, "cache-control": "no-store" });
        return res.end();
      }
      if (url.pathname.startsWith("/api/")) {
        const bearer = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
        const given = bearer || cookie(req, "crenel_token") || "";
        if (url.pathname !== "/api/health" && !safeEqual(given, token)) return send(res, 401, { error: "token required (see the link printed by crenel serve)" });
        const m = req.method ?? "GET";
        if (m !== "GET" && m !== "HEAD") {
          const origin = req.headers.origin;
          if (origin && !allowedHosts().has(origin.replace(/^https?:\/\//, ""))) return send(res, 403, { error: "cross-origin write refused" });
        }
        return await api(req, res, url);
      }
      return serveStatic(res, url.pathname);
    } catch (err) {
      if (res.headersSent) { res.end(); return; }
      const status = err instanceof HttpError ? err.status : 500;
      send(res, status, { error: (err as Error).message });
    }
  });

  await new Promise<void>((ok, ko) => { server.once("error", ko); server.listen(port, host, () => ok()); });
  port = (server.address() as { port: number }).port;
  const shownHost = host.includes(":") ? `[${host}]` : host;
  return {
    server, token, runs,
    url: `http://${shownHost}:${port}`,
    close: () => new Promise<void>((ok) => {
      for (const r of runs.values()) r.stop("server closing");
      server.closeAllConnections?.();
      server.close(() => ok());
    }),
  };
}
