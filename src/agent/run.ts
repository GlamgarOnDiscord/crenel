// One agent run: a plan of tools, executed under the gate, with every step in
// the journal, every network request through the scoped client, every claim
// decided by a validator, and a kill switch that really stops it.
//
// The loop is deliberately a single thread with a fixed set of intent-level
// tools (research: few typed actions beat a shell; one thread decides). The
// planner is deterministic: the prompt picks an intent (full scan, authz,
// secrets, tests, chat, goal). A model, when one is available, only writes
// prose (the summary, chat answers) and may PROPOSE claims; it never decides a
// state and never chooses a request on its own: the gate and the validators
// read the config and the disk, not the model's words.
//
// Events the console renders are journalled as `ui` (same shape as the web
// AgentEvent) and `ui.update`; control events are `phase`, `gate`, `decision`,
// `net`, `claim`, `verdict`, `goal.*`, `results` and `run.end`.

import { randomBytes } from "node:crypto";
import { dirname, isAbsolute, resolve } from "node:path";
import type { Config } from "../core/config.js";
import { Scope, type NetEvent } from "../core/scope.js";
import { safeFetch } from "../core/net.js";
import { REGISTRY, resolveChecks } from "../core/registry.js";
import type { Check, CheckContext, Finding, Severity } from "../core/types.js";
import { generateRegressionFile } from "../generate/tests.js";
import { crawlLiveBundle } from "../checks/live-bundle.js";
import { reviewBundle } from "./bundle-review.js";
import { scanBaas } from "../checks/baas-exposure.js";
import { Journal } from "./journal.js";
import { authorize, type GateDecision, type Judge, type Mode, type PlannedRequest } from "./gate.js";
import { authzUrl, claimFor, validateClaim, type AuthzOptions, type Claim, type ClaimVerdict } from "./validators.js";
import { fence, untrusted, UNTRUSTED_PREAMBLE } from "./untrusted.js";
import { estimateTokens, type Llm } from "./llm.js";
import { GOAL_LABEL, parseGoal, runGoal, type GoalCheck, type GoalSpec } from "./goal.js";
import { uidOf, type AuthzMatrix, type StateStore, type StoredFinding, type StoredTest } from "./state.js";
import { z } from "zod";
import { dockerStatus } from "../toolbox/docker.js";
import { runTool, toolboxOptions, type ToolName } from "../toolbox/run.js";

export type Decision = "once" | "always" | "deny";
export type Intent = "full" | "authz" | "secrets" | "tests" | "chat" | "goal" | "tools";

// Web-facing event shapes (mirror web/src/lib/types.ts AgentEvent).
type Sev = "crit" | "high" | "med" | "low" | "info";
interface InlineFinding { sev: Sev; text: string; state: "proven" | "lead" | "fixed"; id?: string }
export type UiEvent =
  | { kind: "user"; text: string }
  | { kind: "say"; text: string }
  | { kind: "think"; text: string; dur: string }
  | { kind: "plan"; steps: { tool: string; label: string }[] }
  | { kind: "tool"; tool: string; args: string; input: string; lines: string[]; findings?: InlineFinding[]; dur: string; code?: { file: string; body: string } }
  | { kind: "permission"; id: string; tool: string; host: string; requests: string[] }
  | { kind: "note"; text: string; tone?: "warn" | "muted" };

export const SEV: Record<Severity, Sev> = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };
const webState = (s: Finding["state"]) => (s === "proven" ? "proven" : s === "fixed" ? "fixed" : "lead");

const TOOL_CHECKS: Record<string, string[]> = {
  "scan.secrets": ["exposed-secrets", "public-env", "sourcemaps", "committed-credentials", "committed-env", "git-history", "storage-buckets"],
  "scan.repo": ["ci-hardening", "dockerfile", "mcp-surface", "jwt-config", "tls-verification", "cloudflare-audit", "webhook-signature", "ssrf", "business-logic"],
  "scan.deps": ["dependency-risk"],
  "scan.baas": ["baas-exposure", "supabase-rpc"],
  "scan.web": ["headers", "live-bundle", "exposed-files", "graphql", "open-redirect", "next-middleware", "transport", "subdomain-takeover", "email-dns", "dev-server", "ai-infra", "vercel-preview", "cache-deception", "auth-config", "auth-variants", "next-image", "api-docs", "cache-poisoning"],
};
const LABEL: Record<string, string> = {
  "scan.secrets": "Chercher des secrets dans le bundle",
  "scan.repo": "Fouiller le dépôt",
  "scan.deps": "Auditer les dépendances",
  "scan.baas": "Vérifier les clés BaaS et la RLS",
  "scan.web": "Inspecter le site déployé (en-têtes, chunks JS, fichiers exposés)",
  "review.bundle": "Relire les chunks JS avec le modèle (pistes)",
  "authz.matrix": "Prouver l'isolation entre comptes",
  "validate.claims": "Rejouer chaque preuve (validateurs)",
  "tests.generate": "Générer les tests de régression",
  "tools.trufflehog": "trufflehog sur le projet (conteneur sans réseau)",
  "tools.katana": "Découvrir les routes avec katana (conteneur, proxy à périmètre)",
  "tools.nuclei": "Modèles nuclei non intrusifs (conteneur, proxy à périmètre)",
};

/** Pick an intent from the user's words. Deterministic: the model does not plan. */
export function intentOf(prompt: string): Intent {
  const s = prompt.trim().toLowerCase();
  if (s.startsWith("/goal")) return "goal";
  if (s.startsWith("/scan")) return "full";
  if (s.startsWith("/authz")) return "authz";
  if (s.startsWith("/secrets")) return "secrets";
  if (s.startsWith("/test")) return "tests";
  if (s.startsWith("/tools")) return "tools";
  if (s.startsWith("/")) return "chat";
  if (/\bscan|analyse|audit|premier scan/.test(s)) return "full";
  if (/compte a|compte b|entre comptes|isolation|autorisation|authz|tenant/.test(s)) return "authz";
  if (/secret|clé|cle |key|bundle|supabase|firebase|rls/.test(s)) return "secrets";
  if (/\btests?\b|régression|ci\b/.test(s)) return "tests";
  return "chat";
}

export interface RunDeps {
  config: Config;
  configPath: string;
  store: StateStore;
  /** Hosts allowed "always" (shared across runs, persisted by the server). */
  grants: Set<string>;
  llm: Llm | null;
  judge?: Judge;
  /** Override the checks (tests). Defaults to the registry. */
  checks?: Check[];
  /** Run-level budget. */
  maxProbes?: number;
  maxMs?: number;
}

export interface RunOptions {
  prompt: string;
  mode: Mode;
  model?: string;
  goal?: GoalSpec;
  id?: string;
}

const ms = (t: number) => (t < 1000 ? `${t} ms` : `${(t / 1000).toFixed(1).replace(".", ",")} s`);
const pathOf = (url: string) => { try { const u = new URL(url); return u.pathname + u.search; } catch { return url; } };
const hostOf = (url: string) => { try { return new URL(url).hostname; } catch { return ""; } };

export class AgentRun {
  readonly id: string;
  readonly journal: Journal;
  readonly title: string;
  readonly intent: Intent;
  status: "running" | "waiting" | "done" | "stopped" | "error" = "running";
  probes = 0;
  tokens = 0;
  private refusals = 0;
  private readonly ac = new AbortController();
  private readonly pending = new Map<string, (d: Decision) => void>();
  private readonly runGrants = new Set<string>();
  private unattended = false;
  private uiSeq = 0;
  private readonly scope: Scope;
  private readonly projectDir: string;
  private readonly checks: Check[];
  private readonly goal?: GoalSpec;
  private stopReason = "";
  private readonly started = Date.now();

  constructor(private readonly deps: RunDeps, private readonly opts: RunOptions) {
    this.id = opts.id ?? `r-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${randomBytes(4).toString("hex")}`;
    this.intent = opts.goal ? "goal" : intentOf(opts.prompt);
    this.goal = opts.goal ?? (this.intent === "goal" ? parseGoal(opts.prompt.replace(/^\/goal\s*/i, "")) : undefined);
    this.title = opts.prompt.length > 120 ? opts.prompt.slice(0, 118) + "…" : opts.prompt;
    this.journal = new Journal(deps.store.runPath(this.id), this.id);
    const cfg = deps.config;
    const configDir = dirname(resolve(deps.configPath));
    this.projectDir = isAbsolute(cfg.projectDir) ? cfg.projectDir : resolve(configDir, cfg.projectDir);
    this.checks = deps.checks ?? (cfg.checks.length ? resolveChecks(cfg.checks) : REGISTRY);
    this.scope = new Scope({
      allowedHosts: cfg.scope.allowedHosts,
      allowActiveTesting: cfg.scope.allowActiveTesting,
      allowPrivate: cfg.scope.allowPrivate,
      stagingUrl: cfg.scope.stagingUrl,
      signal: this.ac.signal,
      onRequest: (e) => this.onNet(e),
    });
  }

  get signal(): AbortSignal { return this.ac.signal; }

  /* ---------- journal helpers ---------- */

  private ui(ev: UiEvent): string {
    const uid = `${this.id}:${++this.uiSeq}`;
    this.journal.append("ui", { uid, ev });
    return uid;
  }
  private uiUpdate(uid: string, ev: UiEvent): void { this.journal.append("ui.update", { uid, ev }); }
  private phase(p: "running" | "waiting" | "idle"): void {
    this.status = p === "waiting" ? "waiting" : this.status === "waiting" ? "running" : this.status;
    this.journal.append("phase", { phase: p });
  }

  // Every request seen by the scoped client: journalled, counted, audited when
  // nobody was asked, and watched by the monitor that can kill the run.
  private onNet(e: NetEvent): void {
    this.journal.append("net", e);
    if (e.refused) {
      this.refusals++;
      if (this.refusals >= 3 && !this.ac.signal.aborted) this.stop("monitor: three requests refused by the scope in one run");
      return;
    }
    this.probes++;
    if (this.unattended) {
      this.deps.store.appendAudit({ at: new Date().toISOString(), kind: "probe-unattended", run: this.id, mode: this.opts.mode, method: e.method, url: e.url, status: e.status, error: e.error });
    }
    const max = this.deps.maxProbes ?? 1000;
    if (this.probes > max && !this.ac.signal.aborted) this.stop(`budget: more than ${max} requests in one run`);
  }

  /* ---------- control ---------- */

  decide(requestId: string, d: Decision): boolean {
    const fn = this.pending.get(requestId);
    if (!fn) return false;
    this.pending.delete(requestId);
    fn(d);
    return true;
  }

  /** The kill switch: aborts in-flight requests and model calls, denies pending approvals. */
  stop(reason = "stopped by the user"): void {
    if (this.ac.signal.aborted) return;
    this.stopReason = reason;
    this.journal.append("stop", { reason });
    this.ac.abort(new Error(reason));
    for (const [id, fn] of this.pending) { this.pending.delete(id); fn("deny"); }
  }

  private get aborted() { return this.ac.signal.aborted; }

  /* ---------- the run ---------- */

  async start(): Promise<void> {
    this.journal.append("run.start", { prompt: this.opts.prompt, title: this.title, mode: this.opts.mode, intent: this.intent, model: this.opts.model ?? null, llm: this.deps.llm?.label ?? null });
    this.ui({ kind: "user", text: this.opts.prompt });
    this.phase("running");
    let outcome = "done";
    try {
      if (this.intent === "chat") await this.chat();
      else if (this.intent === "goal" && this.goal) outcome = await this.goalLoop(this.goal);
      else await this.plan(this.intent);
      if (this.aborted) outcome = "stopped";
    } catch (err) {
      if (this.aborted) outcome = "stopped";
      else { outcome = "error"; this.ui({ kind: "note", text: `Erreur: ${(err as Error).message}`, tone: "warn" }); }
    }
    if (outcome === "stopped") this.ui({ kind: "note", text: this.stopReason.startsWith("monitor") || this.stopReason.startsWith("budget") ? `Run arrêté (${this.stopReason}). Rien de plus n'a été envoyé.` : "Interrompu. Que dois-je faire à la place ?", tone: "warn" });
    this.status = outcome === "stopped" ? "stopped" : outcome === "error" ? "error" : "done";
    this.journal.append("run.end", { outcome, reason: this.stopReason || undefined, probes: this.probes, tokens: this.tokens, ms: Date.now() - this.started });
    this.phase("idle");
  }

  private steps(intent: Intent): string[] {
    const enabled = new Set(this.checks.map((c) => c.name));
    const has = (tool: string) => (TOOL_CHECKS[tool] ?? []).some((c) => enabled.has(c));
    const authz = (this.deps.config.options["authz-matrix"] ?? {}) as AuthzOptions;
    const authzOn = (authz.resources ?? []).length > 0 && (enabled.has("authz-matrix") || this.deps.config.checks.length === 0);
    const scan = ["scan.secrets", "scan.repo", "scan.deps", "scan.baas", "scan.web"].filter(has);
    const tail = ["validate.claims", "tests.generate"];
    if (intent === "authz") return authzOn ? ["authz.matrix", ...tail] : [];
    if (intent === "secrets") return [...["scan.secrets", "scan.baas"].filter(has), "validate.claims"];
    if (intent === "tests") return this.deps.store.findings().items.length ? ["tests.generate"] : [...scan, ...tail];
    // The optional toolbox: in a full scan when options.toolbox.enabled, always on /tools.
    const tools = ["tools.trufflehog", ...(this.scope.stagingUrl ? ["tools.katana", "tools.nuclei"] : [])];
    if (intent === "tools") return [...tools, ...tail];
    const review = this.deps.llm && this.scope.stagingUrl && scan.includes("scan.web") ? ["review.bundle"] : [];
    return [...scan, ...review, ...(this.toolboxEnabled() ? tools : []), ...(authzOn ? ["authz.matrix"] : []), ...tail];
  }

  /** One pass of the plan. Returns the findings it produced, validated. */
  private async plan(intent: Intent, iteration = 0): Promise<StoredFinding[]> {
    const steps = this.steps(intent);
    if (steps.length === 0) {
      this.ui({ kind: "say", text: "Rien à rejouer: aucune ressource n'est déclarée dans options.authz-matrix de la config." });
      return [];
    }
    if (iteration <= 1) {
      this.ui({ kind: "think", dur: "0 s", text: this.reasoning(intent, steps) });
      this.ui({ kind: "plan", steps: steps.map((t) => ({ tool: t, label: LABEL[t] ?? t })) });
    }
    const found: Finding[] = [];
    const claims: Claim[] = [];
    const ran = new Set<string>();
    const outputs: string[] = [];
    // Toolbox leads, already replayed by the validators inside runTool.
    const toolFound: { f: Finding; v?: ClaimVerdict }[] = [];
    for (const tool of steps) {
      if (this.aborted) break;
      if (tool === "validate.claims") {
        const validated = await this.validateTool(found, claims, outputs, toolFound);
        return this.finish(validated, ran, steps.includes("tests.generate"));
      }
      if (tool === "tests.generate") continue; // done in finish()
      if (tool === "authz.matrix") { claims.push(...(await this.authzTool(found, ran))); continue; }
      if (tool === "review.bundle") { toolFound.push(...(await this.reviewTool())); ran.add("bundle-review"); continue; }
      if (tool.startsWith("tools.")) {
        const out = await this.toolboxTool(tool.slice(6) as ToolName);
        toolFound.push(...out.found);
        if (out.ran) ran.add(`toolbox.${tool.slice(6)}`);
        continue;
      }
      const out = await this.checkTool(tool);
      found.push(...out.findings);
      out.ran.forEach((c) => ran.add(c));
      outputs.push(...out.findings.map((f) => `${f.check} | ${f.title} | ${f.location}`));
    }
    if (steps.includes("tests.generate") && !this.aborted) return this.finish([], ran, true);
    return [];
  }

  private toolboxEnabled(): boolean {
    try { return toolboxOptions(this.deps.config).enabled; } catch { return false; }
  }

  /**
   * One toolbox tool in its container. Network tools go through the gate (the
   * declared stagingUrl), then the scoped egress proxy enforces the same rules
   * as the scoped client on every request the tool sends. Refusals of the proxy
   * are journalled but do not trip the three-refusals monitor (blocking a tool's
   * stray request is the proxy doing its job); a separate cap stops the run.
   */
  private async toolboxTool(name: ToolName): Promise<{ found: { f: Finding; v?: ClaimVerdict }[]; ran: boolean }> {
    const tool = `tools.${name}`;
    const t0 = Date.now();
    const input = JSON.stringify({ outil: name, conteneur: name === "trufflehog" ? "--network none, projet en lecture seule" : "réseau interne, sortie unique: proxy à périmètre", cible: name === "trufflehog" ? "projectDir" : this.scope.stagingUrl }, null, 2);
    let opts;
    try { opts = toolboxOptions(this.deps.config); } catch (err) {
      this.ui({ kind: "note", tone: "warn", text: `${tool}: ${(err as Error).message}` });
      return { found: [], ran: false };
    }
    const st = await dockerStatus(opts.image);
    if (!st.available || !st.imagePresent) {
      this.ui({ kind: "note", tone: "muted", text: `${tool}: boîte à outils désactivée (${st.reason}). Le reste du scan continue.` });
      return { found: [], ran: false };
    }
    if (name !== "trufflehog") {
      const url = this.scope.stagingUrl;
      if (!url || !(await this.gated(tool, [{ method: "GET", url }]))) return { found: [], ran: false };
    }
    let toolRefusals = 0;
    const maxProbes = (this.deps.maxProbes ?? 1000) + opts.maxRequests;
    const scope = new Scope({
      allowedHosts: this.deps.config.scope.allowedHosts, allowActiveTesting: this.deps.config.scope.allowActiveTesting,
      allowPrivate: this.deps.config.scope.allowPrivate, stagingUrl: this.deps.config.scope.stagingUrl, signal: this.ac.signal,
      onRequest: (e) => {
        this.journal.append("net", { ...e, tool: name });
        if (e.refused) {
          if (++toolRefusals >= 200 && !this.ac.signal.aborted) this.stop(`monitor: ${name} had 200 requests refused by the egress proxy`);
          return;
        }
        this.probes++;
        if (this.unattended) this.deps.store.appendAudit({ at: new Date().toISOString(), kind: "probe-unattended", run: this.id, mode: this.opts.mode, method: e.method, url: e.url, status: e.status, error: e.error, tool: name });
        if (this.probes > maxProbes && !this.ac.signal.aborted) this.stop(`budget: more than ${maxProbes} requests in one run`);
      },
    });
    const uid = this.ui({ kind: "tool", tool, args: name, input, lines: ["…"], dur: "" });
    const r = await runTool({
      tool: name, config: this.deps.config, projectDir: this.projectDir, scope, checks: this.checks, signal: this.ac.signal, status: st,
      onEvent: (e) => this.deps.store.appendAudit({ ...e, run: this.id }),
    });
    this.unattended = false;
    const verdictOf = new Map(r.verdicts.map((v) => [v.claimId.replace(/^claim:/, ""), v]));
    const lines = r.ran
      ? [`${r.findings.length} piste(s), ${r.findings.filter((f) => f.state === "proven").length} prouvée(s) par un validateur Crenel`,
        r.network === "none" ? "aucun réseau (--network none)" : `${r.proxy?.requests ?? 0} requête(s) via le proxy, ${r.proxy?.refused ?? 0} refusée(s)`,
        ...(r.timedOut ? ["arrêté: délai dépassé"] : []),
        ...r.suggestions.slice(0, 5).map((s) => `route à déclarer dans la matrice: ${s.path}`)]
      : [`non lancé: ${r.reason}`];
    this.journal.append("toolbox", { tool: name, ran: r.ran, reason: r.reason, exit: r.exit, network: r.network, proxy: r.proxy, raw: r.raw ? { sha256: r.raw.sha256, bytes: r.raw.bytes } : undefined, suggestions: r.suggestions });
    this.uiUpdate(uid, { kind: "tool", tool, args: name, input, lines, findings: r.findings.slice(0, 8).map((f) => ({ sev: SEV[f.severity], text: f.title, state: webState(f.state), id: uidOf(f.id) })), dur: ms(Date.now() - t0) });
    return { found: r.findings.map((f) => ({ f, v: verdictOf.get(f.id) })), ran: r.ran };
  }

  private reasoning(intent: Intent, steps: string[]): string {
    const cfg = this.deps.config.scope;
    const net = steps.some((s) => ["scan.web", "scan.baas", "authz.matrix"].includes(s));
    const mode = this.opts.mode === "readonly" ? "Mode lecture seule: aucune requête ne sortira." : this.opts.mode === "bypass" ? "Mode bypass: je n'interromps pas pour demander, le périmètre reste appliqué et chaque sonde est inscrite à l'audit." : "Je demanderai votre accord avant toute requête vers un hôte.";
    return `Plan déterministe pour « ${intent} ». D'abord ce qui se lit sans réseau (bundle, dépôt, lockfile). ` +
      (net ? `Ensuite les vérifications réseau, seulement vers ${cfg.allowedHosts.join(", ") || "(aucun hôte déclaré)"}; ${cfg.allowActiveTesting ? "les sondes actives sont permises par la config" : "les sondes actives sont coupées dans la config (allowActiveTesting: false)"}. ` : "") +
      `${mode} Rien n'est marqué prouvé sans qu'un validateur ait rejoué la preuve lui-même.`;
  }

  private ctx(scope: Scope): CheckContext {
    return { scope, projectDir: this.projectDir, stagingUrl: scope.stagingUrl, options: this.deps.config.options, log: (m) => this.journal.append("log", { m }) };
  }

  /** A scope that cannot reach anything: for tools the gate kept offline. */
  private offlineScope(): Scope {
    return new Scope({ allowedHosts: [], signal: this.ac.signal });
  }

  private async gated(tool: string, requests: PlannedRequest[]): Promise<boolean> {
    const grants = new Set([...this.deps.grants, ...this.runGrants]);
    const d: GateDecision = await authorize({ tool, requests }, { scope: this.scope, mode: this.opts.mode, grants, userRequest: this.opts.prompt }, this.deps.judge);
    this.journal.append("gate", { tool, requests: requests.length, ...d });
    if (d.verdict === "deny") {
      this.ui({ kind: "note", tone: "muted", text: `${tool}: aucune requête envoyée. ${d.reasons.join("; ")}.` });
      return false;
    }
    if (d.verdict === "allow") {
      // Hosts the user approved earlier in this same task are not "unattended".
      const approvedHere = this.opts.mode !== "bypass" && d.hosts.every((h) => this.runGrants.has(h));
      this.unattended = d.unattended && !approvedHere;
      if (this.unattended) this.ui({ kind: "note", tone: "muted", text: `${tool}: ${requests.length} requête(s) vers ${d.hosts.join(", ")} sans question (${this.opts.mode === "bypass" ? "mode Bypass" : "hôte autorisé pour la session"}), inscrites à l'audit.` });
      return true;
    }
    const id = `p-${randomBytes(4).toString("hex")}`;
    const shown = requests.slice(0, 12).map((r) => `${r.method.toUpperCase().padEnd(4)} ${pathOf(r.url)}`);
    if (requests.length > 12) shown.push(`… et ${requests.length - 12} autres`);
    this.ui({ kind: "permission", id, tool, host: d.hosts.join(", "), requests: shown });
    this.phase("waiting");
    const decision = await new Promise<Decision>((res) => {
      this.pending.set(id, res);
      if (this.aborted) { this.pending.delete(id); res("deny"); }
    });
    this.journal.append("decision", { id, tool, decision, hosts: d.hosts });
    this.phase("running");
    if (decision === "deny") {
      if (!this.aborted) this.ui({ kind: "note", tone: "muted", text: `Refusé. Rien n'a été envoyé à ${d.hosts.join(", ")}.` });
      return false;
    }
    for (const h of d.hosts) { this.runGrants.add(h); if (decision === "always") this.deps.grants.add(h); }
    this.unattended = false;
    return true;
  }

  private inline(fs: Finding[], claimed = true): InlineFinding[] {
    // Before validation, nothing is shown as proven: a check's output is a claim.
    return fs.slice(0, 8).map((f) => ({ sev: SEV[f.severity], text: f.title, state: claimed ? "lead" : webState(f.state), id: uidOf(f.id) }));
  }

  /** The model reads every chunk the site serves; what it says stays a lead. */
  private async reviewTool(): Promise<{ f: Finding; v?: ClaimVerdict }[]> {
    const llm = this.deps.llm!;
    const url = this.scope.stagingUrl!;
    const t0 = Date.now();
    const uid = this.ui({ kind: "tool", tool: "review.bundle", args: llm.label, input: JSON.stringify({ start: url }, null, 2), lines: ["…"], dur: "" });
    // The crawl is the same GETs scan.web already had approved.
    if (!(await this.gated("review.bundle", [{ method: "GET", url }, { method: "GET", url: `${url.replace(/\/+$/, "")}/assets/*.js (chunks)` }]))) {
      this.uiUpdate(uid, { kind: "tool", tool: "review.bundle", args: llm.label, input: "", lines: ["non lancé (requêtes refusées)"], dur: ms(Date.now() - t0) });
      return [];
    }
    const { files, bytes } = await crawlLiveBundle(this.ctx(this.scope), url);
    const r = await reviewBundle(files, llm, { signal: this.ac.signal, maxCalls: 6, log: (m) => this.journal.append("note", { text: m }) });
    const lines = [
      `${files.length} fichier(s), ${Math.round(bytes / 1024)} Ko lus par le modèle en ${r.calls} appel(s)`,
      `${r.findings.length} piste(s), ${r.dropped} écartée(s) (citation introuvable dans le fichier)`,
      ...(r.endpoints.length ? [`endpoints à ajouter à la matrice: ${r.endpoints.map((e) => `${e.method} ${e.path}`).join(", ")}`] : []),
      ...(r.unseenChars ? [`${Math.round(r.unseenChars / 1024)} Ko non relus (budget d'appels)`] : []),
    ];
    this.uiUpdate(uid, { kind: "tool", tool: "review.bundle", args: llm.label, input: JSON.stringify({ start: url, files: files.length }, null, 2), lines, findings: this.inline(r.findings), dur: ms(Date.now() - t0) });
    return r.findings.map((f) => ({ f }));
  }

  private async checkTool(tool: string): Promise<{ findings: Finding[]; ran: string[] }> {
    const names = new Set(TOOL_CHECKS[tool] ?? []);
    const checks = this.checks.filter((c) => names.has(c.name));
    const t0 = Date.now();
    const args = checks.map((c) => c.name).join(", ");
    const input = JSON.stringify({ checks: checks.map((c) => c.name), dir: this.projectDir.split(/[\\/]/).slice(-2).join("/") }, null, 2);
    let scope = this.offlineScope();
    let skip = false;
    if (tool === "scan.web") {
      // The live checks only send GETs: the page and its chunks, a list of known
      // file paths, an introspection query, redirect probes, and one request per
      // declared host for takeovers. The gate sees one line per kind.
      const url = this.scope.stagingUrl;
      if (url) {
        const base = url.replace(/\/+$/, "");
        const reqs: PlannedRequest[] = [
          { method: "GET", url }, { method: "GET", url: `${base}/assets/*.js (chunks)` }, { method: "GET", url: `${base}/.env, /.git/config…` },
          { method: "GET", url: `${base}/graphql?query={__schema…}` }, { method: "GET", url: `${base}/login?next=https://crenel-redirect-check.invalid` },
          { method: "GET", url: `${base}/_next/image?url=https://example.com/ (the site fetches it, not Crenel)` }, { method: "GET", url: `${base}/openapi.json, /v3/api-docs…` },
          ...this.scope.allowedHosts.filter((h) => /[a-z]/i.test(h) && hostOf(url) !== h).map((h) => ({ method: "GET", url: `https://${h}/` })),
        ];
        if (await this.gated(tool, reqs)) scope = this.scope; else skip = true;
      }
    }
    if (tool === "scan.baas") {
      const reqs = scanBaas(this.projectDir).filter((h) => h.kind === "supabase" && this.scope.isHostAllowed(h.url))
        .map((h) => ({ method: "GET", url: `${(h as { url: string }).url}/rest/v1/` }));
      if (reqs.length && this.scope.allowActiveTesting && (await this.gated(tool, [...reqs, ...reqs.map((r) => ({ method: "GET", url: r.url + "<table>?select=*&limit=1" })), ...reqs.map((r) => ({ method: "GET", url: r.url + "rpc/<function> (read-only transaction)" }))]))) scope = this.scope;
    }
    const uid = this.ui({ kind: "tool", tool, args, input, lines: ["…"], dur: "" });
    const findings: Finding[] = [];
    const ran: string[] = [];
    const lines: string[] = [];
    if (!skip) {
      for (const c of checks) {
        if (this.aborted) break;
        try {
          const out = await c.run(this.ctx(scope));
          findings.push(...out);
          ran.push(c.name);
        } catch (err) {
          lines.push(`${c.name}: échec (${(err as Error).message})`);
        }
      }
    }
    this.unattended = false;
    lines.unshift(skip ? "non lancé (requêtes refusées)" : `${ran.length} check(s), ${findings.length} constat(s) soumis au validateur`);
    this.uiUpdate(uid, { kind: "tool", tool, args, input, lines, findings: this.inline(findings), dur: ms(Date.now() - t0) });
    return { findings, ran };
  }

  /** Observe the matrix (who reaches B's objects), then turn every non-denied cell into a claim. */
  private async authzTool(found: Finding[], ran: Set<string>): Promise<Claim[]> {
    const opts = (this.deps.config.options["authz-matrix"] ?? {}) as AuthzOptions;
    const resources = opts.resources ?? [];
    const base = this.scope.stagingUrl;
    const actors = [
      ...(opts.accounts?.a?.token ? [{ id: "a", label: "Compte A", role: "autre tenant", token: opts.accounts.a.token }] : []),
      ...(opts.accounts?.c?.token ? [{ id: "c", label: "Compte C", role: "3e tenant", token: opts.accounts.c.token }] : []),
      { id: "anon", label: "Anonyme", role: "sans jeton", token: undefined as string | undefined },
    ];
    const t0 = Date.now();
    const input = JSON.stringify({ attaquants: actors.map((a) => a.label), cible: "ressources du compte B", ressources: resources.map((r) => r.path) }, null, 2);
    const notes: string[] = [];
    if (!base || !opts.accounts?.a?.token) {
      const uid = this.ui({ kind: "tool", tool: "authz.matrix", args: "hors ligne", input, lines: ["…"], dur: "" });
      // Offline: the registry check emits the test plan as a lead.
      const off = REGISTRY.find((c) => c.name === "authz-matrix")!;
      const out = await off.run(this.ctx(this.offlineScope()));
      found.push(...out);
      ran.add("authz-matrix");
      this.uiUpdate(uid, { kind: "tool", tool: "authz.matrix", args: "hors ligne", input, lines: [!base ? "Pas de stagingUrl: matrice générée, aucune requête." : "Pas de jeton pour le compte A: matrice générée, aucune requête."], findings: this.inline(out), dur: ms(Date.now() - t0) });
      return [];
    }
    const cases: { r: typeof resources[number]; id: string; actor: typeof actors[number]; url: string }[] = [];
    for (const r of resources) {
      const methods = (r.methods ?? ["GET"]).map((m) => m.toUpperCase());
      for (const m of methods.filter((m) => m !== "GET" && m !== "HEAD")) notes.push(`${m} ${r.path}: jamais envoyé (méthode qui modifie l'état, BOLA d'action en roadmap)`);
      if (!methods.includes("GET")) continue;
      for (const id of opts.accounts?.b?.owns?.[r.name] ?? []) for (const actor of actors) cases.push({ r, id, actor, url: authzUrl(base, r, id) });
    }
    const requests = cases.map((c) => ({ method: "GET", url: c.url }));
    const unique = [...new Map(requests.map((r) => [r.url, r])).values()];
    const allowed = await this.gated("authz.matrix", unique);
    const uid = this.ui({ kind: "tool", tool: "authz.matrix", args: `${actors.map((a) => a.label).join(", ")} → ressources de B`, input, lines: ["…"], dur: "" });
    const matrix: AuthzMatrix = {
      at: new Date().toISOString(), run: this.id,
      resources: resources.map((r) => ({ id: r.name, label: r.name, route: `${(r.methods ?? ["GET"]).join("/")} ${r.path}` })),
      actors: actors.map((a) => ({ id: a.id, label: a.label, role: a.role, cells: {} })),
      replay: {}, notes,
    };
    const claims: Claim[] = [];
    const lines: string[] = [];
    if (allowed) {
      for (const c of cases) {
        if (this.aborted) break;
        let status: number | undefined;
        try {
          const res = await safeFetch(c.url, this.scope, { headers: c.actor.token ? { authorization: `Bearer ${c.actor.token}` } : {} });
          status = res.status;
        } catch (err) {
          lines.push(`${c.actor.label} GET ${pathOf(c.url)} → erreur (${(err as Error).message})`);
          continue;
        }
        lines.push(`${c.actor.label.padEnd(8)} GET ${pathOf(c.url)} → ${status}`);
        const row = matrix.actors.find((a) => a.id === c.actor.id)!;
        const prev = row.cells[c.r.name];
        // A cell shows the worst case across B's ids: any 2xx wins.
        if (prev === undefined || (status >= 200 && status < 300)) row.cells[c.r.name] = status;
        matrix.replay[`${c.actor.id}:${c.r.name}`] = `curl -i ${c.actor.token ? `-H 'authorization: Bearer $TOKEN_${c.actor.id.toUpperCase()}' ` : ""}'${c.url}'`;
        if (status >= 200 && status < 300) {
          claims.push({ id: `claim:authz:${c.actor.id}:${c.r.name}:${c.id}`, class: "authz.cross-tenant", source: "agent", detail: { resource: c.r.name, id: c.id, actor: c.actor.id } });
        }
      }
      this.unattended = false;
      ran.add("authz-matrix");
      this.deps.store.saveAuthz(matrix);
    }
    lines.push(...notes);
    if (!allowed) lines.unshift("non lancé (requêtes refusées)");
    else lines.unshift(`${cases.length} requête(s), ${claims.length} réponse(s) à valider`);
    this.uiUpdate(uid, { kind: "tool", tool: "authz.matrix", args: `${actors.map((a) => a.label).join(", ")} → ressources de B`, input, lines, dur: ms(Date.now() - t0) });
    return claims;
  }

  /** Every finding and every agent claim goes through a validator. Nothing else writes proven. */
  private async validateTool(found: Finding[], agentClaims: Claim[], outputs: string[], toolFound: { f: Finding; v?: ClaimVerdict }[] = []): Promise<StoredFinding[]> {
    const t0 = Date.now();
    const llmClaims = await this.proposeClaims(outputs);
    const fromChecks = found.map((f) => ({ f, claim: claimFor(f) }));
    const all = [...fromChecks.map((x) => x.claim), ...agentClaims, ...llmClaims];
    const uid = this.ui({ kind: "tool", tool: "validate.claims", args: `${all.length} affirmation(s)`, input: JSON.stringify({ claims: all.length, sources: { checks: fromChecks.length, agent: agentClaims.length, modele: llmClaims.length } }, null, 2), lines: ["…"], dur: "" });

    // Network replays only toward hosts already approved in this run (or bypass/grants).
    // Checks that read the network (headers, BaaS) replay through the network too.
    const NET_CHECKS = new Set(["headers", "baas-exposure", ...TOOL_CHECKS["scan.web"]!]);
    const netReplay = (c: Claim) => c.class !== "check.replay" || NET_CHECKS.has(String(c.detail.check));
    const needsNet = all.filter(netReplay);
    let netScope = this.offlineScope();
    if (needsNet.length) {
      const reqs: PlannedRequest[] = needsNet.map((c) => ({ method: "GET", url: String(c.detail.url ?? this.scope.stagingUrl ?? "") })).filter((r) => r.url);
      const hosts = new Set(reqs.map((r) => hostOf(r.url)));
      const preApproved = [...hosts].every((h) => this.runGrants.has(h) || this.deps.grants.has(h)) || this.opts.mode === "bypass";
      if (reqs.length && (preApproved ? await this.gated("validate.claims", reqs) : false)) netScope = this.scope;
    }
    const env = { scope: netScope, projectDir: this.projectDir, options: this.deps.config.options, stagingUrl: this.scope.stagingUrl, checks: this.checks };
    const out: StoredFinding[] = [];
    const lines: string[] = [];
    const verdicts = new Map<string, ClaimVerdict>();
    for (const c of all) {
      if (this.aborted) break;
      const v = netReplay(c) ? await validateClaim(c, env) : await validateClaim(c, { ...env, scope: this.offlineScope() });
      verdicts.set(c.id, v);
      this.journal.append("verdict", { claim: c, verdict: v });
    }
    this.unattended = false;
    const now = new Date().toISOString();
    for (const { f, claim } of fromChecks) {
      const v = verdicts.get(claim.id);
      const state: Finding["state"] = v?.state === "proven" ? "proven" : "unproven";
      out.push({ ...f, state, uid: uidOf(f.id), firstSeen: now, lastSeen: now, validator: v?.validator ?? null, verdict: v?.reason, evidence: v?.evidence });
    }
    const opts = (this.deps.config.options["authz-matrix"] ?? {}) as AuthzOptions;
    for (const c of [...agentClaims, ...llmClaims]) {
      const v = verdicts.get(c.id);
      if (!v) continue;
      if (c.class === "authz.cross-tenant") {
        const r = (opts.resources ?? []).find((x) => x.name === c.detail.resource);
        const who = c.detail.actor === "anon" ? "Un visiteur sans jeton" : `Le compte ${String(c.detail.actor).toUpperCase()}`;
        const url = r && this.scope.stagingUrl ? authzUrl(this.scope.stagingUrl, r, String(c.detail.id)) : "";
        const id = `authz-matrix:${c.detail.resource}:GET:${c.detail.id}:${c.detail.actor}`;
        out.push({
          id, uid: uidOf(id), check: "authz-matrix", firstSeen: now, lastSeen: now,
          title: `${who} lit le ${c.detail.resource} du compte B`,
          severity: v.state === "proven" ? "critical" : "high",
          state: v.state, location: url ? `GET ${pathOf(url)}` : String(c.detail.resource),
          description: v.state === "proven"
            ? `${who} obtient l'objet ${c.detail.id} qui appartient au compte B. ${v.reason}. Contrôle d'appartenance absent côté serveur.`
            : `Réponse 2xx sur l'objet ${c.detail.id} du compte B, mais la preuve n'est pas faite: ${v.reason}.`,
          remediation: "Filtrer chaque lecture par compte côté serveur (where owner_id = session.account_id) et renvoyer 404 sinon. Garder le test généré en CI.",
          proof: v.evidence ? { method: v.validator ?? "validateur", replay: v.evidence.request.replace(/\n/g, " | "), evidence: `${v.evidence.response.split("\n")[0]} · témoin: ${v.evidence.control ?? "-"}` } : undefined,
          validator: v.validator, verdict: v.reason, evidence: v.evidence,
          regressionHint: `${who} ne doit jamais lire ${c.detail.resource} ${c.detail.id}.`,
        });
      } else if (v.state === "proven" && c.source === "llm") {
        lines.push(`proposition du modèle confirmée par ${v.validator}: ${v.reason}`);
      }
    }
    // Toolbox leads: their state was decided by a validator inside runTool. A
    // lead proven by replaying a Crenel check is dropped when that check's own
    // finding is already in this run (same place), to avoid a duplicate.
    const have = new Set(out.map((f) => `${f.check}|${f.location}`));
    for (const { f, v } of toolFound) {
      if (f.state === "proven" && v?.validator?.endsWith(":exposed-secrets") && have.has(`exposed-secrets|${f.location}`)) continue;
      out.push({ ...f, uid: uidOf(f.id), firstSeen: now, lastSeen: now, validator: v?.validator ?? null, verdict: v?.reason, evidence: v?.evidence });
    }
    const proven = out.filter((f) => f.state === "proven").length;
    const noValidator = [...verdicts.values()].filter((v) => !v.validator).length;
    lines.unshift(`${proven} prouvé(s) par rejeu, ${out.length - proven} piste(s) non prouvée(s)${noValidator ? `, dont ${noValidator} sans validateur pour leur classe` : ""}`);
    for (const c of llmClaims) lines.push(`modèle: ${c.class} → ${verdicts.get(c.id)?.state ?? "?"} (${verdicts.get(c.id)?.reason ?? ""})`);
    this.uiUpdate(uid, { kind: "tool", tool: "validate.claims", args: `${all.length} affirmation(s)`, input: JSON.stringify({ claims: all.length }, null, 2), lines, findings: out.filter((f) => f.state === "proven").slice(0, 8).map((f) => ({ sev: SEV[f.severity], text: f.title, state: "proven" as const, id: f.uid })), dur: ms(Date.now() - t0) });
    return out;
  }

  /** Optional: a model reads the (fenced, untrusted) tool outputs and may propose claims. Validators decide. */
  private async proposeClaims(outputs: string[]): Promise<Claim[]> {
    const llm = this.deps.llm;
    if (!llm || outputs.length === 0 || this.aborted) return [];
    const authz = (this.deps.config.options["authz-matrix"] ?? {}) as AuthzOptions;
    const prompt = `${UNTRUSTED_PREAMBLE}\nTu aides un outil défensif sur un système que l'utilisateur possède. Propose au plus 3 affirmations à faire vérifier par des validateurs déterministes, en JSON strict: ` +
      `[{"class":"authz.cross-tenant","detail":{"resource":"<nom déclaré>","id":"<id déclaré de B>","actor":"a|anon"}}]. Ressources déclarées: ${JSON.stringify((authz.resources ?? []).map((r) => r.name))}. ` +
      `Réponds [] si rien. Aucune autre classe, aucun texte hors JSON.\n${fence(untrusted("tool-outputs", outputs.join("\n"), 6000))}`;
    try {
      const raw = await llm.ask(prompt, { signal: this.ac.signal, timeoutMs: 90_000 });
      this.tokens += estimateTokens(prompt) + estimateTokens(raw);
      const json = raw.slice(raw.indexOf("["), raw.lastIndexOf("]") + 1);
      const parsed = z.array(z.object({ class: z.literal("authz.cross-tenant"), detail: z.object({ resource: z.string(), id: z.string(), actor: z.enum(["a", "anon"]) }) })).max(3).safeParse(JSON.parse(json || "[]"));
      if (!parsed.success) { this.journal.append("llm.rejected", { reason: "schema" }); return []; }
      return parsed.data.map((c, i) => ({ id: `claim:llm:${i}:${c.detail.resource}:${c.detail.id}:${c.detail.actor}`, class: c.class, source: "llm" as const, detail: c.detail }));
    } catch (err) {
      this.journal.append("llm.error", { message: (err as Error).message });
      return [];
    }
  }

  /** Persist, generate tests, summarise. */
  private async finish(validated: StoredFinding[], ran: Set<string>, genTests: boolean): Promise<StoredFinding[]> {
    const store = this.deps.store;
    const merged = validated.length || ran.size ? store.mergeFindings(this.id, validated, [...ran]) : store.findings().items;
    if (ran.size) {
      store.appendAudit({
        at: new Date(this.started).toISOString(), kind: "scan", run: this.id, project: this.deps.config.project,
        scope: { allowedHosts: this.deps.config.scope.allowedHosts, allowActiveTesting: this.deps.config.scope.allowActiveTesting, stagingUrl: this.deps.config.scope.stagingUrl },
        mode: this.opts.mode, checks: [...ran], errors: 0,
        findings: validated.map((f) => ({ id: f.id, severity: f.severity, state: f.state, validator: f.validator ?? null })),
      });
    }
    if (genTests && !this.aborted) this.testsTool(merged);
    const proven = merged.filter((f) => f.state === "proven").length;
    const leads = merged.filter((f) => f.state === "unproven").length;
    const fixed = merged.filter((f) => f.state === "fixed").length;
    this.journal.append("results", { proven, leads, fixed, ran: [...ran] });
    if (!this.aborted && this.intent !== "goal") await this.summary(merged);
    return merged;
  }

  private testsTool(findings: StoredFinding[]): void {
    const t0 = Date.now();
    const targets = findings.filter((f) => f.state === "proven" || f.state === "fixed");
    const file = generateRegressionFile(targets);
    const prev = new Map(this.deps.store.tests().map((t) => [t.uid, t]));
    const list: StoredTest[] = [];
    for (const f of targets) {
      if (!/\btest\(/.test(generateRegressionFile([f]))) continue;
      list.push(prev.get(f.uid) ?? { uid: f.uid, name: f.regressionHint && f.regressionHint.length < 90 ? f.regressionHint : f.title, check: f.check, status: "draft", at: new Date().toISOString() });
    }
    this.deps.store.saveTests(list, file);
    const firstTest = file.slice(file.indexOf("test("));
    this.ui({
      kind: "tool", tool: "tests.generate", args: `${targets.length} faille(s) prouvée(s)`, dur: ms(Date.now() - t0),
      input: JSON.stringify({ findings: targets.map((f) => f.uid) }, null, 2),
      lines: [`${list.length} test(s) en brouillon dans .crenel/regression.test.ts`, "Rien n'est écrit dans votre dépôt."],
      ...(list.length ? { code: { file: ".crenel/regression.test.ts", body: firstTest.slice(0, 900) } } : {}),
    });
  }

  private async summary(findings: StoredFinding[]): Promise<void> {
    const proven = findings.filter((f) => f.state === "proven");
    const leads = findings.filter((f) => f.state === "unproven");
    const crit = proven.filter((f) => f.severity === "critical").length;
    let text = `${proven.length} faille(s) prouvée(s)${crit ? `, dont ${crit} critique(s)` : ""}, ${leads.length} piste(s) non prouvée(s) (pas de preuve, pas de rapport: elles restent des pistes). ` +
      (proven.length ? `À traiter d'abord: ${proven.slice(0, 3).map((f) => f.title).join(" · ")}.` : "Rien de prouvé sur ce périmètre.");
    if (this.deps.llm && proven.length + leads.length > 0) {
      const data = findings.slice(0, 30).map((f) => `${f.state} | ${f.severity} | ${f.title} | ${f.location}`).join("\n");
      const prompt = `${UNTRUSTED_PREAMBLE}\nRésume pour un fondateur, en français, en 3 phrases maximum, quoi corriger d'abord. Les états (proven/unproven) sont décidés par des validateurs, ne les change pas.\n${fence(untrusted("findings", data))}`;
      try {
        const raw = await this.deps.llm.ask(prompt, { signal: this.ac.signal, timeoutMs: 90_000 });
        this.tokens += estimateTokens(prompt) + estimateTokens(raw);
        if (raw) text = `${text}\n\n${raw}`;
      } catch (err) {
        this.journal.append("llm.error", { message: (err as Error).message });
      }
    }
    this.ui({ kind: "say", text });
  }

  private async chat(): Promise<void> {
    const q = this.opts.prompt.trim();
    const store = this.deps.store.findings().items;
    const s = q.toLowerCase();
    let text = "";
    if (s.startsWith("/cible")) {
      const sc = this.deps.config.scope;
      text = `Cible: ${this.deps.config.project}. Hôtes déclarés: ${sc.allowedHosts.join(", ") || "aucun"}. Sondes actives: ${sc.allowActiveTesting ? "permises par la config" : "coupées"}. Tout autre hôte est refusé par le client réseau.`;
    } else if (s.startsWith("/fix")) {
      text = "Crenel ne modifie pas votre code. Pour chaque faille prouvée, la remédiation est dans sa fiche, et le test de régression est généré dans .crenel/regression.test.ts.";
    } else if (this.deps.llm) {
      const data = store.slice(0, 40).map((f) => `${f.uid} | ${f.state} | ${f.severity} | ${f.title} | ${f.location} | ${f.remediation}`).join("\n");
      const prompt = `${UNTRUSTED_PREAMBLE}\nTu es l'assistant de l'outil défensif Crenel, sur un système que l'utilisateur possède. Réponds en français, court. Tu ne peux rien marquer comme prouvé. Question de l'utilisateur: ${q}\n${fence(untrusted("findings", data))}`;
      try {
        text = await this.deps.llm.ask(prompt, { signal: this.ac.signal, timeoutMs: 90_000 });
        this.tokens += estimateTokens(prompt) + estimateTokens(text);
      } catch (err) {
        text = `Modèle indisponible (${(err as Error).message}).`;
      }
    } else {
      const words = s.replace(/^\/explain\s*/, "").split(/[^a-z0-9_-]+/).filter((w) => w.length > 3);
      const f = store.find((x) => s.includes(x.uid)) ?? store.find((x) => words.some((w) => x.title.toLowerCase().includes(w)));
      text = f
        ? `${f.title} (${f.state === "proven" ? "prouvé" : f.state === "fixed" ? "corrigé" : "piste"}). ${f.description} ${f.proof ? `Preuve: ${f.proof.replay}.` : ""} À faire: ${f.remediation}`
        : "Aucun modèle n'est branché (claude -p introuvable ou coupé), je ne réponds qu'aux commandes: /scan, /authz, /secrets, /test, /goal, /cible, /explain <finding>.";
    }
    this.ui({ kind: "say", text });
  }

  /* ---------- goal ---------- */

  evaluateGoal = async (goal: GoalSpec): Promise<GoalCheck> => {
    const items = this.deps.store.findings().items;
    const scanned = this.deps.store.findings().updatedAt !== undefined;
    const proven = items.filter((f) => f.state === "proven");
    if (goal.kind === "no-proven-critical") {
      const crit = proven.filter((f) => f.severity === "critical");
      return { met: scanned && crit.length === 0, verified: true, state: crit.map((f) => f.id).sort().join("|") + `#${scanned}`, detail: !scanned ? "aucun scan encore" : crit.length ? `${crit.length} critique(s) prouvée(s): ${crit.slice(0, 2).map((f) => f.title).join(" · ")}` : "aucune critique prouvée" };
    }
    if (goal.kind === "authz-isolation") {
      const m = this.deps.store.authz();
      if (!m) return { met: false, verified: true, state: "none", detail: "matrice jamais observée" };
      const untested = m.actors.flatMap((a) => m.resources.filter((r) => a.cells[r.id] === undefined).map((r) => `${a.label}/${r.id}`));
      const leaks = m.actors.flatMap((a) => m.resources.filter((r) => { const c = a.cells[r.id]; return c !== undefined && c >= 200 && c < 300; }).map((r) => `${a.label}/${r.id}`));
      const provenAuthz = proven.filter((f) => f.check === "authz-matrix");
      const met = untested.length === 0 && provenAuthz.length === 0 && leaks.length === 0;
      return { met, verified: true, state: JSON.stringify([untested, leaks, provenAuthz.map((f) => f.id)]), detail: met ? "toutes les cases refusées" : `${provenAuthz.length} fuite(s) prouvée(s), ${leaks.length} réponse(s) 2xx, ${untested.length} case(s) non testée(s)` };
    }
    if (goal.kind === "all-proven-tested") {
      const tested = new Set(this.deps.store.tests().map((t) => t.uid));
      const missing = proven.filter((f) => !tested.has(f.uid));
      return { met: scanned && missing.length === 0, verified: true, state: missing.map((f) => f.uid).sort().join("|") + `#${scanned}`, detail: !scanned ? "aucun scan encore" : missing.length ? `${missing.length} faille(s) prouvée(s) sans test généré` : `${proven.length} faille(s) prouvée(s), toutes avec un test généré (la présence en CI n'est pas vérifiable ici)` };
    }
    if (!this.deps.llm) return { met: false, verified: false, state: "nollm", detail: "no model to judge a free-text goal: use one of the built-in goals" };
    const data = items.slice(0, 40).map((f) => `${f.state} | ${f.severity} | ${f.title}`).join("\n");
    const prompt = `${UNTRUSTED_PREAMBLE}\nObjectif de l'utilisateur: « ${goal.text} ». D'après les constats, est-il atteint ? Réponds en JSON strict {"met":true|false,"why":"..."}.\n${fence(untrusted("findings", data))}`;
    try {
      const raw = await this.deps.llm.ask(prompt, { signal: this.ac.signal, timeoutMs: 90_000 });
      this.tokens += estimateTokens(prompt) + estimateTokens(raw);
      const j = JSON.parse(raw.slice(raw.indexOf("{"), raw.lastIndexOf("}") + 1)) as { met?: boolean; why?: string };
      return { met: j.met === true, verified: false, state: `${j.met}:${items.length}`, detail: `non vérifié (avis du modèle): ${String(j.why ?? "").slice(0, 200)}` };
    } catch (err) {
      return { met: false, verified: false, state: "llm-error", detail: `no model answer: ${(err as Error).message}` };
    }
  };

  private async goalLoop(goal: GoalSpec): Promise<string> {
    const intent: Intent = goal.kind === "authz-isolation" ? "authz" : goal.kind === "all-proven-tested" ? "tests" : "full";
    const t0 = Date.now();
    const res = await runGoal({
      goal,
      signal: this.ac.signal,
      emit: (type, data) => this.journal.append(type, data),
      usage: () => ({ probes: this.probes, tokens: this.tokens }),
      evaluate: () => this.evaluateGoal(goal),
      iterate: async (i) => {
        this.ui({ kind: "note", tone: "muted", text: `Objectif « ${GOAL_LABEL[goal.kind]} », itération ${i}/${goal.budget.maxIterations}.` });
        await this.plan(i === 1 ? intent : intent === "tests" ? "full" : intent, i);
      },
    });
    const label: Record<string, string> = {
      met: "Objectif atteint, vérifié par le code.", "met-unverified": "Objectif atteint selon le modèle, NON vérifié par le code.",
      budget: "Budget épuisé avant l'objectif.", stalled: "Plus rien ne bouge: l'objectif demande une correction de votre côté.",
      stopped: "Objectif interrompu.", unverifiable: "Objectif libre impossible à juger sans modèle.",
    };
    if (res.outcome !== "stopped") this.ui({ kind: "say", text: `${label[res.outcome]} ${res.last?.detail ?? ""} (${res.iterations} itération(s), ${this.probes} requête(s), ${ms(Date.now() - t0)}).` });
    return res.outcome === "stopped" ? "stopped" : "done";
  }
}
