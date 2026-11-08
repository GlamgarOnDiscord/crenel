// Free exploration: a layer ON TOP of the deterministic floor.
//
// The fixed plan only runs checks whose schema we wrote, so a flaw on a route
// shape nobody declared, or a debug endpoint with a custom name, is missed. With
// a model enabled, exploration hands it a few generic tools (an HTTP client, a
// code search and reader, the served JS, the toolbox with free arguments, a
// notebook of leads) and lets it look where it wants, within the same perimeter:
//
//   - every tool goes through the gate, the scoped client (scope, private IPs,
//     redirects, methods), the run's journal and its kill switch; a write needs
//     explore "full", allowActiveTesting and the gate, which asks every time;
//   - budgets in code: model calls, tokens, requests, wall time, toolbox runs;
//   - every tool output reaches the model fenced as untrusted data, capped;
//   - the model never writes a state. Its claims go to the generic validators
//     (request replay, cross-actor diff, secret in response, file match), which
//     replay them with deterministic code. A claim they cannot prove is kept as
//     an unproven lead with the model's reasoning and the exact requests.
//
// Modes: off (nothing), assist (read tools, small budget), full (adds the
// toolbox with free arguments and writes under the gate, larger budget).

import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { z } from "zod";
import type { Config } from "../core/config.js";
import { safeFetch, type SafeResponse } from "../core/net.js";
import { Scope, type NetEvent } from "../core/scope.js";
import type { Check, Finding, Severity } from "../core/types.js";
import { relative, walkFiles } from "../core/walk.js";
import { crawlLiveBundle, extractEndpoints, type ServedFile } from "../checks/live-bundle.js";
import type { PlannedRequest } from "./gate.js";
import { estimateTokens, type Llm } from "./llm.js";
import { fence, untrusted, UNTRUSTED_PREAMBLE } from "./untrusted.js";
import {
  ACTORS, actorMarker, actorToken, cleanHeaders, insideProject, resolveExploreUrl, validateClaim,
  type Actor, type AuthzOptions, type Claim, type ClaimVerdict, type ExploreRequest, type ValidatorEnv,
} from "./validators.js";
import { backendFor, type Backend } from "../toolbox/backend.js";
import { freeArgsProblem, freeArgv } from "../toolbox/free-args.js";
import { httpxTargets, toolboxOptions } from "../toolbox/run.js";
import { TOOL_NAMES, type ToolName } from "../toolbox/names.js";

export type ExploreMode = "off" | "assist" | "full";
export const EXPLORE_MODES: readonly ExploreMode[] = ["off", "assist", "full"];

export const ExploreOptions = z.object({
  maxCalls: z.number().int().min(1).max(50).optional(),
  maxRequests: z.number().int().min(1).max(5000).optional(),
  maxTokens: z.number().int().min(1000).max(2_000_000).optional(),
  maxMs: z.number().int().min(5000).max(3_600_000).optional(),
  maxToolRuns: z.number().int().min(0).max(10).optional(),
  /** secret-in-response: one read-only call to the key's own provider (its host must be declared). */
  secretLiveness: z.boolean().default(false),
  /** explore.ssrf: address the TARGET can reach back for the out-of-band callback (e.g. the host bridge IP for a container target). Default 127.0.0.1. */
  ssrfCallbackHost: z.string().max(255).optional(),
  /** explore.ssrf: a fixed callback port to advertise, so the model can compose structured SSRF (host/port/path split). Default: an ephemeral port (single-URL SSRF only). */
  ssrfCallbackPort: z.number().int().min(1).max(65535).optional(),
  /** explore.dom-xss: path to Playwright's entry (index.mjs) and to a chromium executable, to prove DOM XSS in a real browser. Optional; absent, DOM XSS stays a lead. */
  domXssPlaywright: z.string().max(1024).optional(),
  domXssBrowser: z.string().max(1024).optional(),
}).strict();

export interface ExploreBudget { maxCalls: number; maxRequests: number; maxTokens: number; maxMs: number; maxToolRuns: number }
const DEFAULTS: Record<"assist" | "full", ExploreBudget> = {
  assist: { maxCalls: 6, maxRequests: 40, maxTokens: 120_000, maxMs: 5 * 60_000, maxToolRuns: 0 },
  full: { maxCalls: 24, maxRequests: 300, maxTokens: 600_000, maxMs: 25 * 60_000, maxToolRuns: 10 },
};

/** The run's exploration mode: the run's choice, else the config's, else assist with a model and off without. */
export function resolveExploreMode(config: Pick<Config, "explore">, llmOn: boolean, override?: string): ExploreMode {
  if (!llmOn) return "off";
  if (override && (EXPLORE_MODES as readonly string[]).includes(override)) return override as ExploreMode;
  return config.explore ?? "assist";
}

export function exploreBudget(config: Config, mode: "assist" | "full"): ExploreBudget {
  const r = ExploreOptions.safeParse(config.options.explore ?? {});
  if (!r.success) throw new Error(`options.explore: ${r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")}`);
  const d = DEFAULTS[mode];
  return {
    maxCalls: r.data.maxCalls ?? d.maxCalls, maxRequests: r.data.maxRequests ?? d.maxRequests, maxTokens: r.data.maxTokens ?? d.maxTokens,
    maxMs: r.data.maxMs ?? d.maxMs, maxToolRuns: mode === "full" ? (r.data.maxToolRuns ?? d.maxToolRuns) : 0,
  };
}

/* ---------------- what the model may send ---------------- */

const actor = z.enum(ACTORS as unknown as [Actor, ...Actor[]]);
const requestShape = z.object({
  method: z.string().max(10).optional(), url: z.string().min(1).max(2000), as: actor.optional(),
  headers: z.record(z.string(), z.string()).optional(), body: z.string().max(20_000).optional(),
});
const severity = z.enum(["info", "low", "medium", "high", "critical"]);
const CLAIM_CLASSES = { replay: "explore.replay", "cross-actor": "explore.cross-actor", secret: "explore.secret", "file-match": "explore.file-match", injection: "explore.injection", ssrf: "explore.ssrf", "stored-xss": "explore.stored-xss", "dom-xss": "explore.dom-xss", lfi: "explore.lfi", "jwt-none": "explore.jwt-none", "mass-assignment": "explore.mass-assignment", cors: "explore.cors", reuse: "explore.reuse", graphql: "explore.graphql" } as const;
const TOOL_ARGS = {
  "http.request": requestShape,
  "code.search": z.object({ pattern: z.string().min(1).max(200), glob: z.string().max(100).optional(), ignoreCase: z.boolean().optional() }),
  "code.read": z.object({ path: z.string().min(1).max(500), from: z.number().int().min(1).optional(), to: z.number().int().min(1).optional() }),
  "bundle.fetch": z.object({ path: z.string().max(2000).optional(), grep: z.string().max(200).optional() }),
  "toolbox.run": z.object({ tool: z.enum(TOOL_NAMES as unknown as [ToolName, ...ToolName[]]), args: z.array(z.string()).max(40).default([]) }),
  "note.lead": z.object({ title: z.string().min(1).max(200), reasoning: z.string().max(2000).default(""), severity: severity.default("low"), location: z.string().max(500).optional(), requests: z.array(requestShape).max(5).optional() }),
  "claim.submit": z.object({
    class: z.enum(Object.keys(CLAIM_CLASSES) as [keyof typeof CLAIM_CLASSES, ...(keyof typeof CLAIM_CLASSES)[]]),
    title: z.string().min(1).max(200), severity: severity.default("medium"), reasoning: z.string().max(2000).default(""),
    detail: z.record(z.string(), z.unknown()),
  }),
} as const;
export type ExploreTool = keyof typeof TOOL_ARGS;
const TURN = z.object({ thought: z.string().max(4000).optional(), calls: z.array(z.object({ tool: z.string(), args: z.unknown().optional() })).max(20).default([]), done: z.boolean().default(false) });
const MAX_CALLS_PER_TURN = 8;
const MAX_CLAIMS = 12;

/* ---------------- results ---------------- */

export interface ExploreItem { f: Finding; v?: ClaimVerdict }
export interface ExploreResult {
  found: ExploreItem[];
  calls: number;
  requests: number;
  tokens: number;
  toolRuns: number;
  /** Why exploration ended before the model said it was done. */
  stopped?: string;
  lines: string[];
}

export interface ExploreDeps {
  llm: Llm;
  mode: "assist" | "full";
  config: Config;
  projectDir: string;
  budget: ExploreBudget;
  /** The run's kill switch. */
  signal: AbortSignal;
  /** The gate of the run (asks the user in "ask" mode). */
  gate: (tool: string, requests: PlannedRequest[]) => Promise<boolean>;
  /** Every request sent (journal, probe count, audit); refusals of the scope are reported separately. */
  onNet: (e: NetEvent) => void;
  emit: (type: string, data: unknown) => void;
  checks: Check[];
  /** What the user asked, and what the fixed plan already found (one line each). */
  userPrompt: string;
  context?: string[];
  /** Toolbox backend (tests inject one). */
  backend?: Backend;
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const capSev = (s: Severity, max: Severity): Severity => (SEV_RANK[s] <= SEV_RANK[max] ? s : max);
const one = (s: string, n = 200) => s.replace(/\s+/g, " ").trim().slice(0, n);
const pathOf = (url: string) => { try { const u = new URL(url); return u.pathname + u.search; } catch { return url; } };

interface Logged { method: string; url: string; as: Actor; status?: number; sha256?: string; refused?: string }

export class Explorer {
  private readonly ac = new AbortController();
  private readonly scope: Scope;
  private readonly started = Date.now();
  private calls = 0;
  private tokens = 0;
  private toolRuns = 0;
  private refusals = 0;
  private stopped?: string;
  private readonly history: string[] = [];
  private readonly log: Logged[] = [];
  private readonly found: ExploreItem[] = [];
  private readonly claimed = new Set<string>();
  private bundle?: ServedFile[];
  private readonly approved = new Set<string>();

  constructor(private readonly d: ExploreDeps) {
    const onAbort = () => this.ac.abort(d.signal.reason);
    if (d.signal.aborted) onAbort(); else d.signal.addEventListener("abort", onAbort, { once: true });
    const s = d.config.scope;
    this.scope = new Scope({
      allowedHosts: s.allowedHosts, allowActiveTesting: s.allowActiveTesting, allowPrivate: s.allowPrivate, stagingUrl: s.stagingUrl,
      access: s.access, ratePerSec: s.ratePerSec,
      // The scope is the backstop of the request budget; the explorer refuses first.
      maxRequests: Math.min(d.budget.maxRequests, s.maxRequests ?? Infinity),
      signal: this.ac.signal,
      onRequest: (e) => {
        if (e.refused) { this.d.emit("net", { ...e, explore: true }); return; }
        this.d.onNet(e);
      },
    });
  }

  get requests(): number { return this.scope.requestsSent; }

  /** Stop exploring (budget, monitor); the run itself goes on. */
  private halt(reason: string): void {
    if (this.ac.signal.aborted) return;
    this.stopped = reason;
    this.d.emit("explore.stop", { reason });
    this.ac.abort(new Error(reason));
  }

  private overBudget(): string | null {
    const b = this.d.budget;
    if (Date.now() - this.started > b.maxMs) return `wall time over ${Math.round(b.maxMs / 1000)} s`;
    if (this.tokens >= b.maxTokens) return `token budget (${b.maxTokens}) spent`;
    if (this.requests >= b.maxRequests) return `request budget (${b.maxRequests}) spent`;
    return null;
  }

  async run(): Promise<ExploreResult> {
    this.d.emit("explore.start", { mode: this.d.mode, budget: this.d.budget, llm: this.d.llm.label });
    // Reconnaissance before the first model call, deterministic and cheap: the
    // page and the routes its scripts cite, so the first turn already has
    // something to work on (a model call costs more than a few GETs).
    if (this.d.config.scope.stagingUrl && this.d.budget.maxRequests >= 10) {
      const out = await this.tool("bundle.fetch", {});
      const page = this.bundle?.find((f) => f.kind === "html");
      const links = page ? [...new Set([...page.body.matchAll(/(?:href|src|action)=["']([^"'#]+)["']/gi)].map((m) => m[1]!))].slice(0, 40) : [];
      // API endpoints the served scripts cite: the richest map to enumerate and attack.
      const eps = this.bundle ? [...new Set(this.bundle.filter((f) => f.kind !== "map").flatMap((f) => extractEndpoints(f.body)))].slice(0, 60) : [];
      this.history.push(`[reconnaissance, avant le premier tour]\n→ bundle.fetch {}\n${out.text}`
        + (eps.length ? `\nEndpoints API cités par les scripts (à énumérer et attaquer en priorité):\n${fence(untrusted("endpoints", eps.join("\n"), 3000))}` : "")
        + (links.length ? `\nLiens de la page d'accueil:\n${fence(untrusted("links", links.join("\n"), 2000))}` : ""));
    }
    for (let turn = 1; turn <= this.d.budget.maxCalls; turn++) {
      if (this.ac.signal.aborted) break;
      const over = this.overBudget();
      if (over) { this.halt(over); break; }
      const prompt = this.prompt(turn);
      if (this.tokens + estimateTokens(prompt) > this.d.budget.maxTokens) { this.halt(`token budget (${this.d.budget.maxTokens}) spent`); break; }
      let raw: string;
      try {
        raw = await this.d.llm.ask(prompt, { signal: this.ac.signal, timeoutMs: Math.max(5000, Math.min(180_000, this.d.budget.maxMs - (Date.now() - this.started))) });
      } catch (err) {
        if (!this.ac.signal.aborted) this.d.emit("llm.error", { message: (err as Error).message.slice(0, 300) });
        break;
      }
      this.calls++;
      this.tokens += estimateTokens(prompt) + estimateTokens(raw);
      const parsed = parseTurn(raw);
      if (!parsed) {
        this.d.emit("explore.rejected", { turn, reason: "not the expected JSON", sha256: sha(raw) });
        this.history.push(`[tour ${turn}] ta réponse n'était pas le JSON attendu, rien n'a été exécuté.`);
        continue;
      }
      this.d.emit("explore.turn", { turn, thought: one(parsed.thought ?? "", 500), calls: parsed.calls.map((c) => c.tool) });
      const turnLines: string[] = [];
      if (parsed.calls.length > MAX_CALLS_PER_TURN) turnLines.push(`(${parsed.calls.length - MAX_CALLS_PER_TURN} appel(s) au-delà de ${MAX_CALLS_PER_TURN} ignoré(s))`);
      for (const call of parsed.calls.slice(0, MAX_CALLS_PER_TURN)) {
        if (this.ac.signal.aborted) break;
        const out = await this.tool(call.tool, call.args);
        this.d.emit("explore.tool", { turn, tool: call.tool, result: one(out.summary, 300) });
        turnLines.push(`→ ${call.tool} ${one(JSON.stringify(call.args ?? {}), 300)}\n${out.text}`);
      }
      this.history.push(`[tour ${turn}]\n${turnLines.join("\n")}`);
      if (parsed.done) break;
    }
    const over = this.overBudget();
    if (over && !this.stopped && this.calls < this.d.budget.maxCalls) this.stopped = over;
    const proven = this.found.filter((x) => x.f.state === "proven").length;
    const lines = [
      `${this.calls} appel(s) au modèle, ${this.requests} requête(s), ~${this.tokens} jetons${this.toolRuns ? `, ${this.toolRuns} outil(s) lancé(s)` : ""}`,
      `${proven} prouvé(s) par un validateur générique, ${this.found.length - proven} piste(s) gardée(s)`,
      ...(this.stopped ? [`arrêt: ${this.stopped}`] : []),
    ];
    this.d.emit("explore.end", { calls: this.calls, requests: this.requests, tokens: this.tokens, toolRuns: this.toolRuns, stopped: this.stopped, proven, leads: this.found.length - proven });
    return { found: this.found, calls: this.calls, requests: this.requests, tokens: this.tokens, toolRuns: this.toolRuns, stopped: this.stopped, lines };
  }

  /* ---------------- the prompt ---------------- */

  private prompt(turn: number): string {
    const cfg = this.d.config;
    const opts = (cfg.options["authz-matrix"] ?? {}) as AuthzOptions;
    const exOpts = (cfg.options.explore ?? {}) as { ssrfCallbackHost?: string; ssrfCallbackPort?: number };
    const ssrfCb = exOpts.ssrfCallbackHost && exOpts.ssrfCallbackPort
      ? ` Un rappel hors-bande est prêt sur http://${exOpts.ssrfCallbackHost}:${exOpts.ssrfCallbackPort}/ : pour une SSRF structurée (host/port/path séparés), mets host=${exOpts.ssrfCallbackHost}, port=${exOpts.ssrfCallbackPort}, path=/__INJECT__ (le validateur place le nonce). Pour un seul paramètre URL, laisse le validateur composer l'URL.`
      : "";
    const accounts = (["a", "b", "c"] as const).filter((k) => actorToken(cfg.options, k)).map((k) => `${k}${actorMarker(cfg.options, k) ? ` (marqueur présent seulement dans ses objets: ${actorMarker(cfg.options, k)})` : ""}`);
    const b = this.d.budget;
    const tools = [
      `http.request {method?, url, as?, headers?, body?}: une requête vers un hôte déclaré (url absolue ou chemin relatif à la cible). as = "a" | "b" | "c" | "anon" (le jeton du compte est ajouté par l'outil; tu ne le vois jamais). GET/HEAD seulement${this.d.mode === "full" ? "; une écriture (POST, PUT, PATCH, DELETE) passe par la porte et allowActiveTesting, et l'utilisateur est sollicité à chaque fois" : ""}.`,
      `code.search {pattern, glob?, ignoreCase?}: regex sur les fichiers texte du projet (40 résultats max).`,
      `code.read {path, from?, to?}: lire un fichier du projet (300 lignes max), chemin relatif.`,
      `bundle.fetch {path?, grep?}: sans path, la liste des fichiers JS servis par le site et les routes qu'ils citent; avec path, le contenu (ou les lignes qui contiennent grep).`,
      ...(this.d.mode === "full" && b.maxToolRuns > 0 ? [`toolbox.run {tool: "katana"|"httpx"|"nuclei"|"trufflehog", args: [...]}: un outil de la boîte à outils avec tes arguments; le proxy, le débit et les fichiers sont imposés par Crenel (${b.maxToolRuns} lancement(s) max).`] : []),
      `note.lead {title, reasoning, severity?, location?, requests?}: noter une hypothèse (elle reste une piste). Préfère TOUJOURS claim.submit quand un validateur peut décider: dès qu'un paramètre/argument te semble injectable (SQL/XSS/template/commande) soumets une claim injection, et dès qu'un paramètre semble provoquer une requête côté serveur (URL, host, importFrom, webhook, fetch, avatar_url…) soumets une claim ssrf. note.lead seulement si aucun validateur ne s'applique.`,
      `claim.submit {class, title, severity, reasoning, detail}: soumettre une affirmation à un validateur déterministe qui la rejoue. Classes et detail:\n` +
        `   replay: {request:{method?,url,as?,headers?,body?}, expect:{status?, bodyIncludes:["texte précis présent dans la réponse"]}, control?:{as}, id?}. Prouvé seulement si la réponse contient ces textes, que les témoins (sans identifiants, ou en tant qu'un autre compte, et un objet inexistant) ne les contiennent pas, et que l'un d'eux est le marqueur d'un AUTRE compte que celui de la requête (sinon c'est un fait rejoué, gardé comme piste).\n` +
        `   cross-actor: {url, attacker:"a"|"c"|"anon", owner?:"b", id?}. Prouvé si l'attaquant lit l'objet du propriétaire (même réponse ou marqueur), qu'un id inexistant ne répond pas pareil, et qu'un anonyme ne l'obtient pas. Tente aussi attacker:"anon" sur tout endpoint d'objet authentifié: si l'anonyme obtient l'objet d'un compte avec son marqueur, c'est une fuite d'auth prouvée (le validateur escalade seul).\n` +
        `   secret: {request:{url,as?}}. Prouvé si la réponse contient une clé secrète de forme connue (pas une clé publique).\n` +
        `   file-match: {file, text, line?}. Prouvé si le texte cité (12 caractères min.) est dans le fichier.\n` +
        `   injection: {url, param, where?:"query"|"body", value?, method?, as?} pour un point REST, OU {url, gql:"{ champ(arg:\\"__INJECT__\\"){...} }"} pour GraphQL (mets __INJECT__ là où la charge entre). Le validateur génère LUI-MÊME ses charges et prouve par oracle générique: SQLi (une condition VRAIE répond comme la base, une FAUSSE diverge; ou une erreur SQL), XSS réfléchi (balise injectée renvoyée non échappée), injection de template/commande (un calcul 7*7=49 que le serveur a évalué), NoSQL (opérateurs $ne/$eq en query bracket, body JSON, ou body multi-champ via bodyTemplate avec "__INJECT__" au champ ciblé, ex. login {user, pass:"__INJECT__"}: toujours-vrai répond comme la base, toujours-faux diverge). Un paramètre ignoré n'est jamais prouvé.`,
        `   ssrf: {url, param (ou gql avec __INJECT__), where?, callbackHost?}. Prouvé hors-bande : un écouteur reçoit la requête que le serveur a faite vers l'URL de rappel injectée. callbackHost doit être joignable depuis la cible.${ssrfCb}`,
        `   stored-xss: {storeUrl, storeParam (ou storeGql avec __INJECT__), storeWhere?, retrieveUrl, retrieveGql?}. Pour une XSS STOCKÉE: le validateur stocke un marqueur <svg> via la 1re requête puis vérifie qu'il est servi NON échappé par la 2e (retrieveUrl).`,
        `   dom-xss: {url, param, where?}. Pour une XSS DOM (reflétée par le JS de la page, pas dans le HTML brut): le validateur charge l'URL dans un vrai navigateur et prouve si le script injecté s'exécute (alert avec nonce).`,
        `   lfi: {url, param, where?}. Path traversal / LFI: le validateur fait lire un fichier système connu via ../ (plusieurs encodages) et prouve par le contenu du fichier (ex. root:x:0:0 de /etc/passwd).`,
        `   jwt-none: {url, token, override?}. Donne un JWT valide; le validateur forge une version non signée (alg:none, claims modifiables via override) et prouve si le serveur l'accepte là où l'anonyme est refusé.`,
        `   mass-assignment: {url, field, value, update?, readUrl?, method?, bodyType?, as?}. Un champ que le client ne devrait pas pouvoir fixer (role, isAdmin, credits, plan, verified…): le validateur lit l'objet de l'acteur, fait un update SANS le champ (contrôle: il ne doit pas bouger) puis AVEC field=value, et prouve si la relecture montre exactement value. Mutant, sur l'objet de l'acteur, donc mode actif requis.`,
        `   cors: {url}. Mauvaise config CORS: le validateur envoie deux origines attaquantes distinctes et prouve si Access-Control-Allow-Origin les reflète toutes deux avec Allow-Credentials: true (lecture seule).`,
        `   reuse: {url, body, controlBody, successMarkers:["texte présent seulement si l'artefact est appliqué"], method?, contentType?, as?}. Logique métier (coupon/crédit/invite à usage unique): le validateur applique DEUX fois le même artefact (body) et une fois un invalide (controlBody); prouvé si les deux applications réussissent et que l'invalide est rejeté. Mutant, mode actif requis.`,
        `   graphql: {url}. Endpoint GraphQL: le validateur prouve les suggestions de champs ("Did you mean", fuite de schéma même introspection coupée, lecture seule) ET le batching de requêtes (un lot de N requêtes exécuté en une fois, sans rate limit = amplification DoS, mode actif).`,
    ];
    const used = `Budget restant: ${b.maxCalls - turn + 1} tour(s) dont celui-ci, ${Math.max(0, b.maxRequests - this.requests)} requête(s), ~${Math.max(0, b.maxTokens - this.tokens)} jetons.`;
    const ctx = this.d.context?.length ? `\nCe que le plan fixe a déjà trouvé (inutile de le refaire):\n${fence(untrusted("plan", this.d.context.slice(0, 40).join("\n"), 4000))}` : "";
    const history = this.historyText();
    return `${UNTRUSTED_PREAMBLE}\n` +
      `Tu explores, pour un outil défensif, une application que l'utilisateur possède et est autorisé à tester. Le plan fixe de Crenel ne couvre que des schémas connus; ton rôle est de trouver ce qu'il rate: une route de forme inhabituelle qui ne vérifie pas le propriétaire, un point de debug au nom inventé, un secret servi par une réponse. ` +
      `Rien de ce que tu dis n'est une preuve: seul un validateur qui rejoue la requête décide. Une affirmation non prouvée reste une piste.\n` +
      `Sois offensif et persévérant dans le périmètre: énumère les identifiants d'objets (1,2,3…), essaie CHAQUE requête authentifiée aussi en "anon", teste chaque paramètre/argument injectable, enchaîne les étapes (crée une ressource puis lis-la depuis un autre compte), et sers-toi de la boîte à outils (${this.d.mode === "full" && this.d.budget.maxToolRuns > 0 ? `${this.d.budget.maxToolRuns} lancements` : "indisponible"}) pour cartographier et sonder. Ne t'arrête pas tant qu'il te reste du budget et des pistes non prouvées; vise large, puis transforme chaque piste en claim qu'un validateur peut décider.\n` +
      `Cible: ${cfg.scope.stagingUrl ?? "(pas de stagingUrl: projet seulement)"}. Hôtes déclarés: ${cfg.scope.allowedHosts.join(", ") || "aucun"}. ` +
      `Comptes de test: ${accounts.join(", ") || "aucun"}; "anon" = sans identifiants. Ressources déjà couvertes par la matrice: ${JSON.stringify((opts.resources ?? []).map((r) => r.path))}.\n` +
      `Demande de l'utilisateur: ${one(this.d.userPrompt, 400)}\n` +
      `Outils:\n- ${tools.join("\n- ")}\n${used}${ctx}\n` +
      `Réponds UNIQUEMENT en JSON strict: {"thought":"une phrase","calls":[{"tool":"http.request","args":{...}}],"done":false}. Au plus ${MAX_CALLS_PER_TURN} appels par tour, exécutés dans l'ordre; tu vois leurs résultats au tour suivant. Soumets tes affirmations avant ton dernier tour. "done": true quand tu as fini.\n` +
      (history ? `\nRésultats des tours précédents:\n${history}` : "");
  }

  /** The newest results in full, older ones shortened, the whole bounded. */
  private historyText(max = 24_000): string {
    const out: string[] = [];
    let used = 0;
    for (let i = this.history.length - 1; i >= 0; i--) {
      const h = this.history[i]!;
      const piece = used + h.length <= max ? h : h.split("\n").filter((l) => l.startsWith("[tour") || l.startsWith("→")).join("\n").slice(0, 1500) + "\n(résultats raccourcis)";
      if (used + piece.length > max) break;
      out.unshift(piece);
      used += piece.length;
    }
    return out.join("\n\n");
  }

  /* ---------------- tools ---------------- */

  private async tool(name: string, args: unknown): Promise<{ text: string; summary: string }> {
    const refuse = (why: string) => {
      this.d.emit("explore.refused", { tool: name, reason: why });
      return { text: `REFUSÉ: ${why}`, summary: `refused: ${why}` };
    };
    if (!(name in TOOL_ARGS)) return refuse(`outil inconnu "${one(name, 40)}"`);
    const tool = name as ExploreTool;
    const parsed = TOOL_ARGS[tool].safeParse(args ?? {});
    if (!parsed.success) return refuse(`arguments invalides: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ").slice(0, 300)}`);
    try {
      switch (tool) {
        case "http.request": return await this.httpRequest(parsed.data as z.infer<typeof requestShape>, refuse);
        case "code.search": return this.codeSearch(parsed.data as z.infer<(typeof TOOL_ARGS)["code.search"]>, refuse);
        case "code.read": return this.codeRead(parsed.data as z.infer<(typeof TOOL_ARGS)["code.read"]>, refuse);
        case "bundle.fetch": return await this.bundleFetch(parsed.data as z.infer<(typeof TOOL_ARGS)["bundle.fetch"]>, refuse);
        case "toolbox.run": return await this.toolboxRun(parsed.data as z.infer<(typeof TOOL_ARGS)["toolbox.run"]>, refuse);
        case "note.lead": return this.noteLead(parsed.data as z.infer<(typeof TOOL_ARGS)["note.lead"]>);
        case "claim.submit": return await this.claim(parsed.data as z.infer<(typeof TOOL_ARGS)["claim.submit"]>, refuse);
      }
    } catch (err) {
      if (this.ac.signal.aborted) return { text: "interrompu", summary: "aborted" };
      return { text: `ERREUR: ${one((err as Error).message, 300)}`, summary: `error: ${one((err as Error).message, 120)}` };
    }
  }

  /** Out-of-scope attempts: five of them end the exploration (the run goes on). */
  private outOfScope(why: string, refuse: (w: string) => { text: string; summary: string }) {
    if (++this.refusals >= 5) this.halt("monitor: five requests out of the perimeter refused");
    return refuse(why);
  }

  /** The gate, once per host and kind (the run remembers the user's answer for the task). */
  private async gateFor(tool: string, reqs: PlannedRequest[]): Promise<boolean> {
    const key = `${tool}|${[...new Set(reqs.map((r) => { try { return new URL(r.url).host; } catch { return r.url; } }))].sort().join(",")}`;
    if (tool !== "explore.write" && this.approved.has(key)) return true;
    const ok = await this.d.gate(tool, reqs);
    if (ok && tool !== "explore.write") this.approved.add(key);
    return ok;
  }

  private budgetLeft(n = 1): string | null {
    if (this.requests + n > this.d.budget.maxRequests) { this.halt(`request budget (${this.d.budget.maxRequests}) spent`); return `budget de requêtes épuisé (${this.d.budget.maxRequests})`; }
    return null;
  }

  private async httpRequest(r: z.infer<typeof requestShape>, refuse: (w: string) => { text: string; summary: string }) {
    const url = resolveExploreUrl(r.url, this.d.config.scope.stagingUrl);
    if (!url) return this.outOfScope(`${one(r.url, 120)} n'est pas une URL http(s)`, refuse);
    if (!this.scope.isHostAllowed(url)) return this.outOfScope(`${new URL(url).hostname} n'est pas un hôte déclaré (scope.allowedHosts)`, refuse);
    const method = (r.method ?? "GET").toUpperCase();
    if (!/^[A-Z]{3,7}$/.test(method)) return refuse(`méthode ${one(method, 10)} invalide`);
    // Only GET and HEAD are reads for the gate; anything else, even a read-only POST, is a write here.
    const read = method === "GET" || method === "HEAD";
    const as = r.as ?? "anon";
    if (as !== "anon" && !actorToken(this.d.config.options, as)) return refuse(`aucun jeton configuré pour le compte ${as.toUpperCase()}`);
    if (!read) {
      if (this.d.mode !== "full") return refuse(`${method} modifie l'état: seulement en exploration "full"`);
      if (!this.scope.allowActiveTesting) return refuse(`${method} modifie l'état et allowActiveTesting est coupé dans la config`);
    }
    const left = this.budgetLeft();
    if (left) return refuse(left);
    if (!(await this.gateFor(read ? "explore.http" : "explore.write", [{ method, url }]))) {
      this.log.push({ method, url, as, refused: "gate" });
      return refuse(`la porte a refusé ${method} ${pathOf(url)} (rien n'a été envoyé)`);
    }
    const token = actorToken(this.d.config.options, as);
    let res: SafeResponse;
    try {
      res = await safeFetch(url, this.scope, { method, headers: { ...cleanHeaders(r.headers), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: r.body, maxBytes: 256 * 1024 });
    } catch (err) {
      this.log.push({ method, url, as, refused: (err as Error).message });
      return refuse(one((err as Error).message, 200));
    }
    this.log.push({ method, url, as, status: res.status, sha256: sha(res.body) });
    const keep = ["content-type", "location", "server", "x-powered-by", "access-control-allow-origin", "access-control-allow-credentials", "www-authenticate", "cache-control"];
    const head = keep.map((k) => [k, res.headers.get(k)] as const).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`);
    const cookies = res.headers.getSetCookie?.().map((c) => c.split("=")[0]) ?? [];
    const text = `HTTP ${res.status} (${res.body.length} octets${res.truncated ? ", tronqué" : ""}, sha256 ${sha(res.body).slice(0, 12)})\n${head.join("\n")}${cookies.length ? `\nset-cookie: ${cookies.join(", ")} (valeurs masquées)` : ""}\n` +
      fence(untrusted(`http:${method} ${url} as=${as}`, res.body, 3000));
    return { text, summary: `${method} ${pathOf(url)} as ${as} -> ${res.status}` };
  }

  private codeSearch(a: z.infer<(typeof TOOL_ARGS)["code.search"]>, refuse: (w: string) => { text: string; summary: string }) {
    // Nested quantifiers are the classic catastrophic-backtracking shape: refused.
    if (/\([^)]*[+*][^)]*\)\s*[+*{]/.test(a.pattern)) return refuse("motif refusé (quantificateurs imbriqués)");
    let re: RegExp;
    try { re = new RegExp(a.pattern, a.ignoreCase ? "i" : ""); } catch (err) { return refuse(`regex invalide: ${one((err as Error).message, 100)}`); }
    const glob = a.glob ? globRe(a.glob) : null;
    const root = this.d.projectDir;
    const hits: string[] = [];
    let files = 0;
    const deadline = Date.now() + 5000;
    for (const full of walkFiles(root, { skipDirs: new Set(["node_modules", ".git", ".crenel"]) })) {
      if (++files > 5000 || hits.length >= 40 || Date.now() > deadline) break;
      const rel = relative(root, full);
      if (glob && !glob.test(rel)) continue;
      let body: string;
      try { if (statSync(full).size > 1024 * 1024) continue; body = readFileSync(full, "utf8"); } catch { continue; }
      if (body.slice(0, 8000).includes("\u0000")) continue;
      const lines = body.split("\n");
      for (let i = 0; i < lines.length && hits.length < 40; i++) {
        const l = lines[i]!.slice(0, 400);
        if (re.test(l)) hits.push(`${rel}:${i + 1}: ${l.trim().slice(0, 200)}`);
      }
    }
    return { text: `${hits.length} résultat(s) sur ${files} fichier(s)\n${fence(untrusted(`code.search ${a.pattern}`, hits.join("\n"), 6000))}`, summary: `${hits.length} hit(s)` };
  }

  private codeRead(a: z.infer<(typeof TOOL_ARGS)["code.read"]>, refuse: (w: string) => { text: string; summary: string }) {
    const full = insideProject(this.d.projectDir, a.path.replace(/\\/g, "/").replace(/^\.\//, ""));
    if (!full) return refuse(`${one(a.path, 120)} n'est pas un fichier du projet (rien hors de projectDir)`);
    if (statSync(full).size > 2 * 1024 * 1024) return refuse("fichier de plus de 2 Mo");
    const body = readFileSync(full, "utf8");
    if (body.slice(0, 8000).includes("\u0000")) return refuse("fichier binaire");
    const lines = body.split("\n");
    const from = Math.max(1, a.from ?? 1);
    const to = Math.min(lines.length, a.to ?? from + 299, from + 299);
    const slice = lines.slice(from - 1, to).map((l, i) => `${from + i}: ${l}`).join("\n");
    return { text: `${relative(realpathSync(this.d.projectDir), full)} lignes ${from}-${to} sur ${lines.length}\n${fence(untrusted(`file:${a.path}`, slice, 16_000))}`, summary: `read ${a.path}:${from}-${to}` };
  }

  private async bundleFetch(a: z.infer<(typeof TOOL_ARGS)["bundle.fetch"]>, refuse: (w: string) => { text: string; summary: string }) {
    const start = this.d.config.scope.stagingUrl;
    if (!start) return refuse("pas de stagingUrl dans la config");
    if (!this.bundle) {
      const left = this.budgetLeft(2);
      if (left) return refuse(left);
      const base = start.replace(/\/+$/, "");
      if (!(await this.gateFor("explore.http", [{ method: "GET", url: start }, { method: "GET", url: `${base}/assets/*.js (chunks)` }]))) return refuse("la porte a refusé la lecture du site");
      this.bundle = (await crawlLiveBundle({ scope: this.scope, log: (m) => this.d.emit("log", { m }) }, start)).files;
    }
    const files = this.bundle;
    if (!a.path) {
      const list = files.map((f) => `${pathOf(f.url)} (${f.kind}, ${f.body.length} octets)${f.kind === "js" ? ` routes: ${extractEndpoints(f.body).slice(0, 15).join(" ")}` : ""}`);
      return { text: `${files.length} fichier(s)\n${fence(untrusted("bundle", list.join("\n"), 6000))}`, summary: `${files.length} file(s)` };
    }
    const want = a.path;
    const f = files.find((x) => x.url === want || pathOf(x.url) === want || pathOf(x.url) === `/${want.replace(/^\/+/, "")}`);
    if (!f) return refuse(`${one(a.path, 120)} n'est pas un fichier servi (bundle.fetch sans path pour la liste)`);
    let body = f.body;
    if (a.grep) {
      const g = a.grep.toLowerCase();
      // Minified chunks are one long line: cut around each hit instead.
      const hits: string[] = [];
      let i = body.toLowerCase().indexOf(g);
      while (i >= 0 && hits.length < 20) { hits.push(body.slice(Math.max(0, i - 200), i + g.length + 200)); i = body.toLowerCase().indexOf(g, i + g.length); }
      body = hits.join("\n…\n");
    }
    return { text: fence(untrusted(`bundle:${pathOf(f.url)}`, body, 8000)), summary: `${pathOf(f.url)}${a.grep ? ` grep ${a.grep}` : ""}` };
  }

  private async toolboxRun(a: z.infer<(typeof TOOL_ARGS)["toolbox.run"]>, refuse: (w: string) => { text: string; summary: string }) {
    if (this.d.mode !== "full") return refuse(`toolbox.run seulement en exploration "full"`);
    if (this.toolRuns >= this.d.budget.maxToolRuns) return refuse(`budget d'outils épuisé (${this.d.budget.maxToolRuns})`);
    if (a.tool === "nuclei" && !this.scope.allowActiveTesting) return refuse("nuclei est un test actif: allowActiveTesting est coupé");
    const problem = freeArgsProblem(a.tool, a.args, this.scope);
    if (problem) return refuse(problem);
    let o;
    try { o = toolboxOptions(this.d.config); } catch (err) { return refuse((err as Error).message); }
    const target = this.d.config.scope.stagingUrl;
    const hosts = httpxTargets(this.d.config.scope.allowedHosts);
    if ((a.tool === "nuclei" || a.tool === "katana") && !target && !a.args.some((x) => /^https?:\/\//.test(x))) return refuse("pas de stagingUrl: aucune cible");
    const urls = [...a.args.flatMap((x) => x.split(",")).filter((x) => /^https?:\/\//i.test(x)), ...(a.tool === "httpx" ? hosts.map((h) => `https://${h}/`) : target ? [target] : [])];
    const left = this.budgetLeft(1);
    if (left) return refuse(left);
    if (a.tool !== "trufflehog" && !(await this.gateFor(`explore.toolbox`, urls.map((url) => ({ method: "GET", url }))))) return refuse("la porte a refusé le lancement");
    const backend = this.d.backend ?? backendFor(o);
    const st = await backend.status();
    const blocker = !st.ready ? st.reason : st.tools[a.tool]?.ready ? null : st.tools[a.tool]?.reason;
    if (blocker) return refuse(`boîte à outils indisponible: ${one(blocker ?? "", 160)}`);
    this.toolRuns++;
    // The tool's own requests count in the exploration budget: the proxy refuses past what is left.
    const remaining = Math.max(1, this.d.budget.maxRequests - this.requests);
    const toolScope = new Scope({
      allowedHosts: this.d.config.scope.allowedHosts, allowActiveTesting: this.d.config.scope.allowActiveTesting, allowPrivate: this.d.config.scope.allowPrivate,
      stagingUrl: target, ratePerSec: this.d.config.scope.ratePerSec, signal: this.ac.signal,
      onRequest: (e) => { if (e.refused) this.d.emit("net", { ...e, tool: a.tool, explore: true }); else this.d.onNet(e); },
    });
    const r = await backend.run({
      tool: a.tool, network: a.tool !== "trufflehog", scope: toolScope, projectDir: a.tool === "trufflehog" ? this.d.projectDir : undefined,
      limits: { timeoutMs: Math.min(o.timeoutSec * 1000, Math.max(5000, this.d.budget.maxMs - (Date.now() - this.started))), memory: o.memory },
      proxy: { ratePerSec: o.ratePerSec, maxRequests: remaining }, signal: this.ac.signal,
      onEvent: (e) => this.d.emit("egress", e),
      build: (p) => freeArgv(a.tool, a.args, p, { ratePerSec: o.ratePerSec, target, hosts }),
    }, st);
    const text = `exit ${r.code}${r.timedOut ? " (délai dépassé)" : ""}, réseau ${r.network}, ${r.proxy?.requests ?? 0} requête(s) via le proxy, ${r.proxy?.refused ?? 0} refusée(s)\n${fence(untrusted(`toolbox:${a.tool}`, r.stdout || r.stderr, 6000))}`;
    return { text, summary: `${a.tool} exit ${r.code}` };
  }

  private noteLead(a: z.infer<(typeof TOOL_ARGS)["note.lead"]>) {
    const id = `explore:lead:${sha(`${a.title}|${a.location ?? ""}`).slice(0, 12)}`;
    if (this.claimed.has(id)) return { text: "déjà noté", summary: "duplicate lead" };
    this.claimed.add(id);
    const reqs = (a.requests ?? []).map((r) => `${(r.method ?? "GET").toUpperCase()} ${resolveExploreUrl(r.url, this.d.config.scope.stagingUrl) ?? r.url} as=${r.as ?? "anon"}`);
    this.found.push({
      f: {
        id, check: "explore", title: one(a.title, 160), severity: capSev(a.severity, "medium"), state: "unproven",
        location: one(a.location ?? (reqs[0] ?? "exploration"), 300),
        description: `Piste du modèle, non prouvée (aucun validateur ne l'a rejouée). Raisonnement du modèle: ${one(a.reasoning, 1500)}` + (reqs.length ? ` Requêtes: ${reqs.join(" | ")}.` : "") + this.recent(),
        remediation: "Vérifier à la main, ou la reformuler en affirmation qu'un validateur peut rejouer (claim.submit).",
      },
    });
    return { text: "piste notée (non prouvée)", summary: "lead noted" };
  }

  /** The last requests the model sent, kept with every claim and lead. */
  private recent(n = 6): string {
    const r = this.log.slice(-n).map((l) => `${l.method} ${l.url} as=${l.as} -> ${l.status ?? `refusé (${one(l.refused ?? "", 60)})`}`);
    return r.length ? ` Dernières requêtes de l'exploration: ${r.join(" | ")}.` : "";
  }

  private async claim(a: z.infer<(typeof TOOL_ARGS)["claim.submit"]>, refuse: (w: string) => { text: string; summary: string }) {
    const cls = CLAIM_CLASSES[a.class];
    const key = `explore:${a.class}:${sha(JSON.stringify(canonical(a.detail))).slice(0, 12)}`;
    if (this.claimed.has(key)) return { text: "affirmation déjà soumise", summary: "duplicate claim" };
    if (this.claimed.size >= MAX_CLAIMS) return refuse(`au plus ${MAX_CLAIMS} affirmations par exploration`);
    this.claimed.add(key);
    // Only the detail goes to the validator; any "state" or "proven" the model writes is ignored.
    const claim: Claim = { id: `claim:${key}`, class: cls, source: "llm", detail: a.detail };
    const urls = claimUrls(a.class, a.detail, this.d.config.scope.stagingUrl);
    let env: ValidatorEnv = { scope: this.scope, projectDir: this.d.projectDir, options: this.d.config.options, stagingUrl: this.d.config.scope.stagingUrl, checks: this.d.checks };
    let verdict: ClaimVerdict;
    const offline = new Scope({ allowedHosts: [], signal: this.ac.signal });
    if (urls === null) verdict = { claimId: claim.id, state: "unproven", validator: null, reason: "no request or file to replay in the detail" };
    else if (urls.some((u) => !this.scope.isHostAllowed(u))) verdict = { claimId: claim.id, state: "unproven", validator: null, reason: "a URL of the claim is not on a declared host: nothing was sent" };
    else if (urls.length && this.requests + 6 > this.d.budget.maxRequests) verdict = { claimId: claim.id, state: "unproven", validator: null, reason: "request budget too low to replay it" };
    else if (urls.length && !(await this.gateFor("explore.http", urls.map((url) => ({ method: "GET", url }))))) verdict = { claimId: claim.id, state: "unproven", validator: null, reason: "the gate refused the replay: nothing was sent" };
    else {
      if (!urls.length) env = { ...env, scope: offline };
      verdict = await validateClaim(claim, env);
    }
    this.d.emit("verdict", { claim, verdict, source: "explore" });
    const proven = verdict.state === "proven";
    const loc = a.class === "file-match" ? `${String(a.detail.file ?? "")}${a.detail.line ? `:${String(a.detail.line)}` : ""}`
      : `${String(((a.detail.request as ExploreRequest | undefined)?.method ?? "GET")).toUpperCase()} ${pathOf(urls?.[0] ?? String(a.detail.url ?? ""))}`;
    const sev = proven ? capSev(a.severity, verdict.ceiling ?? "medium") : capSev(a.severity, "medium");
    const f: Finding = {
      id: key, check: "explore", title: one(a.title, 160), severity: sev, state: proven ? "proven" : "unproven", location: one(loc, 300),
      description: proven
        ? `Prouvé par ${verdict.validator}: ${verdict.reason}. Lecture du modèle (non vérifiée au-delà de la preuve): ${one(a.reasoning, 1200)}`
        : `Affirmation du modèle non prouvée: ${verdict.reason}. Raisonnement du modèle: ${one(a.reasoning, 1200)}. Détail soumis: ${one(JSON.stringify(a.detail), 600)}.${this.recent()}`,
      remediation: a.class === "cross-actor" ? "Filtrer chaque lecture par compte côté serveur (where owner_id = session.account_id) et renvoyer 404 sinon."
        : a.class === "secret" ? "Retirer la clé de la réponse, la révoquer et en émettre une nouvelle côté serveur seulement."
        : "Corriger selon la preuve ci-dessus, puis garder le test de régression.",
      proof: proven && verdict.evidence ? { method: verdict.validator ?? "validator", replay: verdict.evidence.request.replace(/\n/g, " | "), evidence: `${verdict.evidence.response.split("\n")[0]}${verdict.evidence.control ? ` · témoin: ${verdict.evidence.control}` : ""}` } : undefined,
      regressionHint: proven ? one(`${a.title}: ne doit plus se reproduire`, 120) : undefined,
    };
    this.found.push({ f, v: verdict });
    return { text: `${proven ? "PROUVÉ" : "NON PROUVÉ (gardé comme piste)"}: ${one(verdict.reason, 400)}`, summary: `${a.class} -> ${verdict.state}` };
  }
}

/** The URLs a claim's validator will request (null: nothing to replay; [] for a file). */
function claimUrls(cls: keyof typeof CLAIM_CLASSES, d: Record<string, unknown>, base?: string): string[] | null {
  if (cls === "file-match") return typeof d.file === "string" ? [] : null;
  const raw = cls === "stored-xss" ? d.storeUrl : (cls === "cross-actor" || cls === "injection" || cls === "ssrf" || cls === "dom-xss" || cls === "lfi" || cls === "mass-assignment" || cls === "cors" || cls === "reuse" || cls === "graphql") ? d.url : cls === "jwt-none" ? d.url : (d.request as { url?: unknown } | undefined)?.url;
  if (typeof raw !== "string") return null;
  const u = resolveExploreUrl(raw, base);
  return u ? [u] : null;
}

function canonical(x: unknown): unknown {
  if (Array.isArray(x)) return x.map(canonical);
  if (x && typeof x === "object") return Object.fromEntries(Object.keys(x as object).sort().map((k) => [k, canonical((x as Record<string, unknown>)[k])]));
  return x;
}

function globRe(g: string): RegExp {
  const re = g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*\/?/g, "\u0000").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]").replace(/\u0000/g, ".*");
  return new RegExp(g.includes("/") ? `^${re}$` : `(^|/)${re}$`);
}

/** The JSON object of a model's answer (fences and prose around it tolerated), or null. */
export function parseTurn(raw: string): z.infer<typeof TURN> | null {
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    const r = TURN.safeParse(JSON.parse(raw.slice(start, end + 1)));
    return r.success ? r.data : null;
  } catch {
    return null;
  }
}
