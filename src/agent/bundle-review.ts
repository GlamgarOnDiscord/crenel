// bundle-review: give a model the whole JavaScript a site serves, not a filtered
// slice. The deterministic detectors only find shapes they already know; a model
// reading the chunks can spot what no regex covers: admin or internal endpoints,
// role checks done only in the browser, hidden routes and feature flags, debug
// code left on, keys of an unknown format, internal hostnames.
//
// What it returns is ADVICE. Every item is a lead labelled as the model's, never
// `proven`. Two guards keep it honest: each item must quote an excerpt that
// literally exists in the served file (or it is dropped as a hallucination), and
// the chunks go to the model fenced as untrusted data, since a hostile site can
// write instructions into its own JavaScript. Endpoints it surfaces are returned
// separately so a deterministic check (the authorization matrix) can replay them.

import type { Finding, Severity } from "../core/types.js";
import type { ServedFile } from "../checks/live-bundle.js";
import type { Llm } from "./llm.js";
import { fence, untrusted, UNTRUSTED_PREAMBLE } from "./untrusted.js";

/** Characters of served code per model call, and how many calls at most. */
const WINDOW_CHARS = 120_000;
const MAX_CALLS = 20;

export interface ReviewItem {
  kind: "secret" | "endpoint" | "client-authz" | "hidden-route" | "debug" | "internal-host" | "other";
  title: string;
  url: string;
  excerpt: string;
  why: string;
  severity: "low" | "medium" | "high";
  endpoint?: { method: string; path: string };
}

export interface ReviewResult {
  findings: Finding[];
  endpoints: { method: string; path: string; url: string }[];
  calls: number;
  /** Characters of served code the model did not see because of the call budget. */
  unseenChars: number;
  dropped: number;
}

/** Split the served files into windows the model can read, file boundaries marked. */
export function windows(files: ServedFile[], size = WINDOW_CHARS): { url: string; text: string }[][] {
  // Pages and scripts first; maps last, only for their original sources.
  const order = [...files].sort((a, b) => (a.kind === "map" ? 1 : 0) - (b.kind === "map" ? 1 : 0));
  const out: { url: string; text: string }[][] = [];
  let cur: { url: string; text: string }[] = [];
  let used = 0;
  for (const f of order) {
    const body = f.kind === "map" ? sourcesOf(f.body) : f.body;
    for (let i = 0; i < body.length; i += size) {
      const part = body.slice(i, i + size);
      if (used + part.length > size && cur.length) { out.push(cur); cur = []; used = 0; }
      cur.push({ url: f.url, text: part });
      used += part.length;
    }
  }
  if (cur.length) out.push(cur);
  return out;
}

function sourcesOf(map: string): string {
  try {
    const m = JSON.parse(map) as { sources?: string[]; sourcesContent?: (string | null)[] };
    return (m.sourcesContent ?? []).map((c, i) => (c ? `// --- ${m.sources?.[i] ?? i}\n${c}` : "")).join("\n");
  } catch { return ""; }
}

const PROMPT = `${UNTRUSTED_PREAMBLE}

Tu relis, pour le propriétaire du site, le JavaScript que son site sert à tous les visiteurs. Cherche ce qu'un attaquant y trouverait d'utile et qu'un simple motif de clé ne voit pas :
- secret ou jeton d'un format non standard, identifiants en dur ;
- endpoints d'admin, internes ou non documentés (méthode et chemin) ;
- contrôle d'accès fait seulement côté client (rôle, plan, isAdmin, feature flag qui débloque une action) ;
- routes cachées, pages de debug, mode test laissé actif ;
- noms d'hôtes internes, URLs de staging, buckets.
Ignore les clés publiques par conception (Stripe pk_, Supabase anon, Firebase apiKey) sauf si elles accompagnent un vrai problème.

Réponds UNIQUEMENT par un tableau JSON, sans texte autour. Chaque élément :
{"kind":"secret|endpoint|client-authz|hidden-route|debug|internal-host|other","title":"...","url":"<url du fichier>","excerpt":"<extrait EXACT copié du fichier, 200 caractères max>","why":"<pourquoi c'est exploitable, une phrase>","severity":"low|medium|high","endpoint":{"method":"GET","path":"/api/..."}}
"endpoint" seulement si un chemin d'API est en jeu. Tableau vide [] si rien de notable. N'invente rien : l'extrait doit exister mot pour mot.`;

function parseItems(raw: string): ReviewItem[] {
  const start = raw.indexOf("["), end = raw.lastIndexOf("]");
  if (start < 0 || end <= start) return [];
  try {
    const arr = JSON.parse(raw.slice(start, end + 1)) as unknown;
    return Array.isArray(arr) ? (arr.filter((x) => x && typeof x === "object") as ReviewItem[]) : [];
  } catch { return []; }
}

const SEV: Record<string, Severity> = { low: "low", medium: "medium", high: "high" };
// Mask what looks like a key (long, letters and digits mixed), not ordinary identifiers.
const redact = (s: string) => s.replace(/\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])([A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]{14,}/g, "$1…");

export async function reviewBundle(files: ServedFile[], llm: Llm, opts: { signal?: AbortSignal; maxCalls?: number; log?: (m: string) => void } = {}): Promise<ReviewResult> {
  const byUrl = new Map(files.map((f) => [f.url, f.kind === "map" ? sourcesOf(f.body) : f.body]));
  const all = windows(files);
  const budget = Math.min(all.length, opts.maxCalls ?? MAX_CALLS);
  const findings: Finding[] = [];
  const endpoints: ReviewResult["endpoints"] = [];
  const seen = new Set<string>();
  let dropped = 0;
  for (let w = 0; w < budget; w++) {
    opts.signal?.throwIfAborted();
    const blocks = all[w]!.map((p) => fence(untrusted(`http:GET ${p.url}`, p.text, WINDOW_CHARS))).join("\n\n");
    let raw = "";
    try { raw = await llm.ask(`${PROMPT}\n\n${blocks}`, { signal: opts.signal, timeoutMs: 300_000 }); }
    catch (err) { opts.log?.(`bundle-review: window ${w + 1}: ${(err as Error).message}`); continue; }
    for (const it of parseItems(raw)) {
      const body = byUrl.get(it.url);
      const excerpt = String(it.excerpt ?? "").slice(0, 200);
      // Anti-hallucination: the quote must exist in the file the model was given.
      if (!body || excerpt.length < 8 || !body.includes(excerpt)) { dropped++; continue; }
      const key = `${it.kind}:${it.url}:${excerpt}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const line = body.slice(0, body.indexOf(excerpt)).split("\n").length;
      findings.push({
        id: `bundle-review:${it.kind}:${it.url}:${line}`,
        check: "bundle-review",
        title: `[IA, non vérifié] ${String(it.title ?? it.kind).slice(0, 140)}`,
        severity: SEV[it.severity] ?? "medium",
        state: "unproven",
        location: `${it.url}:${line}`,
        description: `${String(it.why ?? "").slice(0, 400)} This is the model's reading of the served code, not a proof.`,
        remediation: "Check it by hand, or let a deterministic check replay it (endpoints go to the authorization matrix).",
        proof: { method: "model review of the served JavaScript, quote verified in the file", replay: `curl -s '${it.url}' | grep -nF '${redact(excerpt).replace(/'/g, "'\\''").slice(0, 80)}'`, evidence: redact(excerpt) },
      });
      if (it.endpoint?.path && /^\/[\w\-./:{}[\]]*$/.test(it.endpoint.path)) {
        endpoints.push({ method: String(it.endpoint.method ?? "GET").toUpperCase(), path: it.endpoint.path, url: it.url });
      }
    }
  }
  const unseenChars = all.slice(budget).flat().reduce((n, p) => n + p.text.length, 0);
  if (unseenChars) opts.log?.(`bundle-review: call budget reached, ${Math.round(unseenChars / 1024)} KB of served code not reviewed`);
  return { findings, endpoints, calls: budget, unseenChars, dropped };
}
