// Adapters: external tool output -> Crenel leads.
//
// Everything a tool prints is untrusted data (the target wrote part of it). So:
//   - every result becomes a Finding in state `unproven` (a lead), never more;
//   - the raw output is kept only as an Untrusted envelope (capped, hashed,
//     fenced) for whoever wants to show it to a model;
//   - text copied into a finding is capped and stripped of control characters;
//   - a result about a host outside the scope is dropped, not reported;
//   - a secret is never copied: only a redacted prefix and a hash.
//
// A lead becomes `proven` only through an existing deterministic validator
// (validators.ts), which replays the evidence from the config and the disk:
//   nuclei   http-missing-security-headers  -> header.missing (header-reread)
//   trufflehog result on a file             -> check.replay of exposed-secrets on that file
//   katana   discovered routes              -> suggested authz-matrix resources; once
//                                               declared with B's ids, authz-replay decides.

import { createHash } from "node:crypto";
import type { Finding, Severity } from "../core/types.js";
import type { Scope } from "../core/scope.js";
import type { Claim } from "../agent/validators.js";
import { untrusted, type Untrusted } from "../agent/untrusted.js";

export interface AdapterResult {
  findings: Finding[];
  /** Claims a validator can replay (the only road to `proven`). */
  claims: Claim[];
  raw: Untrusted;
  /** Lines that were not valid JSON, or results dropped (off scope...). */
  skipped: number;
}

const SEVS: Severity[] = ["info", "low", "medium", "high", "critical"];
const sev = (s: unknown): Severity => (SEVS.includes(String(s).toLowerCase() as Severity) ? (String(s).toLowerCase() as Severity) : "info");
/** Cap a string copied from tool output and drop control characters. */
export function clean(s: unknown, max = 300): string {
  const t = String(s ?? "").replace(/[\u0000-\u0008\u000b-\u001f\u007f\u2028\u2029]/g, " ").replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max) + "…" : t;
}

function jsonLines(text: string): { rows: Record<string, unknown>[]; bad: number } {
  const rows: Record<string, unknown>[] = [];
  let bad = 0;
  for (const line of text.split("\n")) {
    const l = line.trim();
    if (!l) continue;
    if (!l.startsWith("{")) { bad++; continue; }
    try {
      const v = JSON.parse(l);
      if (v && typeof v === "object" && !Array.isArray(v)) rows.push(v as Record<string, unknown>);
      else bad++;
    } catch { bad++; }
  }
  return { rows, bad };
}

const TOOL_NOTE = "Sortie d'un outil externe, donnée non fiable: une piste, pas une preuve.";

/* ---------------- nuclei ---------------- */

// nuclei's http-missing-security-headers matcher names -> the header-reread validator's names.
const NUCLEI_HEADERS: Record<string, string> = {
  "content-security-policy": "content-security-policy",
  "strict-transport-security": "strict-transport-security",
  "x-content-type-options": "x-content-type-options",
  "x-frame-options": "x-frame-options",
  "referrer-policy": "referrer-policy",
};

export function parseNuclei(text: string, scope: Scope, stagingUrl?: string): AdapterResult {
  const { rows, bad } = jsonLines(text);
  let skipped = bad;
  const findings: Finding[] = [];
  const claims: Claim[] = [];
  const seen = new Set<string>();
  for (const r of rows) {
    const info = (r.info ?? {}) as Record<string, unknown>;
    const template = clean(r["template-id"], 120);
    const matcher = clean(r["matcher-name"], 80);
    const at = clean(r["matched-at"] ?? r.url ?? r.host, 400);
    if (!template || !at) { skipped++; continue; }
    let url: URL | null = null;
    try { url = new URL(/^[a-z]+:\/\//i.test(at) ? at : `http://${at}`); } catch { /* not a URL */ }
    if (!url || !scope.isHostAllowed(url.toString())) { skipped++; continue; }
    const id = `toolbox.nuclei:${template}${matcher ? `:${matcher}` : ""}:${at}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const name = clean(info.name, 120) || template;
    const extracted = Array.isArray(r["extracted-results"]) ? (r["extracted-results"] as unknown[]).slice(0, 3).map((x) => clean(x, 80)).join(", ") : "";
    findings.push({
      id, check: "toolbox.nuclei", state: "unproven", severity: sev(info.severity), location: at,
      title: `nuclei: ${name}${matcher ? ` (${matcher})` : ""}`,
      description: `${TOOL_NOTE} Modèle nuclei ${template}${matcher ? `, règle ${matcher}` : ""}.` +
        (info.description ? ` ${clean(info.description, 300)}` : "") + (extracted ? ` Extrait: ${extracted}.` : ""),
      remediation: "Vérifier à la main. Crenel ne la marque prouvée que si un validateur déterministe la rejoue.",
    });
    const header = NUCLEI_HEADERS[matcher.toLowerCase()];
    if (template === "http-missing-security-headers" && header && stagingUrl) {
      claims.push({ id: `claim:${id}`, class: "header.missing", source: "agent", detail: { url: stagingUrl, header, from: id } });
    }
  }
  return { findings, claims, raw: untrusted("tool:nuclei", text), skipped };
}

/* ---------------- katana ---------------- */

export interface Route { method: string; url: string; path: string; status?: number }
export interface SuggestedResource { name: string; path: string; methods: string[]; examples: string[] }

// A path segment that looks like an object id: a number, a UUID, a Mongo id,
// a prefixed id (proj_123, usr_ab12), a long hex or base62 token.
const ID_SEGMENT = /^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24}|[a-z]{2,10}_[A-Za-z0-9_]{1,40}|[0-9a-f]{16,64}|[A-Za-z0-9]{20,40})$/i;

export function parseKatana(text: string, scope: Scope): { routes: Route[]; raw: Untrusted; skipped: number } {
  const { rows, bad } = jsonLines(text);
  let skipped = bad;
  const routes = new Map<string, Route>();
  for (const r of rows) {
    const req = (r.request ?? {}) as Record<string, unknown>;
    const res = (r.response ?? {}) as Record<string, unknown>;
    const endpoint = String(req.endpoint ?? "");
    let u: URL;
    try { u = new URL(endpoint); } catch { skipped++; continue; }
    if (!/^https?:$/.test(u.protocol) || !scope.isHostAllowed(u.toString())) { skipped++; continue; }
    const method = clean(req.method ?? "GET", 10).toUpperCase() || "GET";
    const key = `${method} ${u.origin}${u.pathname}`;
    const status = typeof res.status_code === "number" ? res.status_code : undefined;
    if (!routes.has(key)) routes.set(key, { method, url: `${u.origin}${u.pathname}${u.search}`, path: u.pathname, ...(status !== undefined ? { status } : {}) });
  }
  return { routes: [...routes.values()], raw: untrusted("tool:katana", text), skipped };
}

/** Group discovered routes into resource templates for options.authz-matrix.resources. */
export function suggestResources(routes: Route[], declared: { path: string }[] = []): SuggestedResource[] {
  const known = new Set(declared.map((d) => d.path));
  const out = new Map<string, SuggestedResource>();
  for (const r of routes) {
    const segs = r.path.split("/");
    let hasId = false;
    const tpl = segs.map((s, i) => {
      if (i > 0 && s && ID_SEGMENT.test(s) && !/^v\d+$/i.test(s)) { hasId = true; return ":id"; }
      return s;
    });
    if (!hasId) continue;
    // One :id per template (the last one), the others stay literal: the matrix replays one object id.
    const last = tpl.lastIndexOf(":id");
    const path = tpl.map((s, i) => (s === ":id" && i !== last ? segs[i]! : s)).join("/");
    if (known.has(path)) continue;
    const prev = segs[last - 1] ?? "resource";
    const name = (prev.replace(/[^A-Za-z0-9_-]/g, "") || "resource").replace(/ies$/, "y").replace(/s$/, "");
    const cur = out.get(path) ?? { name, path, methods: [], examples: [] };
    if (!cur.methods.includes(r.method)) cur.methods.push(r.method);
    if (cur.examples.length < 3 && !cur.examples.includes(r.path)) cur.examples.push(r.path);
    out.set(path, cur);
  }
  return [...out.values()];
}

/** Each suggested resource becomes an info lead: declare it (with B's ids) and authz-replay decides. */
export function katanaFindings(suggested: SuggestedResource[]): Finding[] {
  return suggested.map((s) => ({
    id: `toolbox.katana:resource:${s.path}`, check: "toolbox.katana", state: "unproven", severity: "info",
    location: `${s.methods.join("/")} ${s.path}`,
    title: `Route avec identifiant non déclarée dans la matrice: ${s.path}`,
    description: `${TOOL_NOTE} katana a trouvé ${s.examples.map((e) => clean(e, 120)).join(", ")}. Si l'objet appartient à un compte, cette route doit refuser les autres comptes.`,
    remediation: `Ajouter à options.authz-matrix.resources: { name: ${s.name}, path: ${s.path}, methods: [GET] }, puis les ids du compte B dans accounts.b.owns.${s.name}. Le validateur authz-replay décidera.`,
  }));
}

/* ---------------- trufflehog ---------------- */

export interface SecretLead { detector: string; file: string; line: number; verified: boolean; fingerprint: string }

/** Path relative to the mounted project (/project/...). */
function projectRel(file: string): string {
  return file.replace(/\\/g, "/").replace(/^\/project\/?/, "");
}

export function parseTrufflehog(text: string): { leads: SecretLead[]; findings: Finding[]; claims: Claim[]; raw: Untrusted; skipped: number } {
  const { rows, bad } = jsonLines(text);
  let skipped = bad;
  const leads: SecretLead[] = [];
  const findings: Finding[] = [];
  const claims: Claim[] = [];
  const seen = new Set<string>();
  for (const r of rows) {
    const meta = (((r.SourceMetadata ?? {}) as Record<string, unknown>).Data ?? {}) as Record<string, unknown>;
    const fsMeta = (meta.Filesystem ?? {}) as Record<string, unknown>;
    const detector = clean(r.DetectorName, 60);
    const file = projectRel(clean(fsMeta.file, 300));
    const line = Number(fsMeta.line ?? 0) || 0;
    if (!detector || !file || file.includes("..")) { skipped++; continue; }
    // Never keep the secret: a hash to deduplicate, nothing else.
    const fingerprint = createHash("sha256").update(String(r.Raw ?? "")).digest("hex").slice(0, 16);
    const id = `toolbox.trufflehog:${detector}:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const verified = r.Verified === true;
    leads.push({ detector, file, line, verified, fingerprint });
    findings.push({
      id, check: "toolbox.trufflehog", state: "unproven", severity: verified ? "high" : "medium", location: `${file}:${line}`,
      title: `trufflehog: secret ${detector} dans ${file}`,
      description: `${TOOL_NOTE} Détecteur ${detector}, empreinte ${fingerprint} (le secret n'est pas copié).` +
        (verified ? " trufflehog le dit actif (vérification opt-in, via le proxy); Crenel ne l'a pas rejoué." : " Vérification réseau désactivée."),
      remediation: "Retirer le secret du code et le révoquer chez le fournisseur. exposed-secrets le rejoue sur le disque pour le prouver.",
    });
    // The replay is exposed-secrets on the disk: if it proves a secret on the same file, the lead is confirmed.
    claims.push({ id: `claim:${id}`, class: "check.replay-file", source: "agent", detail: { check: "exposed-secrets", file, line, from: id } });
  }
  return { leads, findings, claims, raw: untrusted("tool:trufflehog", text), skipped };
}
