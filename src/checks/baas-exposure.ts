// baas-exposure: a Backend-as-a-Service public key in the client bundle, with
// the question that actually matters: is row-level security on?
//
// Apps built fast on Supabase or Firebase ship the project URL and the public
// key to the browser. That is by design: the anon/publishable key is public, and
// the database rules (Postgres RLS, Firebase security rules) are what stop a
// visitor from reading every row. The classic mistake is a table created without
// RLS, readable by anyone holding the public key, which is everyone.
//
// Two layers, same discipline as authz-matrix:
//   - static (always, offline): find URL + public key pairs in the bundle. The
//     key alone proves nothing, so this is a LEAD: "check RLS on every table".
//     (Secret keys, service_role JWT and sb_secret_, are exposed-secrets'
//     job: critical and proven on their own.)
//   - active (opt-in: allowActiveTesting AND the BaaS host in allowedHosts, via
//     the scoped client): read the PostgREST OpenAPI schema with the anon key,
//     then ask each table for ONE row. Read-only, never a write, never more than
//     one row, and the row is never stored or shown: only the table name, the
//     column count and "rows are readable without signing in". A table that
//     answers with a row is PROVEN exposed.
//
// Firebase: Realtime Database answers `/.json?shallow=true` with top-level keys
// only when the rules allow public reads; that is the active probe. Firestore:
// listing collections needs a POST (never sent), but a collection the bundle
// names is read with a GET on the REST API (firestore.googleapis.com must be
// declared); one document back is the proof. Appwrite, PocketBase and Convex have no public-key-equals-access model
// that a GET can prove, so they are leads that point at their permission model.

import { readFileSync, statSync } from "node:fs";

import type { Check, CheckContext, Finding, Severity } from "../core/types.js";
import { walkFiles, extOf, relative } from "../core/walk.js";
import { safeFetch } from "../core/net.js";
import type { Scope } from "../core/scope.js";
import { jwtPayload } from "./exposed-secrets.js";

const TEXT_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json", ".html", ".env", ".txt"]);
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_TABLES = 50;

// Column names that suggest personal or secret data. Names come from the public
// OpenAPI schema (or the keys of the one row), never from row values.
const SENSITIVE_COL = /(e-?mail|phone|password|passwd|pass_hash|token|secret|ssn|iban|card|address|birth|salary|api_?key|stripe|session)/i;

export interface SupabasePair {
  kind: "supabase";
  url: string; // project base URL, no trailing slash
  key: string; // anon JWT or sb_publishable_ key (public by design)
  keyKind: "anon-jwt" | "publishable";
  file: string; // relative to projectDir
  line: number;
}
export interface FirebaseConfig {
  kind: "firebase";
  projectId?: string;
  databaseURL?: string;
  file: string;
  line: number;
}
export interface OtherBaas {
  kind: "appwrite" | "pocketbase" | "convex";
  url: string;
  file: string;
  line: number;
}
export type BaasHit = SupabasePair | FirebaseConfig | OtherBaas;

const lineOf = (content: string, index: number) => content.slice(0, index).split("\n").length;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g;
const PUBLISHABLE_RE = /\bsb_publishable_[A-Za-z0-9_-]{20,}/g;
const SUPABASE_URL_RE = /https:\/\/([a-z0-9-]{6,40})\.supabase\.(co|in)\b/g;
// createClient("https://self-hosted.example", "key"): self-hosted Supabase.
const CREATE_CLIENT_RE = /createClient\(\s*["'`](https?:\/\/[^"'`\s]+)["'`]\s*,\s*["'`]([A-Za-z0-9_.-]{20,})["'`]/g;

/** Pure: find BaaS URL + public key pairs and configs in one file's content. */
export function extractBaas(content: string, file: string): BaasHit[] {
  const hits: BaasHit[] = [];
  const seen = new Set<string>();
  const push = (h: BaasHit) => {
    const k = JSON.stringify([h.kind, "url" in h ? h.url : (h as FirebaseConfig).projectId ?? (h as FirebaseConfig).databaseURL, "key" in h ? h.key : ""]);
    if (!seen.has(k)) { seen.add(k); hits.push(h); }
  };
  const anonKeys: { key: string; ref?: string; index: number }[] = [];
  for (const m of content.matchAll(JWT_RE)) {
    const p = jwtPayload(m[0]);
    if (p?.role === "anon") anonKeys.push({ key: m[0], ref: typeof p.ref === "string" ? p.ref : undefined, index: m.index! });
  }
  const pubKeys = [...content.matchAll(PUBLISHABLE_RE)].map((m) => ({ key: m[0], index: m.index! }));

  // Explicit createClient(url, key) calls first: they pair exactly.
  for (const m of content.matchAll(CREATE_CLIENT_RE)) {
    const key = m[2]!;
    const p = jwtPayload(key);
    const keyKind = key.startsWith("sb_publishable_") ? "publishable" : p?.role === "anon" ? "anon-jwt" : null;
    if (!keyKind) continue;
    push({ kind: "supabase", url: m[1]!.replace(/\/+$/, ""), key, keyKind, file, line: lineOf(content, m.index!) });
  }
  // Hosted projects: https://<ref>.supabase.co with a key in the same file.
  // Prefer the anon JWT whose `ref` claim matches the URL, else the nearest key.
  for (const m of content.matchAll(SUPABASE_URL_RE)) {
    const ref = m[1]!;
    const url = `https://${ref}.supabase.${m[2]}`;
    const near = (k: { index: number }) => Math.abs(k.index - m.index!);
    const byRef = anonKeys.find((k) => k.ref === ref);
    const nearest = [...anonKeys.map((k) => ({ ...k, kk: "anon-jwt" as const })), ...pubKeys.map((k) => ({ ...k, kk: "publishable" as const }))]
      .sort((a, b) => near(a) - near(b))[0];
    const pick = byRef ? { key: byRef.key, kk: "anon-jwt" as const } : nearest ? { key: nearest.key, kk: nearest.kk } : null;
    if (!pick) continue;
    push({ kind: "supabase", url, key: pick.key, keyKind: pick.kk, file, line: lineOf(content, m.index!) });
  }
  // Firebase web config: apiKey + projectId / databaseURL in one object.
  for (const m of content.matchAll(/\bapiKey\s*:\s*["']AIza[0-9A-Za-z_-]{35}["']/g)) {
    const around = content.slice(m.index!, m.index! + 800);
    const projectId = around.match(/\bprojectId\s*:\s*["']([a-z0-9-]{4,40})["']/)?.[1];
    const databaseURL = around.match(/\bdatabaseURL\s*:\s*["'](https:\/\/[a-z0-9.-]+\.(?:firebaseio\.com|firebasedatabase\.app))["']/)?.[1];
    if (!projectId && !databaseURL) continue;
    push({ kind: "firebase", projectId, databaseURL, file, line: lineOf(content, m.index!) });
  }
  for (const m of content.matchAll(/https:\/\/(?:cloud|[a-z0-9-]+\.cloud)\.appwrite\.io\/v1/g)) push({ kind: "appwrite", url: m[0], file, line: lineOf(content, m.index!) });
  for (const m of content.matchAll(/new PocketBase\(\s*["'](https?:\/\/[^"'\s]+)["']/g)) push({ kind: "pocketbase", url: m[1]!, file, line: lineOf(content, m.index!) });
  for (const m of content.matchAll(/https:\/\/[a-z0-9-]+\.convex\.cloud\b/g)) push({ kind: "convex", url: m[0], file, line: lineOf(content, m.index!) });
  return hits;
}

/** Walk the project and collect every BaaS hit. Shared by the check and its validator. */
export function scanBaas(projectDir: string): BaasHit[] {
  const out: BaasHit[] = [];
  for (const file of walkFiles(projectDir, { accept: (n) => TEXT_EXT.has(extOf(n)) })) {
    try {
      if (statSync(file).size > MAX_BYTES) continue;
      out.push(...extractBaas(readFileSync(file, "utf8"), relative(projectDir, file)));
    } catch {
      continue;
    }
  }
  return out;
}

function redactKey(k: string): string {
  return `${k.slice(0, 10)}...${k.slice(-4)} (${k.length} chars)`;
}

export interface TableReadResult {
  table: string;
  status: number;
  /** True when at least one row came back with the public key only. */
  readable: boolean;
  columns: number;
  sensitive: string[];
}

const supaHeaders = (key: string) => ({ apikey: key, authorization: `Bearer ${key}` });

/** List the tables PostgREST exposes, with their column names, from the OpenAPI schema. */
export async function listSupabaseTables(pair: Pick<SupabasePair, "url" | "key">, scope: Scope): Promise<{ table: string; columns: string[] }[]> {
  const res = await safeFetch(`${pair.url}/rest/v1/`, scope, {
    headers: { ...supaHeaders(pair.key), accept: "application/openapi+json" },
  });
  if (res.status !== 200) return [];
  let spec: { paths?: Record<string, unknown>; definitions?: Record<string, { properties?: Record<string, unknown> }> };
  try {
    spec = JSON.parse(res.body);
  } catch {
    return [];
  }
  const tables = Object.keys(spec.paths ?? {})
    .filter((p) => p !== "/" && !p.startsWith("/rpc/"))
    .map((p) => p.slice(1))
    .filter((t) => /^[A-Za-z0-9_]+$/.test(t))
    .slice(0, MAX_TABLES);
  return tables.map((t) => ({ table: t, columns: Object.keys(spec.definitions?.[t]?.properties ?? {}) }));
}

/**
 * Ask one table for at most one row with the public key. The row is parsed only
 * to count it and its keys, then dropped: nothing of its content leaves here.
 */
export async function readOneRow(pair: Pick<SupabasePair, "url" | "key">, table: string, schemaColumns: string[], scope: Scope): Promise<TableReadResult> {
  const res = await safeFetch(`${pair.url}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, scope, {
    headers: { ...supaHeaders(pair.key), accept: "application/json" },
  });
  let rows = 0;
  let keys: string[] = [];
  if (res.status >= 200 && res.status < 300) {
    try {
      const data = JSON.parse(res.body) as unknown;
      if (Array.isArray(data)) {
        rows = data.length;
        if (rows > 0 && data[0] && typeof data[0] === "object") keys = Object.keys(data[0] as object);
      }
    } catch {
      rows = 0;
    }
  }
  const cols = keys.length ? keys : schemaColumns;
  return { table, status: res.status, readable: rows > 0, columns: cols.length, sensitive: cols.filter((c) => SENSITIVE_COL.test(c)) };
}

export function supabaseReplay(url: string, table: string): string {
  return `curl -s '${url}/rest/v1/${table}?select=*&limit=1' -H 'apikey: <ANON_KEY>' -H 'authorization: Bearer <ANON_KEY>'`;
}

/** Build the PROVEN finding for a table readable with the public key. */
export function tableFinding(pair: SupabasePair, r: TableReadResult): Finding {
  const severity: Severity = r.sensitive.length ? "critical" : "high";
  return {
    id: `baas-exposure:supabase-rls:${pair.url}:${r.table}`,
    check: "baas-exposure",
    title: `Table ${r.table} readable without signing in (Supabase RLS)`,
    severity,
    state: "proven",
    location: `${pair.url}/rest/v1/${r.table}`,
    description:
      `With only the public key found in ${pair.file}:${pair.line}, the table ${r.table} returned a row. ` +
      `Anyone who opens the site can read it. ${r.columns} column(s)` +
      (r.sensitive.length ? `, including likely sensitive ones (${r.sensitive.join(", ")}).` : ".") +
      ` The row itself was not kept.`,
    remediation:
      `Enable row-level security on ${r.table} (ALTER TABLE ${r.table} ENABLE ROW LEVEL SECURITY) and add policies ` +
      `that only let a signed-in user read their own rows. Keep the generated test so it cannot come back.`,
    proof: {
      method: "anonymous read replayed with the bundle's public key (limit=1, content not kept)",
      replay: supabaseReplay(pair.url, r.table),
      evidence: `HTTP ${r.status}, 1 row readable without signing in, ${r.columns} column(s) (content not kept)`,
    },
    regressionHint: `The table ${r.table} must not be readable with the anon key.`,
  };
}

/** Realtime Database: shallow read of the root. Returns the number of top-level keys, or null. */
export async function readFirebaseRoot(databaseURL: string, scope: Scope): Promise<{ status: number; keys: number } | null> {
  const res = await safeFetch(`${databaseURL.replace(/\/+$/, "")}/.json?shallow=true`, scope);
  if (res.status !== 200) return { status: res.status, keys: 0 };
  try {
    const data = JSON.parse(res.body) as unknown;
    return { status: 200, keys: data && typeof data === "object" ? Object.keys(data as object).length : 0 };
  } catch {
    return { status: 200, keys: 0 };
  }
}

const FIRESTORE = "https://firestore.googleapis.com";

/** Collection names the client code reads: collection(db, "x"), .collection("x"), doc(db, "x", …). */
export function firestoreCollections(projectDir: string): string[] {
  const out = new Set<string>();
  for (const file of walkFiles(projectDir, { accept: (n) => [".js", ".mjs", ".ts", ".tsx", ".jsx"].includes(extOf(n)) })) {
    let text = "";
    try { if (statSync(file).size > 4 * 1024 * 1024) continue; text = readFileSync(file, "utf8"); } catch { continue; }
    for (const m of text.matchAll(/\b(?:collection|doc|collectionGroup)\(\s*\w+\s*,\s*["'`]([A-Za-z0-9_-]{1,64})["'`]/g)) out.add(m[1]!);
    for (const m of text.matchAll(/\.collection\(\s*["'`]([A-Za-z0-9_-]{1,64})["'`]/g)) out.add(m[1]!);
  }
  return [...out];
}

function hostOf(url: string): string {
  try { return new URL(url).hostname; } catch { return ""; }
}

export const baasExposure: Check = {
  name: "baas-exposure",
  title: "BaaS public key in the bundle, and whether its tables are readable without RLS",
  readOnly: true, // static detection is read-only; live reads are gated separately
  async run(ctx: CheckContext): Promise<Finding[]> {
    const hits = scanBaas(ctx.projectDir);
    const findings: Finding[] = [];
    ctx.log(`baas-exposure: ${hits.length} BaaS config(s) in ${ctx.projectDir}`);
    // Live probing needs both opt-ins: active testing on, and the BaaS host
    // declared as yours. Without them we stay offline and report leads.
    const canProbe = (url: string) => ctx.scope.allowActiveTesting && ctx.scope.isHostAllowed(url);

    for (const h of hits) {
      if (h.kind === "supabase") {
        const lead: Finding = {
          id: `baas-exposure:supabase:${h.url}`,
          check: "baas-exposure",
          title: `Supabase public key in the bundle: check RLS on every table (${hostOf(h.url)})`,
          severity: "medium",
          state: "unproven",
          location: `${h.file}:${h.line}`,
          description:
            `The bundle carries the Supabase project URL ${h.url} and its public ${h.keyKind === "anon-jwt" ? "anon key" : "publishable key"} ` +
            `(${redactKey(h.key)}). That key is public by design: what protects the data is row-level security. ` +
            `Any table without RLS is readable by every visitor.`,
          remediation:
            "Enable RLS on every table in the exposed schemas and write policies per role. To prove it, add " +
            `${hostOf(h.url)} to allowedHosts and turn on allowActiveTesting: Crenel then reads one row per table with this key.`,
          proof: { method: "URL + public key pair found in the bundle", replay: `grep -n '${hostOf(h.url)}' "${h.file}"`, evidence: redactKey(h.key) },
        };
        if (!canProbe(h.url)) { findings.push(lead); continue; }
        ctx.scope.assertActiveAllowed("baas-exposure (live read)");
        let tables: { table: string; columns: string[] }[] = [];
        try {
          tables = await listSupabaseTables(h, ctx.scope);
        } catch (err) {
          ctx.log(`baas-exposure: schema read failed on ${h.url}: ${(err as Error).message}`);
          findings.push(lead);
          continue;
        }
        let proven = 0;
        for (const t of tables) {
          try {
            const r = await readOneRow(h, t.table, t.columns, ctx.scope);
            if (r.readable) { findings.push(tableFinding(h, r)); proven++; }
          } catch (err) {
            ctx.log(`baas-exposure: ${t.table}: ${(err as Error).message}`);
          }
        }
        ctx.log(`baas-exposure: ${tables.length} table(s) exposed by the API, ${proven} readable without signing in`);
        if (proven === 0) findings.push({ ...lead, description: lead.description + ` Live check: ${tables.length} table(s) listed, none returned a row with this key.` });
        continue;
      }
      if (h.kind === "firebase") {
        const label = h.projectId ?? hostOf(h.databaseURL ?? "");
        const lead: Finding = {
          id: `baas-exposure:firebase:${label}`,
          check: "baas-exposure",
          title: `Firebase web config in the bundle: check security rules (${label})`,
          severity: "medium",
          state: "unproven",
          location: `${h.file}:${h.line}`,
          description:
            `The bundle carries a Firebase web config for ${label}. Its apiKey is public by design; Firestore and ` +
            `Realtime Database rules are what protect the data. Open rules (allow read: if true) expose everything.`,
          remediation: "Review Firestore and Realtime Database rules: require request.auth and scope reads to the owner. Restrict the API key by HTTP referrer.",
        };
        if (h.databaseURL && canProbe(h.databaseURL)) {
          ctx.scope.assertActiveAllowed("baas-exposure (live read)");
          try {
            const r = await readFirebaseRoot(h.databaseURL, ctx.scope);
            if (r && r.status === 200 && r.keys > 0) {
              findings.push({
                id: `baas-exposure:firebase-rtdb:${h.databaseURL}`,
                check: "baas-exposure",
                title: `Realtime Database readable without signing in (${hostOf(h.databaseURL)})`,
                severity: "critical",
                state: "proven",
                location: `${h.databaseURL}/.json`,
                description: `A shallow read of the database root answered with ${r.keys} top-level key(s) without any sign-in. The content was not kept.`,
                remediation: "Set Realtime Database rules to deny reads by default and allow only authenticated owners.",
                proof: {
                  method: "anonymous shallow read of the database root (keys only, content not kept)",
                  replay: `curl -s '${h.databaseURL}/.json?shallow=true'`,
                  evidence: `HTTP 200, ${r.keys} top-level key(s) readable without signing in`,
                },
                regressionHint: "The Realtime Database root must not be readable without auth.",
              });
              continue;
            }
          } catch (err) {
            ctx.log(`baas-exposure: firebase read failed: ${(err as Error).message}`);
          }
        }
        // Firestore: a named collection is read with a plain GET on the REST API
        // (OpenFirebase's method). The names come from the bundle itself.
        if (h.projectId && canProbe(FIRESTORE)) {
          ctx.scope.assertActiveAllowed("baas-exposure (live read)");
          let proved = false;
          for (const coll of firestoreCollections(ctx.projectDir).slice(0, 20)) {
            const url = `${FIRESTORE}/v1/projects/${encodeURIComponent(h.projectId)}/databases/(default)/documents/${encodeURIComponent(coll)}?pageSize=1`;
            try {
              const res = await safeFetch(url, ctx.scope);
              const docs = res.status === 200 ? ((JSON.parse(res.body) as { documents?: unknown[] }).documents ?? []) : [];
              if (!docs.length) continue;
              proved = true;
              findings.push({
                id: `baas-exposure:firestore:${h.projectId}:${coll}`, check: "baas-exposure",
                title: `Firestore collection ${coll} readable without signing in (${h.projectId})`, severity: "critical", state: "proven",
                location: url.replace("?pageSize=1", ""),
                description: `An anonymous GET on the Firestore REST API returned a document of ${coll}. Anyone can read the collection. The document was not kept.`,
                remediation: `Firestore rules: deny by default and allow reads of ${coll} only when request.auth.uid owns the document.`,
                proof: { method: "anonymous GET of one document of a collection named in the bundle (content not kept)", replay: `curl -s '${url}'`, evidence: "HTTP 200, 1 document returned without signing in" },
                regressionHint: `The Firestore collection ${coll} must not be readable without auth.`,
              });
            } catch (err) { ctx.log(`baas-exposure: firestore ${coll}: ${(err as Error).message}`); }
          }
          if (proved) continue;
        }
        findings.push(lead);
        continue;
      }
      findings.push({
        id: `baas-exposure:${h.kind}:${h.url}`,
        check: "baas-exposure",
        title: `${h.kind[0]!.toUpperCase() + h.kind.slice(1)} endpoint in the bundle: check its permissions (${hostOf(h.url)})`,
        severity: "low",
        state: "unproven",
        location: `${h.file}:${h.line}`,
        description: `The bundle talks to ${h.url}. Access is decided by the backend's permission rules, not by the URL; a collection left public is readable by anyone.`,
        remediation: h.kind === "convex"
          ? "Check that every public query and mutation verifies ctx.auth before returning data."
          : "Review collection permissions: no public read on collections that hold user data.",
      });
    }
    return findings;
  },
};
