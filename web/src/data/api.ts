import { useSyncExternalStore } from "react";
import * as mock from "./mock.ts";
import type { Finding, Severity, Target, Task } from "../lib/types.ts";

// The console's data layer. When the page is served by `crenel serve`, it reads
// the local API (same origin, the token travels in an HttpOnly cookie) and
// every page renders the real state. When the API is not there (static build,
// `pnpm dev` alone, SSR tests), it falls back to the demo data in mock.ts.
// Pages read through `useData()`; nothing else in a page changes.

export interface Data {
  live: boolean;
  /** "claude -p" when the server can call a model, null otherwise. */
  llm: string | null;
  /** Custom model provider specs the engine supports (names only, never a key). */
  customProviders: string[];
  /** Model-key env var NAMES set on the server; null when unknown (demo). */
  modelKeys: string[] | null;
  /** Free exploration by default for a run (the config's choice; off without a model). */
  explore: "off" | "assist" | "full";
  project: string;
  targets: Target[];
  findings: Finding[];
  tasks: Task[];
  tests: { name: string; check: string; status: "draft" | "ci"; when: string; finding: string }[];
  secrets: { kind: string; masked: string; loc: string; valid: string; sev: Severity; finding: string }[];
  authzResources: { id: string; label: string; route: string }[];
  authzActors: { id: string; label: string; role: string; cells: Record<string, number> }[];
  /** Replay command per cell ("actor:resource"), live only. */
  authzReplay: Record<string, string>;
  daily: typeof mock.daily;
  activity: { kind: "proven" | "guard" | "task" | "fixed" | "lead"; title: string; meta: string }[];
  onboarding: typeof mock.onboarding;
  guardedCount: number;
  provenCount: number;
}

export const demo: Data = {
  live: false, llm: null, customProviders: [], modelKeys: null, explore: "off", project: "acme-app",
  targets: mock.targets, findings: mock.findings, tasks: mock.tasks, tests: mock.tests, secrets: mock.secrets,
  authzResources: mock.authzResources, authzActors: mock.authzActors, authzReplay: {},
  daily: mock.daily, activity: mock.activity, onboarding: mock.onboarding,
  guardedCount: mock.guardedCount, provenCount: mock.provenCount,
};

let snapshot: Data = demo;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());
const subscribe = (l: () => void) => { listeners.add(l); return () => listeners.delete(l); };

/** Current data: live when the API answered, demo otherwise (always demo on the server). */
export function useData(): Data {
  return useSyncExternalStore(subscribe, () => snapshot, () => demo);
}
export const isLive = () => snapshot.live;

/* ---------------- API calls ---------------- */

export async function apiFetch<T = unknown>(path: string, init: { method?: string; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const res = await fetch(path, {
    method: init.method ?? "GET",
    credentials: "same-origin",
    signal: init.signal,
    headers: init.body !== undefined ? { "content-type": "application/json" } : undefined,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  const text = await res.text();
  const data = text ? (() => { try { return JSON.parse(text); } catch { return text; } })() : null;
  if (!res.ok) throw new Error((data as { error?: string } | null)?.error ?? `HTTP ${res.status}`);
  return data as T;
}

/** Re-read /api/state. Stays in demo mode when the API is not reachable. */
export async function refresh(): Promise<boolean> {
  if (typeof window === "undefined" || typeof fetch === "undefined") return false;
  try {
    const s = await apiFetch<ServerState>("api/state", { signal: AbortSignal.timeout(4000) });
    if (!s || typeof s !== "object" || !Array.isArray(s.findings)) return false;
    snapshot = toData(s);
    emit();
    return true;
  } catch {
    return false;
  }
}

let timer: ReturnType<typeof setTimeout> | undefined;
/** Coalesced refresh, for bursts of run events. */
export function refreshSoon(ms = 300) {
  clearTimeout(timer);
  timer = setTimeout(() => void refresh(), ms);
}

if (typeof window !== "undefined" && typeof fetch !== "undefined") void refresh();

/* ---------------- mapping server -> console ---------------- */

interface ServerFinding {
  id: string; uid: string; check: string; title: string; severity: string; state: "proven" | "unproven" | "fixed";
  location: string; description: string; remediation: string; firstSeen: string; lastSeen: string;
  proof?: { method: string; replay: string; evidence?: string }; regressionHint?: string; validator?: string | null; verdict?: string;
}
interface ServerRun { id: string; title: string; startedAt: string; endedAt?: string; status: string; outcome?: string; proven: number; leads: number; fixed: number; goal?: { text: string; status: string } }
export interface ServerState {
  project: string | null;
  scope: { allowedHosts: string[]; stagingUrl?: string; allowActiveTesting: boolean } | null;
  llm: string | null;
  customProviders?: string[];
  modelKeys?: string[];
  explore?: "off" | "assist" | "full";
  findings: ServerFinding[];
  scannedAt: string | null;
  runs: ServerRun[];
  authz: { resources: { id: string; label: string; route: string }[]; actors: { id: string; label: string; role: string; cells: Record<string, number> }[]; replay: Record<string, string> } | null;
  authzResources: { name: string; path: string; methods?: string[] }[];
  tests: { uid: string; name: string; check: string; status: "draft"; at: string; code?: string }[];
  audit: { at: string; kind?: string; findings?: { state: string }[] }[];
}

const SEV: Record<string, Severity> = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };
const DAY = 86_400_000;

export function ago(iso?: string | null, now = Date.now()): string {
  if (!iso) return "jamais";
  const d = Math.max(0, now - Date.parse(iso));
  if (d < 60_000) return "à l'instant";
  if (d < 3_600_000) return `il y a ${Math.round(d / 60_000)} min`;
  if (d < DAY) return `il y a ${Math.round(d / 3_600_000)} h`;
  if (d < 2 * DAY) return "hier";
  return `il y a ${Math.round(d / DAY)} j`;
}
const since = (iso?: string) => ago(iso).replace(/^il y a /, "");
const dur = (a: string, b?: string) => {
  if (!b) return undefined;
  const s = Math.round((Date.parse(b) - Date.parse(a)) / 1000);
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, "0")}`;
};

export function toData(s: ServerState): Data {
  const testByUid = new Map(s.tests.map((t) => [t.uid, t]));
  const findings: Finding[] = s.findings.map((f) => ({
    id: f.uid, sev: SEV[f.severity] ?? "info", title: f.title, location: f.location,
    state: f.state === "proven" ? "proven" : f.state === "fixed" ? "fixed" : "lead",
    seen: since(f.firstSeen), check: f.check, description: f.verdict && f.state !== "proven" ? `${f.description} (${f.verdict})` : f.description,
    remediation: f.remediation, proof: f.proof, regression: testByUid.get(f.uid)?.code,
    // "Gardé" means a test runs in CI; Crenel cannot see your CI, so it never claims it.
    guarded: false,
  }));
  const project = s.project ?? "projet";
  const host = s.scope?.stagingUrl ? new URL(s.scope.stagingUrl).host : s.scope?.allowedHosts[0] ?? "local";
  const open = findings.filter((f) => f.state !== "fixed");
  const targets: Target[] = [{
    id: "project", name: project, url: host, kind: s.scope?.stagingUrl ? "site" : "repo", env: s.scope?.allowActiveTesting ? "sondes actives" : "lecture seule",
    findings: open.length, proven: open.filter((f) => f.state === "proven").length, lastScan: ago(s.scannedAt),
  }];
  const tasks: Task[] = s.runs.map((r) => ({
    id: r.id, title: r.goal ? `Objectif: ${r.goal.text}` : r.title, target: project, when: ago(r.startedAt),
    trigger: r.goal ? "objectif" : "manuel", dur: dur(r.startedAt, r.endedAt),
    status: r.status === "waiting" ? "waiting" : r.status === "running" ? "running" : r.status === "done" ? "done" : "stopped",
    proven: r.proven || undefined, leads: r.leads || undefined, fixed: r.fixed || undefined,
  }));
  const tests = s.tests.map((t) => ({ name: t.name, check: t.check, status: "draft" as const, when: ago(t.at), finding: t.uid }));
  const secrets = findings
    .filter((f) => (f.check === "exposed-secrets" || f.check === "baas-exposure" || f.check === "committed-credentials") && f.state !== "fixed")
    .map((f) => ({ kind: f.title, masked: f.proof?.evidence ?? "(masqué)", loc: f.location, valid: "inconnue", sev: f.sev, finding: f.id }));
  const authzResources = s.authz?.resources ?? s.authzResources.map((r) => ({ id: r.name, label: r.name, route: `${(r.methods ?? ["GET"]).join("/")} ${r.path}` }));
  const authzActors = s.authz?.actors ?? [
    { id: "a", label: "Compte A", role: "autre tenant", cells: {} },
    { id: "anon", label: "Anonyme", role: "sans jeton", cells: {} },
  ];

  // 90-day series from the audit log (one line per scan) and the runs.
  const today = Math.floor(Date.now() / DAY);
  const series = () => Array.from({ length: 90 }, () => 0);
  const daily = { detected: series(), proven: series(), guarded: series(), leads: series(), fixed: series(), tasks: series(), minutes: series() };
  const slot = (iso: string) => { const i = 89 - (today - Math.floor(Date.parse(iso) / DAY)); return i >= 0 && i < 90 ? i : -1; };
  for (const a of s.audit) {
    if (a.kind && a.kind !== "scan") continue;
    const i = slot(a.at);
    if (i < 0 || !a.findings) continue;
    daily.detected[i] = Math.max(daily.detected[i]!, a.findings.length);
    daily.proven[i] = Math.max(daily.proven[i]!, a.findings.filter((x) => x.state === "proven").length);
    daily.leads[i] = Math.max(daily.leads[i]!, a.findings.filter((x) => x.state === "unproven").length);
  }
  const secs: number[][] = Array.from({ length: 90 }, () => []);
  for (const r of s.runs) {
    const i = slot(r.startedAt);
    if (i < 0) continue;
    daily.tasks[i]!++;
    daily.fixed[i]! += r.fixed;
    if (r.endedAt) secs[i]!.push(Math.round((Date.parse(r.endedAt) - Date.parse(r.startedAt)) / 1000));
  }
  secs.forEach((l, i) => { daily.minutes[i] = l.length ? l.sort((a, b) => a - b)[Math.floor(l.length / 2)]! : 0; });

  const activity: Data["activity"] = [
    ...s.findings.filter((f) => f.state === "proven").map((f) => ({ kind: "proven" as const, title: `Prouvé: ${f.title}`, meta: `${ago(f.firstSeen)} · ${f.validator ?? "validateur"}`, at: f.firstSeen })),
    ...s.findings.filter((f) => f.state === "fixed").map((f) => ({ kind: "fixed" as const, title: `Corrigé: ${f.title}`, meta: ago(f.lastSeen), at: f.lastSeen })),
    ...s.runs.map((r) => ({ kind: "task" as const, title: `${r.status === "done" ? "Tâche terminée" : r.status === "stopped" ? "Tâche interrompue" : "Tâche en cours"}: ${r.title}`, meta: ago(r.startedAt), at: r.startedAt })),
  ].sort((a, b) => b.at.localeCompare(a.at)).slice(0, 6).map(({ at: _at, ...x }) => x);

  return {
    live: true, llm: s.llm, customProviders: s.customProviders ?? [], modelKeys: s.modelKeys ?? null, explore: s.explore ?? (s.llm ? "assist" : "off"), project, targets, findings, tasks, tests, secrets, authzResources, authzActors,
    authzReplay: s.authz?.replay ?? {}, daily, activity,
    onboarding: mock.onboarding.map((o) => ({ ...o, done: o.id === "target" ? (s.scope?.allowedHosts.length ?? 0) > 0 : false })),
    guardedCount: 0,
    provenCount: findings.filter((f) => f.state === "proven").length,
  };
}
