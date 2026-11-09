import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import { apiFetch, refreshSoon, useData } from "./api.ts";
import type { AgentEvent } from "../lib/types.ts";

// Drives the Agent page from a real run of `crenel serve`: starts runs, follows
// their journal over SSE (replayed from the start, then live), and sends the
// user's decisions and the stop. The page keeps its own rendering; this hook
// only feeds the same state setters the scripted demo uses.

type Phase = "running" | "waiting" | "idle" | "interrupted";
type Decision = "once" | "always" | "deny";

export interface GoalProgress {
  text: string;
  label: string;
  status: "active" | "met" | "met-unverified" | "budget" | "stalled" | "stopped" | "unverifiable";
  verified: boolean;
  detail: string;
  iteration: number;
  budget: { maxIterations: number; maxProbes: number; maxMs: number; maxTokens: number };
  remaining?: { iterations: number; probes: number; ms: number; tokens: number };
}

interface Setters {
  setEvents: Dispatch<SetStateAction<AgentEvent[]>>;
  setPhase: Dispatch<SetStateAction<Phase>>;
  setDecisions: Dispatch<SetStateAction<Record<number, Decision>>>;
  setAllowed: Dispatch<SetStateAction<string[]>>;
}

interface Entry { seq: number; type: string; data: Record<string, unknown> & { uid?: string; ev?: AgentEvent } }

export function useLiveAgent(s: Setters) {
  const { live } = useData();
  const runId = useRef<string | null>(null);
  const index = useRef(new Map<string, number>()); // ui uid -> position in events
  const permIds = useRef(new Map<number, string>()); // event index -> permission request id
  const source = useRef<EventSource | null>(null);
  const [goal, setGoal] = useState<GoalProgress | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => () => source.current?.close(), []);

  const onEntry = useCallback((e: Entry) => {
    const d = e.data;
    if (e.type === "ui" && d.ev && d.uid) {
      const uid = d.uid;
      const ev = d.ev;
      s.setEvents((list) => {
        const at = index.current.get(uid) ?? list.length;
        index.current.set(uid, at);
        if (ev.kind === "permission" && "id" in ev) permIds.current.set(at, String((ev as { id: string }).id));
        return at < list.length ? list : [...list, ev];
      });
      if (ev.kind === "tool" || ev.kind === "say") refreshSoon();
    } else if (e.type === "ui.update" && d.ev && d.uid) {
      const at = index.current.get(d.uid);
      const ev = d.ev;
      if (at !== undefined) s.setEvents((list) => list.map((x, i) => (i === at ? ev : x)));
      refreshSoon();
    } else if (e.type === "phase") {
      if (d.phase === "waiting") s.setPhase("waiting");
      else if (d.phase === "running") s.setPhase("running");
    } else if (e.type === "decision") {
      const id = String(d.id);
      const at = [...permIds.current.entries()].find(([, v]) => v === id)?.[0];
      if (at !== undefined) s.setDecisions((m) => ({ ...m, [at]: d.decision as Decision }));
      if (d.decision === "always") s.setAllowed((a) => [...new Set([...a, ...((d.hosts as string[]) ?? [])])]);
    } else if (e.type === "goal.start") {
      setGoal({ text: String(d.text), label: String(d.label), status: "active", verified: false, detail: "", iteration: 0, budget: d.budget as GoalProgress["budget"] });
    } else if (e.type === "goal.iteration") {
      setGoal((g) => g && { ...g, iteration: Number(d.iteration), remaining: d.remaining as GoalProgress["remaining"] });
    } else if (e.type === "goal.check") {
      setGoal((g) => g && { ...g, verified: !!d.verified, detail: String(d.detail), remaining: d.remaining as GoalProgress["remaining"] });
    } else if (e.type === "goal.end") {
      setGoal((g) => g && { ...g, status: d.outcome as GoalProgress["status"], verified: !!d.verified, detail: String(d.detail ?? g.detail), remaining: d.remaining as GoalProgress["remaining"] });
    } else if (e.type === "run.end") {
      s.setPhase(d.outcome === "stopped" ? "interrupted" : "idle");
      refreshSoon(50);
    }
  }, [s]);

  /** Follow a run's journal (replays it from the start, then live). */
  const attach = useCallback((id: string) => {
    source.current?.close();
    runId.current = id;
    const es = new EventSource(`api/runs/${encodeURIComponent(id)}/events`);
    source.current = es;
    const types = ["ui", "ui.update", "phase", "decision", "goal.start", "goal.iteration", "goal.check", "goal.end", "run.end"];
    for (const t of types) es.addEventListener(t, (m) => { try { onEntry(JSON.parse((m as MessageEvent).data) as Entry); } catch { /* ignore a bad frame */ } });
    es.addEventListener("eof", () => { es.close(); if (source.current === es) source.current = null; });
    es.onerror = () => { if (es.readyState === EventSource.CLOSED) setError("Flux interrompu"); };
  }, [onEntry]);

  /** Start a run (or a goal) and follow it. Events are appended to the current conversation. */
  const start = useCallback(async (prompt: string, opts: { mode: string; model: string; modelBaseUrl?: string; modelApiKeyEnv?: string; modelTemperature?: number; effort?: string; goal?: string; explore?: string }) => {
    setError(null);
    s.setPhase("running");
    try {
      // For a custom model, carry its spec plus the connection; the key itself is
      // never sent, only the NAME of its env var (modelApiKeyEnv). See llm.ts.
      const m = { model: opts.model, modelBaseUrl: opts.modelBaseUrl, modelApiKeyEnv: opts.modelApiKeyEnv, modelTemperature: opts.modelTemperature, effort: opts.effort };
      const r = opts.goal
        ? await apiFetch<{ id: string }>("api/goals", { method: "POST", body: { text: opts.goal, mode: opts.mode, ...m, explore: opts.explore } })
        : await apiFetch<{ id: string }>("api/runs", { method: "POST", body: { prompt, mode: opts.mode, ...m, explore: opts.explore } });
      if (!opts.goal) setGoal(null);
      attach(r.id);
    } catch (err) {
      setError((err as Error).message);
      s.setEvents((e) => [...e, { kind: "note", text: `Impossible de lancer la tâche: ${(err as Error).message}`, tone: "warn" }]);
      s.setPhase("idle");
    }
  }, [attach, s]);

  const reset = useCallback(() => {
    source.current?.close();
    source.current = null;
    runId.current = null;
    index.current.clear();
    permIds.current.clear();
    setGoal(null);
  }, []);

  const decide = useCallback((eventIndex: number, d: Decision) => {
    const id = permIds.current.get(eventIndex);
    if (!id || !runId.current) return;
    void apiFetch(`api/runs/${runId.current}/decision`, { method: "POST", body: { id, decision: d } }).catch((err) => setError((err as Error).message));
  }, []);

  const stop = useCallback(() => {
    if (!runId.current) return;
    void apiFetch(`api/runs/${runId.current}/stop`, { method: "POST", body: {} }).catch(() => {});
  }, []);

  return { enabled: live, start, attach, reset, decide, stop, goal, error };
}
