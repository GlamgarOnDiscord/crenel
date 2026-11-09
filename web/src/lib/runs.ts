// Agent runs in the console: the link that reopens one, and the follow-ups
// offered under its final summary (scripted in the demo, derived from what the
// run really found with crenel serve).
import type { AgentEvent } from "./types.ts";

export const DEMO_SUGGESTIONS = ["/fix Préparer les correctifs", "/test Fusionner le test d'isolation", "/explain La clé Stripe"];

/** Live follow-ups: explain the first proven finding, generate its test, re-run the scan. */
export function suggestionsFor(events: AgentEvent[]): string[] {
  const found = events.flatMap((e) => (e.kind === "tool" ? e.findings ?? [] : []));
  const proven = found.filter((f) => f.state === "proven");
  const out: string[] = [];
  if (proven[0]) out.push(`/explain ${proven[0].text}`);
  if (proven.length) out.push("/test");
  else if (found[0]) out.push(`/explain ${found[0].text}`);
  out.push("/scan");
  return out;
}

/** The console route that reopens a task in the agent; a URL, so it can be copied and shared. */
export const taskRoute = (id: string) => `/app/agent?task=${encodeURIComponent(id)}`;

/** The task the agent page should open: router state first (in-app navigation), then ?task= (a copied link). */
export function taskIdOf(state: unknown, search: string): string | undefined {
  const st = (state ?? {}) as { taskId?: string };
  if (st.taskId) return st.taskId;
  return new URLSearchParams(search).get("task") ?? undefined;
}
