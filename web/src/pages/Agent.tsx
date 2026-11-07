import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { ShieldQuestion, SquarePen } from "lucide-react";
import { Mark } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { Composer } from "../components/Composer.tsx";
import { Button, Dots, SeverityChip, StateBadge, EffortBars } from "../components/ui.tsx";
import { agentAfterAllow, agentAfterDeny, agentScript, tasks } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import type { AgentEvent } from "../lib/types.ts";
import { effortOf, modeLabel, modelLabel, useWorkspace } from "../lib/workspace.tsx";

type Phase = "running" | "waiting" | "idle" | "interrupted";
type Decision = "once" | "always" | "deny";

const defaultPrompt = (t: string) => `Scanne ${t}: secrets, dépendances et autorisation entre comptes.`;
const TICK = 850;

function reply(q: string, target: string, url: string): string {
  const s = q.toLowerCase();
  if (s.startsWith("/cible")) return `Cible active: ${target} (${url}). Je ne touche qu'aux hôtes déclarés pour cette cible; tout le reste est bloqué au niveau réseau.`;
  if (s.startsWith("/explain") || s.includes("stripe") || s.includes("expliqu")) return "La clé sk_live_ de dist/app.js:5 est dans le bundle servi au navigateur, donc publique. Preuve: grep -nE 'sk_(live|test)_' dist/app.js la retrouve à chaque build. À traiter comme compromise: révoquez-la dans Stripe, puis déplacez l'appel côté serveur.";
  if (s.startsWith("/fix") || s.includes("corrig")) return "Je prépare un diff par faille prouvée et le test qui va avec. Rien n'est poussé sans vous: je vous montre la PR en brouillon d'abord.";
  if (s.startsWith("/test") || s.includes("test")) return "1 test en brouillon (A ne peut pas lire le projet de B) et 6 déjà gardés en CI. Une fois le brouillon fusionné, la faille d'autorisation ne pourra plus revenir sans casser le build.";
  if (s.startsWith("/secrets") || s.includes("secret") || s.includes("clé")) return "3 secrets trouvés: clé Stripe (active, prouvée), clé PEM (prouvée), clé Google (piste: restriction par domaine à vérifier). Les deux premières sont à révoquer maintenant.";
  return `Compris. Je reste en lecture seule sur ${target}. Dites-moi quoi attaquer, ou tapez / pour voir les commandes.`;
}

function initial(state: unknown, targetName: string): { events: AgentEvent[]; queue: AgentEvent[]; phase: Phase; title: string; decisions: Record<number, Decision> } {
  const st = (state ?? {}) as { prompt?: string; taskId?: string };
  const task = st.taskId ? tasks.find((t) => t.id === st.taskId) : undefined;
  if (task && task.id !== "t-live") {
    const before = agentScript.filter((e) => e.kind !== "permission");
    const perm = agentScript.find((e) => e.kind === "permission")!;
    const events = [{ kind: "user", text: task.title } as AgentEvent, ...before, perm, ...agentAfterAllow];
    return { events, queue: [], phase: "idle", title: task.title, decisions: { [before.length + 1]: "once" } };
  }
  const prompt = st.prompt ?? task?.title ?? defaultPrompt(targetName);
  return { events: [{ kind: "user", text: prompt }], queue: [...agentScript], phase: "running", title: task?.title ?? prompt, decisions: {} };
}

function fmtTokens(n: number) {
  return `${(n / 1000).toLocaleString("fr-FR", { minimumFractionDigits: 1, maximumFractionDigits: 1 })} k`;
}

export function Agent() {
  const location = useLocation();
  const ws = useWorkspace();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const init = useMemo(() => initial(location.state, ws.target.name), [location.key]);
  const [events, setEvents] = useState<AgentEvent[]>(init.events);
  const [queue, setQueue] = useState<AgentEvent[]>(init.queue);
  const [phase, setPhase] = useState<Phase>(init.phase);
  const [decisions, setDecisions] = useState<Record<number, Decision>>(init.decisions);
  const [allowed, setAllowed] = useState<string[]>([]);
  const [stream, setStream] = useState<{ idx: number; full: string; len: number } | null>(null);
  const [input, setInput] = useState("");
  const endRef = useRef<HTMLDivElement>(null);
  const permRef = useRef<HTMLButtonElement>(null);

  // Reset when navigating here again with a new prompt or task.
  useEffect(() => {
    setEvents(init.events); setQueue(init.queue); setPhase(init.phase); setDecisions(init.decisions); setStream(null);
  }, [init]);

  // Script playback, one event per tick. A permission event pauses the run.
  useEffect(() => {
    if (phase !== "running") return;
    if (queue.length === 0) { setPhase("idle"); return; }
    const t = setTimeout(() => {
      const [next, ...rest] = queue;
      if (!next) return;
      if (next.kind === "permission" && (ws.mode === "probes" || allowed.includes(next.host))) {
        setEvents((e) => [...e, { kind: "note", text: `${next.tool}: requêtes vers ${next.host} autorisées par le mode « ${modeLabel(ws.mode)} ».`, tone: "muted" }]);
        setQueue([...agentAfterAllow]);
        return;
      }
      setEvents((e) => [...e, next]);
      setQueue(rest);
      if (next.kind === "permission") setPhase("waiting");
    }, TICK);
    return () => clearTimeout(t);
  }, [phase, queue, ws.mode, allowed]);

  // Streamed replies to the user's own messages.
  useEffect(() => {
    if (!stream) return;
    if (stream.len >= stream.full.length) { setStream(null); return; }
    const t = setTimeout(() => {
      const len = Math.min(stream.full.length, stream.len + 3);
      setEvents((e) => e.map((ev, i) => (i === stream.idx && ev.kind === "say" ? { ...ev, text: stream.full.slice(0, len) } : ev)));
      setStream({ ...stream, len });
    }, 14);
    return () => clearTimeout(t);
  }, [stream]);

  // Keep the latest event in view: scroll the shell's scroll container to its
  // bottom (the dock is in flow, so the transcript ends just above it).
  useEffect(() => {
    const scroller = endRef.current?.closest(".main");
    if (scroller) scroller.scrollTop = scroller.scrollHeight;
  }, [events.length, stream?.len, phase]);
  useEffect(() => { if (phase === "waiting") permRef.current?.focus(); }, [phase]);

  const decide = useCallback((d: Decision) => {
    const idx = events.length - 1;
    const ev = events[idx];
    if (phase !== "waiting" || !ev || ev.kind !== "permission") return;
    setDecisions((m) => ({ ...m, [idx]: d }));
    if (d === "always") setAllowed((a) => [...a, ev.host]);
    setQueue(d === "deny" ? [...agentAfterDeny] : [...agentAfterAllow]);
    setPhase("running");
  }, [events, phase]);

  const interrupt = useCallback(() => {
    if (phase !== "running" && phase !== "waiting" && !stream) return;
    if (phase === "waiting") setDecisions((m) => ({ ...m, [events.length - 1]: "deny" }));
    setQueue([]); setStream(null);
    setEvents((e) => [...e, { kind: "note", text: "Interrompu. Que dois-je faire à la place ?", tone: "warn" }]);
    setPhase("interrupted");
  }, [phase, stream, events.length]);

  // Escape interrupts; 1/2/3 answer a pending permission (outside text fields).
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.defaultPrevented) return;
      if (e.key === "Escape") { interrupt(); return; }
      const inField = (e.target as HTMLElement)?.tagName === "TEXTAREA" || (e.target as HTMLElement)?.tagName === "INPUT";
      if (phase === "waiting" && !inField) {
        if (e.key === "1") decide("once");
        else if (e.key === "2") decide("always");
        else if (e.key === "3") decide("deny");
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [interrupt, decide, phase]);

  function send(text: string) {
    setInput("");
    const cmd = text.trim().toLowerCase();
    if (cmd === "/clear") { setEvents([]); setQueue([]); setStream(null); setPhase("idle"); return; }
    if (phase === "waiting") setDecisions((m) => ({ ...m, [events.length - 1]: "deny" }));
    setStream(null);
    if (cmd.startsWith("/scan")) {
      setEvents((e) => [...e, { kind: "user", text }]);
      setQueue([...agentScript]); setPhase("running"); return;
    }
    if (cmd.startsWith("/authz")) {
      const perm = agentScript.find((e) => e.kind === "permission")!;
      setEvents((e) => [...e, { kind: "user", text }]);
      setQueue([{ kind: "say", text: "Je relance la matrice d'autorisation: le compte A contre chaque ressource du compte B." }, perm]);
      setPhase("running"); return;
    }
    const full = reply(text, ws.target.name, ws.target.url);
    setQueue([]); setPhase("idle");
    setEvents((e) => {
      const next: AgentEvent[] = [...e, { kind: "user", text }, { kind: "say", text: "" }];
      setStream({ idx: next.length - 1, full, len: 0 });
      return next;
    });
  }

  const busy = phase === "running" || phase === "waiting" || !!stream;
  const tokens = 1800 + events.reduce((n, e) => n + (e.kind === "tool" ? 2300 : e.kind === "permission" ? 600 : 420 + ("text" in e ? e.text.length * 3 : 0)), 0);
  const effort = effortOf(ws.effort);
  const phaseLabel = phase === "running" || stream ? "travaille" : phase === "waiting" ? "attend votre accord" : phase === "interrupted" ? "interrompu" : "prêt";

  return (
    <div className="agent">
      <Topbar scoped compact crumb="Agent" title={init.title.length > 80 ? init.title.slice(0, 78) + "…" : init.title}
        actions={<Button variant="ghost" size="sm" to="/app/overview"><SquarePen size={14} /> Nouvelle tâche</Button>} />

      <div className="transcript" role="log" aria-live="polite" aria-relevant="additions" aria-label="Déroulé de l'agent">
        {events.length === 0 && (
          <div className="tr-empty"><Mark size={28} /><p>Conversation effacée. Tapez <span className="mono">/scan</span> pour relancer.</p></div>
        )}
        {events.map((ev, i) => {
          const isLast = i === events.length - 1;
          if (ev.kind === "user") return (
            <div key={i} className="ev ev-user fade-up"><span className="ev-caret" aria-hidden="true">›</span><p>{ev.text}</p></div>
          );
          if (ev.kind === "say") return (
            <div key={i} className="ev ev-say fade-up">
              <span className="ev-av" aria-label="Crenel"><Mark size={18} /></span>
              <p>{ev.text}{stream?.idx === i && <span className="cursor cursor-blink" aria-hidden="true" />}</p>
            </div>
          );
          if (ev.kind === "note") return (
            <div key={i} className={cn("ev ev-note fade-up", ev.tone)}><span className="elbow" aria-hidden="true" />{ev.text}</div>
          );
          if (ev.kind === "tool") {
            const running = isLast && phase === "running";
            const hasProven = ev.findings?.some((f) => f.state === "proven");
            return (
              <div key={i} className="ev ev-tool fade-up">
                <div className="ev-head">
                  <span className={cn("bullet", running ? "run" : hasProven ? "bad" : "ok")} aria-hidden="true" />
                  <span className="mono"><b>{ev.tool}</b><span className="faint">({ev.args})</span></span>
                  {!running && <span className="ev-dur mono">{ev.dur}</span>}
                </div>
                <div className="ev-res">
                  <span className="elbow" aria-hidden="true" />
                  {running ? (
                    <span className="loader-row"><Dots /> exécution…</span>
                  ) : (
                    <div className="ev-res-body">
                      {ev.lines.map((l, j) => <div key={j} className="mono faint ev-line">{l}</div>)}
                      {ev.findings?.map((f, j) => (
                        <div key={`f${j}`} className={cn("ev-find", f.sev)}>
                          <SeverityChip sev={f.sev} />
                          <span className="ev-find-t">{f.text}</span>
                          <StateBadge state={f.state} />
                          {f.id && <Link to={`/app/findings/${f.id}`} className="linkish ev-find-l">voir</Link>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          }
          // permission
          const d = decisions[i];
          return (
            <div key={i} className="ev ev-tool fade-up">
              <div className="ev-head">
                <span className={cn("bullet", d ? "ok" : "wait")} aria-hidden="true" />
                <span className="mono"><b>{ev.tool}</b><span className="faint">(compte A → compte B)</span></span>
              </div>
              {d ? (
                <div className="ev-res"><span className="elbow" aria-hidden="true" />
                  <span className={cn("perm-done", d === "deny" && "deny")}>
                    {d === "once" ? `Autorisé une fois · ${ev.requests.length} requêtes vers ${ev.host}` : d === "always" ? `Toujours autorisé pour ${ev.host}` : "Refusé, rien n'a été envoyé"}
                  </span>
                </div>
              ) : (
                <div className="perm" role="group" aria-labelledby={`perm-${i}`}>
                  <div className="perm-hd" id={`perm-${i}`}>
                    <ShieldQuestion size={16} aria-hidden="true" />
                    <span><b className="mono">{ev.tool}</b> veut envoyer {ev.requests.length} requêtes à <b className="mono">{ev.host}</b></span>
                  </div>
                  <pre className="perm-req">{ev.requests.join("\n")}</pre>
                  <p className="perm-q">Le run est en pause. Autoriser ces requêtes en lecture, avec le jeton du compte A&nbsp;?</p>
                  <div className="perm-opts">
                    <button ref={permRef} type="button" className="perm-b primary" onClick={() => decide("once")}><span className="kn">1</span>Autoriser une fois</button>
                    <button type="button" className="perm-b" onClick={() => decide("always")}><span className="kn">2</span>Toujours pour cet hôte</button>
                    <button type="button" className="perm-b" onClick={() => decide("deny")}><span className="kn">3</span>Refuser <span className="faint">Échap</span></button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
        {phase === "running" && events[events.length - 1]?.kind !== "tool" && (
          <div className="ev ev-thinking"><span className="bullet run" aria-hidden="true" /><span className="loader-row">Crenel réfléchit <Dots /></span></div>
        )}
        <div ref={endRef} />
      </div>

      <div className="dock">
        <Composer
          variant="dock" value={input} onChange={setInput} onSubmit={send} busy={busy} onStop={interrupt}
          placeholder={phase === "waiting" ? "Répondez à la demande ci-dessus, ou écrivez pour la refuser" : "Demandez une suite, ou tapez / pour les commandes"}
        />
        <div className="statusline">
          <span className="sl-l">
            <span className={cn("sl-dot", busy && "on")} aria-hidden="true" />
            <span className="sl-phase">{phaseLabel}</span>
            <span className="mono">{ws.target.name}</span>
            <span className="hide-sm">{modeLabel(ws.mode)}</span>
            <span className="hide-sm">{modelLabel(ws.model)}</span>
            <span className="sl-eff hide-sm"><EffortBars level={effort.level} />{effort.label}</span>
            <span className="mono">{fmtTokens(tokens)} tokens</span>
            {allowed.length > 0 && <span className="mono hide-sm">{allowed.join(", ")} autorisé</span>}
          </span>
          <span className="sl-r hide-sm"><kbd>/</kbd> commandes <kbd>Échap</kbd> interrompre</span>
        </div>
      </div>
    </div>
  );
}
