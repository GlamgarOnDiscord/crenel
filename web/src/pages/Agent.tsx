import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { ArrowDown, Brain, Check, ChevronDown, CircleDashed, ExternalLink, Loader2, Minus, ShieldQuestion, SquarePen, Wrench, X } from "lucide-react";
import { Mark } from "../brand/Logo.tsx";
import { ModelLogo } from "../brand/ModelLogo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { Composer } from "../components/Composer.tsx";
import { Button, CodeBlock, ContextGauge, Dots, EffortBars, SeverityChip, Shimmer, StateBadge } from "../components/ui.tsx";
import { agentAfterAllow, agentAfterDeny, agentScript, tasks } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import type { AgentEvent, Source } from "../lib/types.ts";
import { CONTEXT_WINDOW, effortOf, modeLabel, modelOf, useWorkspace } from "../lib/workspace.tsx";

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
  return `Compris. Je reste sur ${target}, dans le périmètre déclaré. Dites-moi quoi attaquer, ou tapez / pour voir les commandes.`;
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



/* ---------- AI building blocks, re-implemented in Crenel's own CSS after the
   patterns of Vercel AI Elements (Apache-2.0) and prompt-kit (MIT). No code
   copied from either. ---------- */

function Reasoning({ text, dur, live }: { text: string; dur: string; live: boolean }) {
  const [open, setOpen] = useState(live);
  useEffect(() => { if (!live) setOpen(false); }, [live]);
  return (
    <div className="reason">
      <button type="button" className="reason-hd" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <Brain size={14} aria-hidden="true" />
        {live ? <Shimmer>Réflexion…</Shimmer> : <span>Réflexion · {dur}</span>}
        <ChevronDown size={13} className={cn("chev", open && "up")} aria-hidden="true" />
      </button>
      {open && <p className="reason-b">{text}</p>}
    </div>
  );
}

type StepState = "done" | "run" | "todo" | "skip";
function Plan({ steps, state }: { steps: { tool: string; label: string }[]; state: (tool: string) => StepState }) {
  const [open, setOpen] = useState(true);
  const done = steps.filter((s) => state(s.tool) === "done").length;
  return (
    <div className="plan">
      <button type="button" className="plan-hd" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span>Plan</span><span className="mono faint">{done}/{steps.length}</span>
        <span className="plan-bar" aria-hidden="true"><i style={{ width: `${(done / steps.length) * 100}%` }} /></span>
        <ChevronDown size={13} className={cn("chev", open && "up")} aria-hidden="true" />
      </button>
      {open && (
        <ol className="plan-list">
          {steps.map((s) => {
            const st = state(s.tool);
            return (
              <li key={s.tool} className={cn("pstep", st)}>
                <span className="pstep-ic" aria-hidden="true">
                  {st === "done" ? <Check size={11} strokeWidth={3} /> : st === "run" ? <Loader2 size={11} className="spin" /> : st === "skip" ? <Minus size={11} /> : <CircleDashed size={11} />}
                </span>
                {st === "run" ? <Shimmer>{s.label}</Shimmer> : <span>{s.label}</span>}
                <span className="sr-only">{st === "done" ? " (fait)" : st === "run" ? " (en cours)" : st === "skip" ? " (ignoré)" : " (à faire)"}</span>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}

function ToolCall({ ev, running }: { ev: Extract<AgentEvent, { kind: "tool" }>; running: boolean }) {
  const [open, setOpen] = useState(false);
  const proven = ev.findings?.some((f) => f.state === "proven");
  return (
    <div className="tool">
      <button type="button" className="tool-hd" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <Wrench size={14} aria-hidden="true" />
        <span className="mono tool-n">{running ? <Shimmer>{ev.tool}</Shimmer> : ev.tool}</span>
        <span className="mono faint tool-a">{ev.args}</span>
        <span className="sp" />
        {running ? <span className="tpill run"><Loader2 size={11} className="spin" aria-hidden="true" />en cours</span>
          : <span className={cn("tpill", proven && "bad")}>{proven ? "faille prouvée" : "terminé"}</span>}
        {!running && <span className="mono faint tool-d">{ev.dur}</span>}
        <ChevronDown size={13} className={cn("chev", open && "up")} aria-hidden="true" />
      </button>
      {open && (
        <div className="tool-b">
          <div className="tool-sec"><span className="tool-lab">Entrée</span><pre>{ev.input}</pre></div>
          <div className="tool-sec"><span className="tool-lab">Sortie</span><pre>{running ? "…" : ev.lines.join("\n")}</pre></div>
        </div>
      )}
      {!running && ev.findings && ev.findings.length > 0 && (
        <div className="tool-f">
          {ev.findings.map((f, j) => (
            <div key={j} className={cn("ev-find", f.state)}>
              <SeverityChip sev={f.sev} />
              <span className="ev-find-t">{f.text}</span>
              <StateBadge state={f.state} />
              {f.id && <Link to={`/app/findings/${f.id}`} className="linkish ev-find-l">voir</Link>}
            </div>
          ))}
        </div>
      )}
      {!running && ev.code && <div className="tool-code"><CodeBlock file={ev.code.file} code={ev.code.body} /></div>}
    </div>
  );
}

function Sources({ items }: { items: Source[] }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="sources">
      <button type="button" className="sources-hd" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {items.length} sources <ChevronDown size={12} className={cn("chev", open && "up")} aria-hidden="true" />
      </button>
      {open && (
        <ul className="sources-l">
          {items.map((s) => (
            <li key={s.label}><a href={s.href} target="_blank" rel="noopener noreferrer"><span className="faint">{s.kind}</span>{s.label}<ExternalLink size={11} aria-hidden="true" /></a></li>
          ))}
        </ul>
      )}
    </div>
  );
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
      if (next.kind === "permission" && ws.mode === "readonly") {
        setEvents((e) => [...e, { kind: "note", text: `${next.tool}: aucune requête envoyée à ${next.host}, le mode est « Lecture seule ».`, tone: "muted" }]);
        setQueue([...agentAfterDeny.slice(1)]);
        return;
      }
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

  // Stick to the bottom while the user is near it; otherwise show a
  // "Revenir en bas" button (after prompt-kit ScrollButton).
  const [away, setAway] = useState(false);
  const awayRef = useRef(false);
  useEffect(() => {
    const scroller = endRef.current?.closest(".main") as HTMLElement | null;
    if (!scroller) return;
    function onScroll() {
      const a = scroller!.scrollHeight - scroller!.scrollTop - scroller!.clientHeight > 160;
      awayRef.current = a; setAway(a);
    }
    scroller.addEventListener("scroll", onScroll, { passive: true });
    return () => scroller.removeEventListener("scroll", onScroll);
  }, []);
  function toBottom() {
    const scroller = endRef.current?.closest(".main") as HTMLElement | null;
    if (scroller) scroller.scrollTop = scroller.scrollHeight;
  }
  useEffect(() => { if (!awayRef.current) toBottom(); }, [events.length, stream?.len, phase]);
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
  const model = modelOf(ws.model);
  const phaseLabel = phase === "running" || stream ? "travaille" : phase === "waiting" ? "attend votre accord" : phase === "interrupted" ? "interrompu" : "prêt";

  // Plan step state, derived from the events shown so far.
  const lastIdx = events.length - 1;
  function stepState(tool: string): StepState {
    const i = events.findIndex((e) => e.kind === "tool" && e.tool === tool);
    if (i >= 0) return i === lastIdx && phase === "running" ? "run" : "done";
    const permIdx = events.findIndex((e) => e.kind === "permission" && e.tool === tool);
    if (permIdx >= 0) return decisions[permIdx] === "deny" ? "skip" : "run";
    if (tool === "authz.matrix" && events.some((e) => e.kind === "note" && e.text.includes("Lecture seule"))) return "skip";
    if (tool === "tests.generate" && (phase === "idle" || phase === "interrupted") && events.some((e) => e.kind === "plan")) {
      return events.some((e) => e.kind === "tool" && e.tool === "scan.deps") ? "skip" : "todo";
    }
    return "todo";
  }

  return (
    <div className="agent">
      <Topbar scoped compact crumb="Agent" title={init.title.length > 80 ? init.title.slice(0, 78) + "…" : init.title}
        actions={<Button variant="ghost" size="sm" to="/app/overview"><SquarePen size={14} /> Nouvelle tâche</Button>} />

      <div className="transcript" role="log" aria-live="polite" aria-relevant="additions" aria-label="Déroulé de l'agent">
        {events.length === 0 && (
          <div className="tr-empty"><Mark size={28} /><p>Conversation effacée. Tapez <span className="mono">/scan</span> pour relancer.</p></div>
        )}
        {events.map((ev, i) => {
          const isLast = i === lastIdx;
          if (ev.kind === "user") return (
            <div key={i} className="msg-user fade-up"><p>{ev.text}</p></div>
          );
          if (ev.kind === "think") return <div key={i} className="fade-up"><Reasoning text={ev.text} dur={ev.dur} live={isLast && phase === "running"} /></div>;
          if (ev.kind === "plan") return <div key={i} className="fade-up"><Plan steps={ev.steps} state={stepState} /></div>;
          if (ev.kind === "say") return (
            <div key={i} className="msg-ai fade-up">
              <span className="ev-av" aria-label="Crenel"><Mark size={20} /></span>
              <div className="msg-ai-b">
                <p>{ev.text}{stream?.idx === i && <span className="cursor cursor-blink" aria-hidden="true" />}</p>
                {ev.sources && <Sources items={ev.sources} />}
              </div>
            </div>
          );
          if (ev.kind === "note") return (
            <div key={i} className={cn("ev-note fade-up", ev.tone)}><span className="elbow" aria-hidden="true" />{ev.text}</div>
          );
          if (ev.kind === "tool") return <div key={i} className="fade-up"><ToolCall ev={ev} running={isLast && phase === "running"} /></div>;
          // permission = Confirmation
          const d = decisions[i];
          return (
            <div key={i} className="fade-up">
              {d ? (
                <div className="tool">
                  <div className="tool-hd static">
                    <ShieldQuestion size={14} aria-hidden="true" />
                    <span className="mono tool-n">{ev.tool}</span><span className="mono faint tool-a">{ev.requests.length} requêtes vers {ev.host}</span>
                    <span className="sp" />
                    <span className={cn("tpill", d !== "deny" && "brand")}>{d === "once" ? "autorisé une fois" : d === "always" ? "toujours autorisé" : "refusé"}</span>
                  </div>
                </div>
              ) : (
                <div className="perm" role="group" aria-labelledby={`perm-${i}`}>
                  <div className="perm-hd" id={`perm-${i}`}>
                    <span className="ichip brand" aria-hidden="true"><ShieldQuestion size={15} /></span>
                    <span><b className="mono">{ev.tool}</b> veut envoyer {ev.requests.length} requêtes à <b className="mono">{ev.host}</b></span>
                  </div>
                  <pre className="perm-req">{ev.requests.join("\n")}</pre>
                  <p className="perm-q">Le run est en pause. Lecture seule, avec le jeton du compte A.</p>
                  <div className="perm-opts">
                    <button ref={permRef} type="button" className="perm-b primary" onClick={() => decide("once")}><span className="kn">1</span>Autoriser une fois</button>
                    <button type="button" className="perm-b" onClick={() => decide("always")}><span className="kn">2</span>Toujours pour cet hôte</button>
                    <button type="button" className="perm-b" onClick={() => decide("deny")}><X size={13} aria-hidden="true" />Refuser <span className="kn">Échap</span></button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
        {phase === "running" && events[lastIdx]?.kind !== "tool" && events[lastIdx]?.kind !== "think" && (
          <div className="ev-thinking"><Dots /><Shimmer>Crenel réfléchit</Shimmer></div>
        )}
        <div ref={endRef} />
      </div>

      <div className="dock">
        {away && (
          <button type="button" className="tobottom" onClick={toBottom}><ArrowDown size={14} aria-hidden="true" /> Revenir en bas</button>
        )}
        <Composer
          variant="dock" value={input} onChange={setInput} onSubmit={send} busy={busy} onStop={interrupt}
          placeholder={phase === "waiting" ? "Répondez à la demande, ou écrivez pour la refuser" : "Demandez une suite, ou tapez /"}
          extra={<ContextGauge used={tokens} total={CONTEXT_WINDOW[ws.model]} />}
        />
        <div className="statusline">
          <span className="sl-l">
            <span className={cn("sl-dot", busy && "on")} aria-hidden="true" />
            <span className="sl-phase">{phaseLabel}</span>
            <span className="mono">{ws.target.name}</span>
            <span className="hide-sm">{modeLabel(ws.mode)}</span>
            <span className="sl-model hide-sm"><ModelLogo provider={model.provider} size={12} />{model.label}</span>
            <span className="sl-eff hide-sm"><EffortBars level={effort.level} />{effort.label}</span>
            {allowed.length > 0 && <span className="mono hide-sm">{allowed.join(", ")} autorisé</span>}
          </span>
          <span className="sl-r hide-sm"><kbd>/</kbd> commandes <kbd>Échap</kbd> interrompre</span>
        </div>
      </div>
    </div>
  );
}
