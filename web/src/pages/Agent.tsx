import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Check, CircleDashed, Copy, Goal, Loader2, Minus, RotateCcw, ShieldQuestion, SquarePen, X } from "lucide-react";
import { Mark, type Mood } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { Composer } from "../components/Composer.tsx";
import { Button, SeverityChip, StateBadge } from "../components/ui.tsx";
import { useToast } from "../components/toast.tsx";
import { Conversation, ConversationContent, ConversationEmptyState, ConversationScrollButton } from "../components/ai/conversation.tsx";
import { Message, MessageAction, MessageActions, MessageContent } from "../components/ai/message.tsx";
import { Reasoning, ReasoningContent, ReasoningTrigger } from "../components/ai/reasoning.tsx";
import { Plan, PlanAction, PlanContent, PlanHeader, PlanTitle, PlanTrigger, TaskItem, TaskItemFile } from "../components/ai/plan.tsx";
import { Tool, ToolContent, ToolHeader, ToolInput, ToolOutput } from "../components/ai/tool.tsx";
import { CodeBlock } from "../components/ai/code-block.tsx";
import { Source, Sources, SourcesContent, SourcesTrigger } from "../components/ai/sources.tsx";
import { Confirmation, ConfirmationAccepted, ConfirmationAction, ConfirmationActions, ConfirmationRejected, ConfirmationRequest, ConfirmationTitle } from "../components/ai/confirmation.tsx";
import { Context, ContextContent, ContextTrigger } from "../components/ai/context.tsx";
import { Suggestion, Suggestions } from "../components/ai/suggestion.tsx";
import { Shimmer } from "../components/ai/shimmer.tsx";
import { Skeleton } from "../components/arc/skeleton/skeleton.tsx";
import { Progress } from "../components/arc/progress/progress.tsx";
import { ThinkingBar } from "../components/kit/thinking-bar.tsx";
import { FeedbackBar } from "../components/kit/feedback-bar.tsx";
import { BorderTrail } from "../components/kit/border-trail.tsx";
import { TextMorph } from "../components/kit/text-morph.tsx";
import { Loader } from "../components/kit/loader.tsx";
import { Steps, StepsContent, StepsItem, StepsTrigger } from "../components/kit/steps.tsx";
import { agentAfterAllow, agentAfterDeny, agentScript, tasks } from "../data/mock.ts";
import { useData } from "../data/api.ts";
import { useLiveAgent } from "../data/live-run.ts";
import { cn } from "../lib/cn.ts";
import type { AgentEvent } from "../lib/types.ts";
import { contextWindowOf, goalOf, modeLabel, modelSend, useWorkspace } from "../lib/workspace.tsx";

type Phase = "running" | "waiting" | "idle" | "interrupted";
const GOAL_STATUS: Record<string, string> = {
  active: "en cours", met: "atteint, vérifié", "met-unverified": "atteint selon le modèle, non vérifié", budget: "budget épuisé",
  stalled: "bloqué: une correction est nécessaire", stopped: "interrompu", unverifiable: "invérifiable sans modèle",
};
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
  const permRef = useRef<HTMLButtonElement>(null);
  // With `crenel serve`, the conversation is a real run streamed from the API.
  const live = useLiveAgent({ setEvents, setPhase, setDecisions, setAllowed });
  const data = useData();
  const startLive = (text: string) => {
    const goal = ws.goal !== "none" ? goalOf(ws.goal).text : undefined;
    if (goal) ws.setGoal("none");
    void live.start(text, { mode: ws.mode, ...modelSend(ws.model, ws.customModels), goal, explore: ws.explore ?? undefined });
  };

  // Reset when navigating here again with a new prompt or task.
  useEffect(() => {
    if (live.enabled) {
      live.reset(); setEvents([]); setQueue([]); setDecisions({}); setStream(null);
      const st = (location.state ?? {}) as { prompt?: string; taskId?: string };
      const last = data.tasks[0];
      if (st.taskId) { setPhase("running"); live.attach(st.taskId); }
      else if (st.prompt) startLive(st.prompt);
      else if (last) { setPhase("running"); live.attach(last.id); }
      else startLive(defaultPrompt(ws.target.name));
      return;
    }
    setEvents(init.events); setQueue(init.queue); setPhase(init.phase); setDecisions(init.decisions); setStream(null);
  }, [init, live.enabled]); // eslint-disable-line react-hooks/exhaustive-deps

  // Script playback, one event per tick. A permission event pauses the run.
  useEffect(() => {
    if (live.enabled || phase !== "running") return;
    if (queue.length === 0) { setPhase("idle"); return; }
    const t = setTimeout(() => {
      const [next, ...rest] = queue;
      if (!next) return;
      if (next.kind === "permission" && ws.mode === "readonly") {
        setEvents((e) => [...e, { kind: "note", text: `${next.tool}: aucune requête envoyée à ${next.host}, le mode est « Lecture seule ».`, tone: "muted" }]);
        setQueue([...agentAfterDeny.slice(1)]);
        return;
      }
      if (next.kind === "permission" && (ws.mode === "bypass" || allowed.includes(next.host))) {
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

  useEffect(() => { if (phase === "waiting") permRef.current?.focus(); }, [phase]);

  const decide = useCallback((d: Decision) => {
    const idx = events.length - 1;
    const ev = events[idx];
    if (phase !== "waiting" || !ev || ev.kind !== "permission") return;
    setDecisions((m) => ({ ...m, [idx]: d }));
    if (d === "always") setAllowed((a) => [...a, ev.host]);
    if (live.enabled) { live.decide(idx, d); setPhase("running"); return; }
    setQueue(d === "deny" ? [...agentAfterDeny] : [...agentAfterAllow]);
    setPhase("running");
  }, [events, phase]);

  const interrupt = useCallback(() => {
    if (phase !== "running" && phase !== "waiting" && !stream) return;
    if (live.enabled) { live.stop(); return; }
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
    if (cmd === "/clear") { live.reset(); setEvents([]); setQueue([]); setStream(null); setPhase("idle"); return; }
    if (live.enabled) { if (phase === "running" || phase === "waiting") live.stop(); startLive(text); return; }
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
  // While the run works, a live mascot sits under the conversation: it searches,
  // and celebrates once when the last tool proved a finding.
  const lastTool = [...events].reverse().find((e) => e.kind === "tool");
  const justProved = lastTool?.kind === "tool" && !!lastTool.findings?.some((f) => f.state === "proven");
  const mood: Mood = phase === "running" || stream ? (justProved ? "found" : "working") : "idle";
  const tokens = 1800 + events.reduce((n, e) => n + (e.kind === "tool" ? 2300 : e.kind === "permission" ? 600 : 420 + ("text" in e ? e.text.length * 3 : 0)), 0);
  const phaseLabel = phase === "running" || stream ? "travaille" : phase === "waiting" ? "attend votre accord" : phase === "interrupted" ? "interrompu" : "prêt";
  const toast = useToast();
  const [feedback, setFeedback] = useState(true);

  const lastIdx = events.length - 1;
  type StepState = "done" | "run" | "todo" | "skip";
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
  const finalSay = [...events].map((e, i) => ({ e, i })).reverse().find(({ e }) => e.kind === "say" && !!e.sources)?.i;

  return (
    <div className="agent">
      <Topbar scoped compact crumb="Agent" title={init.title.length > 80 ? init.title.slice(0, 78) + "…" : init.title}
        actions={<Button variant="ghost" size="sm" to="/app/overview"><SquarePen size={14} /> Nouvelle tâche</Button>} />

      <Conversation>
        <ConversationContent aria-live="polite" aria-relevant="additions" aria-label="Déroulé de l'agent">
          {events.length === 0 && (
            <ConversationEmptyState icon={<Mark size={32} />} title="Conversation effacée" description="Tapez /scan pour relancer une analyse." />
          )}
          {events.map((ev, i) => {
            const isLast = i === lastIdx;
            if (ev.kind === "user") return (
              <Message key={i} from="user" className="fade-up"><MessageContent>{ev.text}</MessageContent></Message>
            );
            if (ev.kind === "think") {
              const live = isLast && phase === "running";
              return (
                <div key={i} className="fade-up">
                  <Reasoning isStreaming={live} duration={live ? undefined : Number(ev.dur.replace(/\D/g, "")) || undefined}>
                    <ReasoningTrigger />
                    <ReasoningContent>{ev.text}</ReasoningContent>
                  </Reasoning>
                </div>
              );
            }
            if (ev.kind === "plan") {
              const done = ev.steps.filter((st) => stepState(st.tool) === "done").length;
              return (
                <div key={i} className="fade-up">
                  <Plan isStreaming={phase === "running" && done < ev.steps.length}>
                    <PlanHeader>
                      <PlanTitle>Plan d'attaque</PlanTitle>
                      <PlanAction>
                        <span className="font-mono text-[12px] text-fg-faint">{done}/{ev.steps.length}</span>
                        <span className="w-24"><Progress value={done} max={ev.steps.length} label="Avancement du plan" /></span>
                        <PlanTrigger />
                      </PlanAction>
                    </PlanHeader>
                    <PlanContent>
                      <ol className="plan-list">
                        {ev.steps.map((st) => {
                          const state = stepState(st.tool);
                          return (
                            <li key={st.tool} className={cn("pstep", state)}>
                              <span className="pstep-ic" aria-hidden="true">
                                {state === "done" ? <Check size={11} strokeWidth={3} className="t-check" /> : state === "run" ? <Loader2 size={11} className="spin" /> : state === "skip" ? <Minus size={11} /> : <CircleDashed size={11} />}
                              </span>
                              <TaskItem className={cn(state === "done" && "text-fg-muted")}>{state === "run" ? <Shimmer>{st.label}</Shimmer> : st.label}</TaskItem>
                              <TaskItemFile>{st.tool}</TaskItemFile>
                              <span className="sr-only">{state === "done" ? " (fait)" : state === "run" ? " (en cours)" : state === "skip" ? " (ignoré)" : " (à faire)"}</span>
                            </li>
                          );
                        })}
                      </ol>
                    </PlanContent>
                  </Plan>
                </div>
              );
            }
            if (ev.kind === "say") return (
              <Message key={i} from="assistant" className="fade-up">
                <span className="ev-av" aria-label="Crenel"><Mark size={22} /></span>
                <MessageContent>
                  <p>{ev.text}{stream?.idx === i && <span className="cursor cursor-blink" aria-hidden="true" />}</p>
                  {ev.sources && (
                    <Sources>
                      <SourcesTrigger count={ev.sources.length} />
                      <SourcesContent>{ev.sources.map((src) => <Source key={src.label} href={src.href} title={src.label} kind={src.kind} />)}</SourcesContent>
                    </Sources>
                  )}
                  {i === finalSay && (
                    <>
                      <MessageActions>
                        <MessageAction tooltip="Copier le bilan" onClick={async () => { try { await navigator.clipboard.writeText(ev.text); } catch { /* ignore */ } toast({ type: "success", title: "Bilan copié" }); }}><Copy className="size-3.5" /></MessageAction>
                        <MessageAction tooltip="Relancer le scan" onClick={() => send("/scan")}><RotateCcw className="size-3.5" /></MessageAction>
                      </MessageActions>
                      <Suggestions aria-label="Suites possibles">
                        {["/fix Préparer les correctifs", "/test Fusionner le test d'isolation", "/explain La clé Stripe"].map((sg) => (
                          <Suggestion key={sg} suggestion={sg} onClick={(v) => send(v)} />
                        ))}
                      </Suggestions>
                      {feedback && (
                        <FeedbackBar className="w-fit" title="Ce bilan vous a aidé ?" icon={<Mark size={16} />}
                          onHelpful={() => { setFeedback(false); toast({ type: "success", title: "Merci, c'est noté" }); }}
                          onNotHelpful={() => { setFeedback(false); toast({ type: "info", title: "Merci, on va l'améliorer" }); }}
                          onClose={() => setFeedback(false)} />
                      )}
                    </>
                  )}
                </MessageContent>
              </Message>
            );
            if (ev.kind === "note") return (
              <div key={i} className={cn("ev-note fade-up", ev.tone)}><span className="elbow" aria-hidden="true" />{ev.text}</div>
            );
            if (ev.kind === "tool") {
              const running = isLast && phase === "running";
              const proven = ev.findings?.some((f) => f.state === "proven");
              return (
                <div key={i} className="fade-up">
                  <Tool>
                    <ToolHeader title={ev.tool} args={ev.args} duration={ev.dur} state={running ? "input-available" : proven ? "output-proven" : "output-available"} />
                    <ToolContent>
                      <ToolInput input={ev.input} />
                      <ToolOutput output={running ? "…" : ev.lines.join("\n")} />
                    </ToolContent>
                    {running ? (
                      <div className="tool-run"><Loader variant="bars" label="Outil en cours" /><Skeleton lines={2} label="Résultats en cours" /></div>
                    ) : (
                      <>
                        {ev.findings && ev.findings.length > 0 && (
                          <div className="tool-f">
                            {ev.findings.map((f, j) => (
                              <div key={j} className={cn("ev-find", `is-${f.state}`)}>
                                <SeverityChip sev={f.sev} />
                                <span className="ev-find-t">{f.text}</span>
                                <StateBadge state={f.state} />
                                {f.id && <Link to={`/app/findings/${f.id}`} className="linkish ev-find-l">voir</Link>}
                              </div>
                            ))}
                          </div>
                        )}
                        {ev.code && <div className="tool-code"><CodeBlock filename={ev.code.file} code={ev.code.body} language="ts" /></div>}
                      </>
                    )}
                  </Tool>
                </div>
              );
            }
            // permission: AI Elements Confirmation, with a motion-primitives BorderTrail while it waits
            const d = decisions[i];
            return (
              <div key={i} className="fade-up">
                <Confirmation state={d ? "approval-responded" : "approval-requested"} approved={d ? d !== "deny" : undefined} aria-labelledby={`perm-${i}`}>
                  {!d && <BorderTrail size={90} className="bg-brand opacity-70" />}
                  <ConfirmationTitle id={`perm-${i}`}>
                    <span className={cn("ichip sm", !d && "brand")} aria-hidden="true"><ShieldQuestion size={14} /></span>
                    <span><b className="mono">{ev.tool}</b> veut envoyer {ev.requests.length} requêtes à <b className="mono">{ev.host}</b></span>
                  </ConfirmationTitle>
                  <ConfirmationRequest>
                    <pre className="perm-req">{ev.requests.join("\n")}</pre>
                    <p className="perm-q">Le run est en pause. Lecture seule, avec le jeton du compte A.</p>
                  </ConfirmationRequest>
                  <ConfirmationAccepted><p className="perm-done"><Check size={13} className="t-check" aria-hidden="true" /> {d === "always" ? `Toujours autorisé pour ${ev.host}` : `Autorisé une fois, ${ev.requests.length} requêtes envoyées`}</p></ConfirmationAccepted>
                  <ConfirmationRejected><p className="perm-done deny"><X size={13} aria-hidden="true" /> Refusé, rien n'a été envoyé</p></ConfirmationRejected>
                  <ConfirmationActions>
                    <ConfirmationAction ref={permRef} variant="primary" onClick={() => decide("once")}><span className="kn">1</span>Autoriser une fois</ConfirmationAction>
                    <ConfirmationAction onClick={() => decide("always")}><span className="kn">2</span>Toujours pour cet hôte</ConfirmationAction>
                    <ConfirmationAction onClick={() => decide("deny")}><X size={13} aria-hidden="true" />Refuser <span className="kn">Échap</span></ConfirmationAction>
                  </ConfirmationActions>
                </Confirmation>
              </div>
            );
          })}
          {phase === "running" && (
            <ThinkingBar className="fade-up" icon={<Mark size={26} mood={mood} />}
              text={justProved ? "Crenel a trouvé une faille" : events[lastIdx]?.kind === "tool" ? "Crenel fouille" : "Crenel réfléchit"}
              onStop={interrupt} stopLabel="Interrompre" />
          )}
          {events.some((e) => e.kind === "think") && (
            <Steps defaultOpen={false} className="trace">
              <StepsTrigger leftIcon={<CircleDashed size={14} />}>Journal du run</StepsTrigger>
              <StepsContent>
                {events.filter((e) => e.kind === "tool").map((e, k) => e.kind === "tool" && <StepsItem key={k}><span className="font-mono text-fg-muted">{e.tool}</span> · {e.dur} · {e.lines[0]}</StepsItem>)}
                <StepsItem>{phaseLabel}</StepsItem>
              </StepsContent>
            </Steps>
          )}
        </ConversationContent>
        <ConversationScrollButton />
      </Conversation>

      <div className="dock">
        {live.goal && (
          <div className="goalline" aria-live="polite" aria-label="Progression de l'objectif">
            <span className="gl-t"><Goal size={13} aria-hidden="true" />{live.goal.label}</span>
            <span className={cn(live.goal.status === "met" && "gl-ok")}>{GOAL_STATUS[live.goal.status]}</span>
            {live.goal.detail && <span className="hide-sm">{live.goal.detail}</span>}
            <span>itération {live.goal.iteration}/{live.goal.budget.maxIterations}</span>
            {live.goal.remaining && <span className="mono">{Math.max(0, live.goal.remaining.probes)} sondes, {Math.max(0, Math.round(live.goal.remaining.ms / 60000))} min restantes</span>}
          </div>
        )}
        <Composer
          variant="dock" value={input} onChange={setInput} onSubmit={send} busy={busy} onStop={interrupt}
          placeholder={phase === "waiting" ? "Répondez à la demande, ou écrivez pour la refuser" : "Demandez une suite, ou tapez /"}
          extra={
            <Context usedTokens={tokens} maxTokens={contextWindowOf(ws.model)} usage={{ input: Math.round(tokens * 0.72), output: Math.round(tokens * 0.2), reasoning: Math.round(tokens * 0.08) }}>
              <ContextTrigger />
              <ContextContent />
            </Context>
          }
        />
        <div className="statusline">
          <span className="sl-l">
            <span className={cn("sl-dot", busy && "on")} aria-hidden="true" />
            <TextMorph className="sl-phase">{phaseLabel}</TextMorph>
            {allowed.length > 0 && <span className="mono hide-sm">{allowed.join(", ")} autorisé</span>}
          </span>
          <span className="sl-r hide-sm"><kbd>/</kbd> commandes <kbd>Échap</kbd> interrompre</span>
        </div>
      </div>
    </div>
  );
}
