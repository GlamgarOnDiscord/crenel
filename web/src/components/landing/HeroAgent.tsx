/* The hero's product shot: the Crenel console playing one agent session on a
   loop. A prompt is typed into the composer and sent; the agent (the animated
   jackdaw) thinks, reads the live bundle, asks before probing staging, proves
   the authorization flaw with three requests, then writes the regression
   tests. The proof panel fills as the proof lands. It only runs while on
   screen; with reduced motion it shows the finished session, still. */
import { useEffect, useRef, useState } from "react";
import { ArrowUp, Check, Eye, FlaskConical, LayoutDashboard, Loader2, Radar, ShieldCheck, Users } from "lucide-react";
import { Mark } from "../../brand/Logo.tsx";
import { Shimmer } from "../ai/shimmer.tsx";
import { cn } from "../../lib/utils";

const PROMPT = "Scanne acme-app et prouve ce que tu trouves";
// Phase durations (ms). 0 is the typing phase, timed by the prompt length.
const PHASES = [0, 1000, 1200, 900, 1500, 600, 1500, 1000, 3400];
const LAST = PHASES.length - 1;

function useOnScreen<T extends Element>() {
  const ref = useRef<T | null>(null);
  const [on, setOn] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof IntersectionObserver === "undefined") { setOn(true); return; }
    const io = new IntersectionObserver(([e]) => setOn(!!e?.isIntersecting), { threshold: 0.15 });
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return [ref, on] as const;
}

function useReduced() {
  const [r, setR] = useState(false);
  useEffect(() => {
    const m = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!m) return;
    setR(m.matches);
    const f = () => setR(m.matches);
    m.addEventListener?.("change", f);
    return () => m.removeEventListener?.("change", f);
  }, []);
  return r;
}

export function HeroAgent() {
  const [ref, onScreen] = useOnScreen<HTMLDivElement>();
  const reduced = useReduced();
  const [phase, setPhase] = useState(0);
  const [typed, setTyped] = useState(0);

  useEffect(() => {
    if (reduced) { setPhase(LAST); setTyped(PROMPT.length); return; }
    if (!onScreen) return;
    if (phase === 0) {
      if (typed < PROMPT.length) {
        const t = setTimeout(() => setTyped((n) => n + 1), typed === 0 ? 700 : 38 + Math.random() * 40);
        return () => clearTimeout(t);
      }
      const t = setTimeout(() => setPhase(1), 450);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => {
      if (phase === LAST) { setPhase(0); setTyped(0); } else setPhase(phase + 1);
    }, PHASES[phase]);
    return () => clearTimeout(t);
  }, [phase, typed, onScreen, reduced]);

  const sent = phase >= 1;
  const mood = phase >= 6 && phase < LAST ? "found" : phase >= 1 && phase < LAST ? "working" : "idle";
  const at = (n: number) => phase >= n;

  return (
    <div className="lx-shot" ref={ref} role="img" aria-label="Démo de la console Crenel : l'agent scanne acme-app, demande avant de sonder, prouve une faille d'autorisation et écrit les tests.">
      <div className="lx-shot-glow" aria-hidden="true" />
      <div className="lx-app" aria-hidden="true">
        <aside className="lx-app-side">
          <div className="lx-app-brand"><Mark size={18} /><b>crenel</b></div>
          <div className="lx-app-search mono">Rechercher <kbd>⌘K</kbd></div>
          <span className="lx-app-h">Espace</span>
          <span className="lx-app-nav"><LayoutDashboard size={13} />Vue d'ensemble</span>
          <span className="lx-app-nav on"><Radar size={13} />Agent</span>
          <span className="lx-app-nav"><ShieldCheck size={13} />Failles{at(6) && <em>2</em>}</span>
          <span className="lx-app-nav"><Users size={13} />Autorisation</span>
          <span className="lx-app-nav"><FlaskConical size={13} />Tests{at(8) && <em className="ok">2</em>}</span>
          <span className="lx-app-h">Cibles</span>
          <span className="lx-app-nav"><i className="lx-dot a" />acme-app</span>
          <span className="lx-app-nav"><i className="lx-dot" />acme-staging</span>
        </aside>

        <main className="lx-app-main">
          <div className="lx-app-top">
            <span className="lx-crumb">Cibles / acme-app / <b>Agent</b></span>
            <span className="mode"><Eye size={12} />Demander</span>
          </div>
          <div className="lx-chat">
            {sent && <div className="ha-user ha-in">{PROMPT}</div>}
            {sent && (
              <div className="ha-agent ha-in">
                <span className="ha-avatar"><Mark size={26} mood={mood} /></span>
                <div className="ha-flow">
                  <div className="ha-name">Crenel <span className="ui-badge">AGENT</span>
                    {phase >= 1 && phase < 2 && <Shimmer className="ha-think">réfléchit…</Shimmer>}
                  </div>
                  {at(2) && <Tool done={at(3)} name="scan.secrets" arg="bundle en ligne · 31 chunks" />}
                  {at(3) && <Finding sev="CRIT" text="sk_live_ dans assets/index-4f2a.js" tag="clé serveur" />}
                  {at(4) && <Tool done={at(6)} name="authz.matrix" arg="compte A → objets de B" />}
                  {at(4) && !at(6) && (
                    <div className="ha-perm ha-in">
                      <span>Envoyer 4 GET à <b className="mono">staging.acme.app</b> ?</span>
                      <span className={cn("ui-key primary", at(5) && "pressed")}>Autoriser une fois</span>
                      <span className="ui-key">Toujours</span>
                      <span className="ui-key">Refuser</span>
                    </div>
                  )}
                  {at(6) && <Finding sev="HAUTE" text="GET /api/projects/proj_b_1 → 200, rejoué ×3" tag="prouvé" />}
                  {at(7) && <Tool done={at(8)} name="tests.generate" arg="2 preuves" />}
                  {at(8) && <div className="ha-done ha-in"><Check size={13} /> 2 tests de régression prêts pour la CI</div>}
                </div>
              </div>
            )}
          </div>
          <div className="lx-composer">
            <div className="ui-input">
              <span className={cn("ha-typed", !sent && typed === 0 && "ph")}>
                {sent ? "" : typed === 0 ? "Décrivez une attaque, ou tapez /" : PROMPT.slice(0, typed)}
                {!sent && <i className="ha-caret" />}
              </span>
              <div className="ha-tools">
                <span className="ui-pill"><Eye size={11} />Demander</span>
                <span className="ui-pill">✦ Effort · Moyen</span>
                <span className={cn("ha-send", !sent && typed === PROMPT.length && "ready")}><ArrowUp size={14} /></span>
              </div>
            </div>
          </div>
        </main>

        <aside className="lx-app-proof">
          <span className="lx-app-h">Preuve · authz.matrix</span>
          {at(6) ? (
            <>
              <div className="pf ha-in" style={{ animationDelay: "0ms" }}><b>Propriétaire</b><span>B lit proj_b_1</span><em className="ok">200</em></div>
              <div className="pf hot ha-in" style={{ animationDelay: "160ms" }}><b>Attaquant</b><span>A lit proj_b_1</span><em className="bad">200 ×3</em></div>
              <div className="pf ha-in" style={{ animationDelay: "320ms" }}><b>Contrôle</b><span>sans session</span><em>401</em></div>
              <div className="pf-foot ha-in" style={{ animationDelay: "480ms" }}>Rejouable · <span className="mono">crenel replay f_7c2</span></div>
            </>
          ) : (
            <div className="pf-wait">{at(4) ? <><Loader2 size={13} className="ha-spin" /> en attente de votre accord</> : "Aucune preuve pour l'instant"}</div>
          )}
        </aside>
      </div>
    </div>
  );
}

function Tool({ name, arg, done }: { name: string; arg: string; done: boolean }) {
  return (
    <div className="ha-tool ha-in">
      <span className={cn("ha-st", done && "ok")}>{done ? <Check size={11} /> : <Loader2 size={11} className="ha-spin" />}</span>
      <span className="mono">{done ? name : <Shimmer>{name}</Shimmer>}</span>
      <span className="ha-arg">{arg}</span>
    </div>
  );
}

function Finding({ sev, text, tag }: { sev: string; text: string; tag: string }) {
  return (
    <div className="ha-find ha-in">
      <span className={cn("ha-sev", sev === "CRIT" ? "crit" : "high")}>{sev}</span>
      <span className="mono">{text}</span>
      <span className="ha-tag">{tag}</span>
    </div>
  );
}
