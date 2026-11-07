import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Check, ChevronRight, Github, GitBranch, MessageSquare, Plus, ShieldAlert, ShieldCheck, CircleDashed, Star } from "lucide-react";
import { Composer } from "../components/Composer.tsx";
import { KpiTile, TaskList } from "../components/ui.tsx";
import { daily, findings, guardedCount, onboarding, tasks } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import { REPO_URL } from "../lib/links.ts";

const SUGGESTIONS = [
  "Prouve que le compte A ne lit pas les données du compte B",
  "Cherche des clés serveur dans le bundle",
  "Génère les tests manquants pour la CI",
];

const ONB_ICON = { target: Plus, github: Github, ci: GitBranch, slack: MessageSquare } as const;
const sum = (a: number[]) => a.reduce((n, x) => n + x, 0);
const last30 = (a: number[]) => a.slice(-30);

export function Overview() {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [tab, setTab] = useState<"active" | "archived">("active");
  useEffect(() => { document.title = "Accueil · Crenel"; }, []);

  const list = tasks.filter((t) => (tab === "archived" ? t.archived : !t.archived));
  const proven = findings.filter((f) => f.state === "proven").length;
  const leads = findings.filter((f) => f.state === "lead").length;

  function go(prompt: string) { navigate("/app/agent", { state: { prompt } }); }

  return (
    <div className="home">
      <section className="launch" aria-labelledby="launch-title">
        <h1 id="launch-title">Que doit attaquer Crenel&nbsp;?</h1>
        <Composer value={q} onChange={setQ} onSubmit={go} placeholder="Décrivez une attaque, ou tapez /" autoFocus />
        <div className="sugg" aria-label="Suggestions">
          {SUGGESTIONS.map((s) => (
            <button type="button" key={s} className="sugg-b" onClick={() => go(s)}>{s}</button>
          ))}
        </div>
      </section>

      <ul className="onb-cards" aria-label="Mise en route">
        {onboarding.map((o) => {
          const I = ONB_ICON[o.id as keyof typeof ONB_ICON];
          return (
            <li key={o.id} className={cn("onb-card", o.done && "done")}>
              <span className="onb-ic" aria-hidden="true"><I size={16} /></span>
              {o.done && <span className="onb-done" aria-hidden="true"><Check size={11} strokeWidth={3} /></span>}
              <Link to={o.to} className="onb-t stretched">{o.title}<span className="sr-only">{o.done ? ", fait" : ", à faire"}</span></Link>
              <span className="onb-d">{o.desc}</span>
            </li>
          );
        })}
      </ul>

      <section className="home-tasks" aria-label="Tâches">
        <div className="tabsrow">
          <div role="tablist" aria-label="Tâches" className="tabs">
            <button type="button" role="tab" aria-selected={tab === "active"} className={cn("tab", tab === "active" && "on")} onClick={() => setTab("active")}>Tâches</button>
            <button type="button" role="tab" aria-selected={tab === "archived"} className={cn("tab", tab === "archived" && "on")} onClick={() => setTab("archived")}>Archivées</button>
          </div>
          <Link to="/app/scans" className="linkish">Tout voir <ChevronRight size={14} /></Link>
        </div>
        <div role="tabpanel"><TaskList items={list.slice(0, 5)} /></div>
      </section>

      <section className="home-posture" aria-labelledby="posture-t">
        <div className="tabsrow plain"><h2 id="posture-t" className="sec-t">Posture</h2><span className="faint small">30 derniers jours</span></div>
        <div className="kpis three">
          <KpiTile label="Prouvés" icon={<ShieldAlert size={14} />} value={proven} delta={1} bad="up" comparison="vs 30 j" data={last30(daily.proven)} tone="danger" to="/app/findings" />
          <KpiTile label="Gardés en CI" icon={<ShieldCheck size={14} />} value={guardedCount} delta={2} comparison="vs 30 j" data={last30(daily.guarded)} tone="brand" to="/app/tests" />
          <KpiTile label="Pistes" icon={<CircleDashed size={14} />} value={leads} delta={sum(last30(daily.leads)) > 120 ? 3 : -2} comparison="vs 30 j" data={last30(daily.leads)} to="/app/findings" />
        </div>
      </section>

      <a className="giftband" href={REPO_URL} target="_blank" rel="noopener noreferrer">
        <Star size={15} aria-hidden="true" />
        <span><b>Crenel est open source.</b> <span className="faint">Une étoile sur GitHub aide d'autres fondateurs à le trouver.</span></span>
        <span className="sp" /><span className="giftband-cta">Mettre une étoile</span>
      </a>
    </div>
  );
}
