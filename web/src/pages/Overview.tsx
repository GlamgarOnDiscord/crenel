import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Check, ChevronRight, CircleDashed, Github, GitBranch, MessageSquare, Plus, ShieldAlert, ShieldCheck, Star } from "lucide-react";
import { Composer } from "../components/Composer.tsx";
import { Card, KpiTile, TaskList } from "../components/ui.tsx";
import { Suggestion, Suggestions } from "../components/ai/suggestion.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/arc/tabs/tabs.tsx";
import { FunnelChart } from "../components/bklit/funnel-chart.tsx";
import { StackedBars } from "../components/bencho/StackedBars.tsx";
import "../components/bencho/StackedBars.css";
import { daily, findings, guardedCount, onboarding, tasks } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import { REPO_URL } from "../lib/links.ts";

const SUGGESTIONS = [
  "Prouve que le compte A ne lit pas les données du compte B",
  "Cherche des clés serveur dans le bundle",
  "Génère les tests manquants pour la CI",
];

const ONB_ICON = { target: Plus, github: Github, ci: GitBranch, slack: MessageSquare } as const;
const last30 = (a: number[]) => a.slice(-30);

export function Overview() {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  useEffect(() => { document.title = "Accueil · Crenel"; }, []);

  const proven = findings.filter((f) => f.state === "proven").length;
  const leads = findings.filter((f) => f.state === "lead").length;
  const provenEver = findings.filter((f) => f.state === "proven" || (f.state === "fixed" && f.proof)).length;
  const provenGuarded = findings.filter((f) => (f.state === "proven" || (f.state === "fixed" && f.proof)) && f.guarded).length;

  function go(prompt: string) { navigate("/app/agent", { state: { prompt } }); }

  return (
    <div className="home">
      <section className="launch t-reveal" aria-labelledby="launch-title">
        <h1 id="launch-title">Que doit attaquer Crenel&nbsp;?</h1>
        <Composer value={q} onChange={setQ} onSubmit={go} placeholder="Décrivez une attaque, ou tapez /" autoFocus />
        <Suggestions className="sugg" aria-label="Suggestions">
          {SUGGESTIONS.map((s) => <Suggestion key={s} suggestion={s} onClick={go} />)}
        </Suggestions>
      </section>

      <ul className="onb-cards" aria-label="Mise en route">
        {onboarding.map((o) => {
          const I = ONB_ICON[o.id as keyof typeof ONB_ICON];
          return (
            <li key={o.id} className={cn("onb-card", o.done && "done")}>
              <span className="onb-ic" aria-hidden="true"><I size={16} /></span>
              {o.done && <span className="onb-done t-check" aria-hidden="true"><Check size={11} strokeWidth={3} /></span>}
              <Link to={o.to} className="onb-t stretched">{o.title}<span className="sr-only">{o.done ? ", fait" : ", à faire"}</span></Link>
              <span className="onb-d">{o.desc}</span>
            </li>
          );
        })}
      </ul>

      <section className="home-tasks" aria-label="Tâches">
        <Tabs defaultValue="active">
          <div className="tabsrow">
            <TabsList aria-label="Tâches">
              <TabsTrigger value="active">Tâches</TabsTrigger>
              <TabsTrigger value="archived">Archivées</TabsTrigger>
            </TabsList>
            <Link to="/app/scans" className="linkish learn">Tout voir <ChevronRight size={14} /></Link>
          </div>
          <TabsContent value="active"><TaskList items={tasks.filter((t) => !t.archived).slice(0, 5)} /></TabsContent>
          <TabsContent value="archived"><TaskList items={tasks.filter((t) => t.archived)} /></TabsContent>
        </Tabs>
      </section>

      <section className="home-posture" aria-labelledby="posture-t">
        <div className="tabsrow plain"><h2 id="posture-t" className="sec-t">Posture</h2><span className="faint small">30 derniers jours</span></div>
        <div className="kpis three">
          <KpiTile label="Prouvés" icon={<ShieldAlert size={14} />} value={proven} delta={1} bad="up" comparison="vs 30 j" data={last30(daily.proven)} tone="danger" to="/app/findings" />
          <KpiTile label="Gardés en CI" icon={<ShieldCheck size={14} />} value={guardedCount} delta={2} comparison="vs 30 j" data={last30(daily.guarded)} tone="brand" to="/app/tests" />
          <KpiTile label="Pistes" icon={<CircleDashed size={14} />} value={leads} delta={3} comparison="vs 30 j" data={last30(daily.leads)} to="/app/findings" />
        </div>
        <div className="posture-row">
          <Card title="Du détecté au gardé" meta="chaque faille doit se rejouer, puis rester en CI">
            <div className="funnel-wrap">
              <FunnelChart data={[
                { label: "Détectés", value: findings.length },
                { label: "Prouvés", value: provenEver, color: "var(--danger)" },
                { label: "Prouvés et gardés", value: provenGuarded, color: "var(--brand)" },
              ]} layers={3} gap={6} formatValue={(v) => new Intl.NumberFormat("fr-FR").format(v)} formatPercentage={(p) => `${Math.round(p)} %`} />
            </div>
          </Card>
          <div className="bencho stb-wrap"><StackedBars bars={20} gap={4} /></div>
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
