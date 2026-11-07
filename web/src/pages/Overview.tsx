import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, ChevronRight } from "lucide-react";
import { Mark } from "../brand/Logo.tsx";
import { Composer } from "../components/Composer.tsx";
import { CopyButton, SeverityChip, TaskList } from "../components/ui.tsx";
import { findings, guardedCount, tasks } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import { SEV_RANK } from "../lib/types.ts";
import { useWorkspace } from "../lib/workspace.tsx";

const SUGGESTIONS = [
  "Prouve que le compte A ne lit pas les données du compte B",
  "Cherche des clés serveur dans le bundle client",
  "Explique la clé Stripe prouvée et prépare le correctif",
  "Génère les tests manquants pour la CI",
];

const toFix = findings
  .filter((f) => f.state === "proven")
  .sort((a, b) => SEV_RANK[a.sev] - SEV_RANK[b.sev]);

export function Overview() {
  const navigate = useNavigate();
  const { target } = useWorkspace();
  const [q, setQ] = useState("");
  const [tab, setTab] = useState<"active" | "archived">("active");
  useEffect(() => { document.title = "Accueil · Crenel"; }, []);

  const list = tasks.filter((t) => (tab === "archived" ? t.archived : !t.archived));
  const detected = findings.length;
  const proven = toFix.length;

  function go(prompt: string) { navigate("/app/agent", { state: { prompt } }); }

  return (
    <div className="home">
      <section className="launch" aria-labelledby="launch-title">
        <div className="launch-mark" aria-hidden="true"><Mark size={68} /></div>
        <h1 id="launch-title">Que doit attaquer Crenel&nbsp;?</h1>
        <p className="launch-sub">Sur <b>{target.name}</b> <span className="mono">{target.url}</span>. Chaque faille est prouvée par une requête rejouable, puis gardée en CI.</p>
        <Composer value={q} onChange={setQ} onSubmit={go} placeholder="Décrivez une attaque à tenter, ou tapez / pour les commandes" autoFocus />
        <div className="sugg" aria-label="Suggestions">
          {SUGGESTIONS.map((s) => (
            <button type="button" key={s} className="sugg-b" onClick={() => go(s)}>{s}</button>
          ))}
        </div>
      </section>

      <section className="home-tasks" aria-label="Tâches">
        <div className="tabsrow">
          <div role="tablist" aria-label="Tâches" className="tabs">
            <button type="button" role="tab" aria-selected={tab === "active"} className={cn("tab", tab === "active" && "on")} onClick={() => setTab("active")}>Tâches</button>
            <button type="button" role="tab" aria-selected={tab === "archived"} className={cn("tab", tab === "archived" && "on")} onClick={() => setTab("archived")}>Archivées</button>
          </div>
          <Link to="/app/scans" className="linkish">Tout l'historique <ChevronRight size={14} /></Link>
        </div>
        <div role="tabpanel"><TaskList items={list.slice(0, 6)} /></div>
      </section>

      <section className="posture" aria-labelledby="posture-title">
        <div className="posture-hd">
          <h2 id="posture-title">Posture</h2>
          <span className="faint">{target.name}</span>
        </div>
        <ol className="pipeline" aria-label="Du détecté au gardé">
          <li><Link to="/app/findings" className="pl-n">{detected}</Link><span className="pl-l">détectés</span></li>
          <li className="pl-arrow" aria-hidden="true"><ArrowRight size={14} /></li>
          <li className="proven"><Link to="/app/findings" state={{ filter: "proven" }} className="pl-n">{proven}</Link><span className="pl-l">prouvés</span></li>
          <li className="pl-arrow" aria-hidden="true"><ArrowRight size={14} /></li>
          <li className="guarded"><Link to="/app/tests" className="pl-n">{guardedCount}</Link><span className="pl-l">gardés en CI</span></li>
        </ol>
        <h3 className="fixnow-hd">À corriger maintenant</h3>
        <ul className="fixnow">
          {toFix.map((f) => (
            <li key={f.id}>
              <div className="fixnow-top">
                <SeverityChip sev={f.sev} />
                <Link to={`/app/findings/${f.id}`} className="fixnow-t">{f.title}</Link>
              </div>
              {f.proof && (
                <div className="fixnow-cmd"><code>{f.proof.replay}</code><CopyButton text={f.proof.replay} /></div>
              )}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
