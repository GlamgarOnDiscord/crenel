import { Link } from "react-router-dom";
import { FileCode2, GitPullRequest, ShieldCheck } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, GuardBadge, KpiTile } from "../components/ui.tsx";
import { daily, guardedCount, tests } from "../data/mock.ts";

export function Tests() {
  const drafts = tests.length - guardedCount;
  return (
    <>
      <Topbar scoped title="Tests gardés" insight={<><b>{guardedCount} failles</b> ne peuvent plus revenir sans casser le build.</>} actions={<Button size="sm"><GitPullRequest size={14} /> Ouvrir la PR des brouillons</Button>} />
      <div className="content mid">
        <div className="kpis three">
          <KpiTile label="Gardés en CI" icon={<ShieldCheck size={14} />} value={guardedCount} delta={2} comparison="vs 30 j" data={daily.guarded.slice(-30)} tone="brand" />
          <KpiTile label="Brouillons" icon={<FileCode2 size={14} />} value={drafts} comparison="à fusionner" />
          <KpiTile label="Régressions bloquées" icon={<GitPullRequest size={14} />} value={3} delta={1} comparison="vs 30 j" data={daily.fixed.slice(-30)} />
        </div>
        <ul className="tlist">
          {tests.map((t) => (
            <li key={t.name} className="tcase">
              <span className={t.status === "ci" ? "ichip brand" : "ichip"} aria-hidden="true"><FileCode2 size={15} /></span>
              <div className="tcase-main">
                <Link to={`/app/findings/${t.finding}`} className="tcase-t stretched">{t.name}</Link>
                <div className="mono faint tcase-m"><span>{t.check}</span><span>{t.when}</span></div>
              </div>
              {t.status === "ci" ? <GuardBadge label="en CI" /> : <span className="draft">brouillon</span>}
            </li>
          ))}
        </ul>
      </div>
    </>
  );
}
