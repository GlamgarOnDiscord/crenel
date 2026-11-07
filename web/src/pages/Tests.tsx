import { Link } from "react-router-dom";
import { FileCode2, GitPullRequest } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, GuardBadge } from "../components/ui.tsx";
import { guardedCount, tests } from "../data/mock.ts";

export function Tests() {
  const drafts = tests.length - guardedCount;
  return (
    <>
      <Topbar scoped title="Tests gardés" actions={<Button size="sm"><GitPullRequest size={14} /> Ouvrir la PR des brouillons</Button>} />
      <div className="content mid">
        <div className="guardhero">
          <div className="gh-n"><span className="gh-big">{guardedCount}</span><span>failles gardées en CI</span></div>
          <div className="gh-n quiet"><span className="gh-big">{drafts}</span><span>brouillon à fusionner</span></div>
          <p>Chaque faille prouvée devient un test de régression. Une fois en CI, elle ne peut plus revenir sans casser le build.</p>
        </div>
        <ul className="tlist">
          {tests.map((t) => (
            <li key={t.name} className="tcase">
              <span className={t.status === "ci" ? "sq amber" : "sq slate"} aria-hidden="true"><FileCode2 size={16} /></span>
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
