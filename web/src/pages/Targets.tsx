import { Link } from "react-router-dom";
import { FolderClosed, Plus, Globe } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button } from "../components/ui.tsx";
import { targets } from "../data/mock.ts";

export function Targets() {
  return (
    <>
      <Topbar crumb="Espace de travail" title="Cibles" actions={<Button to="/app/onboarding"><Plus size={15} /> Ajouter une cible</Button>} />
      <div className="content">
        <p className="muted" style={{ margin: 0, maxWidth: "62ch" }}>Une cible est un site ou un dépôt que vous possédez. Chaque cible a son propre dossier de scans, findings et tests. Crenel ne teste que des hôtes que vous avez déclarés.</p>
        <section className="folders">
          {targets.map((t) => (
            <a key={t.id} className="folder" href="#/app/overview">
              <div className="fh">
                <span className="fi"><FolderClosed size={18} /></span>
                <div><div className="nm">{t.name}</div><div className="url"><Globe size={10} style={{ verticalAlign: -1, marginRight: 4 }} />{t.url}</div></div>
              </div>
              <div className="stat">
                <span><b>{t.findings}</b> findings</span>
                <span><b style={{ color: t.proven ? "var(--crit-ink)" : "var(--low-ink)" }}>{t.proven}</b> prouvés</span>
                <span className="faint">{t.env}</span>
              </div>
              <div className="faint mono" style={{ fontSize: 11 }}>dernier scan · {t.lastScan}</div>
            </a>
          ))}
          <Link to="/app/onboarding" className="folder" style={{ alignItems: "center", justifyContent: "center", color: "var(--fg-faint)", borderStyle: "dashed" }}>
            <Plus size={22} /><span style={{ fontSize: 13 }}>Ajouter une cible</span>
          </Link>
        </section>
      </div>
    </>
  );
}
