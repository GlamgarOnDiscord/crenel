import { Link, useNavigate } from "react-router-dom";
import { FolderGit2, Globe, Plus } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button } from "../components/ui.tsx";
import { targets } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import { useWorkspace } from "../lib/workspace.tsx";

export function Targets() {
  const ws = useWorkspace();
  const navigate = useNavigate();
  return (
    <>
      <Topbar crumb="Espace" title="Cibles" insight={<>Crenel ne parle qu'aux hôtes déclarés ici.</>} actions={<Button to="/app/onboarding"><Plus size={15} /> Ajouter une cible</Button>} />
      <div className="content">
        <section className="folders">
          {targets.map((t) => {
            const Icon = t.kind === "repo" ? FolderGit2 : Globe;
            const active = ws.target.id === t.id;
            return (
              <div key={t.id} className={cn("folder", active && "active")}>
                <div className="fh">
                  <span className={cn("ichip", active && "brand")} aria-hidden="true"><Icon size={16} /></span>
                  <div>
                    <button type="button" className="nm stretched" onClick={() => { ws.setTargetId(t.id); navigate("/app/overview"); }}>
                      {t.name}<span className="sr-only">, ouvrir cette cible</span>
                    </button>
                    <div className="url mono">{t.url}</div>
                  </div>
                  {active && <span className="pill amber">active</span>}
                </div>
                <div className="stat">
                  <span><b>{t.findings}</b> findings</span>
                  <span><b className={t.proven ? "crit-ink" : ""}>{t.proven}</b> prouvé{t.proven > 1 ? "s" : ""}</span>
                  <span className="faint">{t.env}</span>
                </div>
                <div className="faint mono small">dernier scan · {t.lastScan}</div>
              </div>
            );
          })}
          <Link to="/app/onboarding" className="folder add">
            <Plus size={22} aria-hidden="true" /><span>Ajouter une cible</span>
          </Link>
        </section>
      </div>
    </>
  );
}
