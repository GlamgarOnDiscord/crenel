import { Link, useNavigate } from "react-router-dom";
import { Check, FolderGit2, Globe, MoreHorizontal, Play, Plus, Trash2 } from "lucide-react";
import { Badge } from "../components/arc/badge/badge.tsx";
import { DropdownMenu } from "../components/arc/dropdown-menu/dropdown-menu.tsx";
import { Sparkline } from "../components/arc/sparkline/sparkline.tsx";
import { useToast } from "../components/toast.tsx";
import { daily } from "../data/mock.ts";

import { Topbar } from "../components/Shell.tsx";
import { Button } from "../components/ui.tsx";
import { targets } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import { useWorkspace } from "../lib/workspace.tsx";

// Weekly findings per target, cut from the shared daily series with an offset.
const trend = (id: string) => { const off = id.length * 7; return Array.from({ length: 12 }, (_, w) => daily.detected.slice(off % 30 + w * 5, off % 30 + w * 5 + 7).reduce((a, b) => a + b, 0)); };

export function Targets() {
  const ws = useWorkspace();
  const navigate = useNavigate();
  const toast = useToast();
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
                  {active ? <Badge size="sm" tone="success">active</Badge> : <span className="sp" />}
                  <span className="folder-menu">
                    <DropdownMenu iconOnly label={`Actions pour ${t.name}`} icon={<MoreHorizontal size={16} />} items={[
                      { label: "Rendre active", icon: <Check size={14} />, disabled: active, onSelect: () => { ws.setTargetId(t.id); toast({ type: "success", title: `${t.name} est la cible active` }); } },
                      { label: "Lancer un scan", icon: <Play size={14} />, onSelect: () => { ws.setTargetId(t.id); navigate("/app/agent", { state: { prompt: `Scan complet de ${t.name}` } }); } },
                      { label: "Retirer la cible", icon: <Trash2 size={14} />, destructive: true, separatorBefore: true, onSelect: () => toast({ type: "warning", title: "Retrait à confirmer dans Paramètres" }) },
                    ]} />
                  </span>
                </div>
                <div className="stat">
                  <span><b>{t.findings}</b> findings</span>
                  <span><b className={t.proven ? "crit-ink" : ""}>{t.proven}</b> prouvé{t.proven > 1 ? "s" : ""}</span>
                  <span className="faint">{t.env}</span>
                </div>
                <div className="folder-spark">
                  <Sparkline data={trend(t.id)} label="Findings par semaine" value={String(t.findings)} tone={t.proven ? "danger" : "accent"} width={280} height={44} interactive={false} />
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
