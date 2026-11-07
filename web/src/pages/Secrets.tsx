import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ExternalLink, KeyRound, MoreHorizontal, RotateCcw, TerminalSquare, X } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, SeverityChip } from "../components/ui.tsx";
import { Badge } from "../components/arc/badge/badge.tsx";
import { MetricCard } from "../components/arc/metric-card/metric-card.tsx";
import { DropdownMenu } from "../components/arc/dropdown-menu/dropdown-menu.tsx";
import { SlideConfirm } from "../components/bencho/SlideConfirm.tsx";
import "../components/bencho/SlideConfirm.css";
import { useToast } from "../components/toast.tsx";
import { useData } from "../data/api.ts";
import { cn } from "../lib/cn.ts";

export function Secrets() {
  const navigate = useNavigate();
  const toast = useToast();
  const { secrets } = useData();
  const [confirm, setConfirm] = useState<string | null>(null);
  const [revoked, setRevoked] = useState<string[]>([]);
  const active = secrets.filter((s) => s.valid === "active" && !revoked.includes(s.finding)).length;

  return (
    <>
      <Topbar width="mid" scoped title="Secrets" insight={<><b>{active} secret{active > 1 ? "s" : ""} actif{active > 1 ? "s" : ""}</b> lisible{active > 1 ? "s" : ""} par n'importe qui. Révoquez d'abord, déplacez ensuite.</>} />
      <div className="content mid">
        <div className="metrics">
          <MetricCard label="Exposés" value={secrets.length - revoked.length} context="dans le bundle et le dépôt" change={revoked.length ? `−${revoked.length}` : undefined} />
          <MetricCard label="Actifs" value={active} context="validés auprès du fournisseur" />
          <MetricCard label="Révoqués" value={revoked.length} context="depuis ce scan" change={revoked.length ? `+${revoked.length}` : undefined} />
        </div>
        <ul className="secrets">
          {secrets.map((s) => {
            const done = revoked.includes(s.finding);
            const asking = confirm === s.finding;
            return (
              <li key={s.finding} className={cn("secret", done && "revoked")}>
                <span className={cn("ichip", s.sev === "crit" && !done && "danger")} aria-hidden="true"><KeyRound size={16} /></span>
                <div className="secret-main">
                  <div className="secret-top"><SeverityChip sev={s.sev} /><Link to={`/app/findings/${s.finding}`} className="secret-t">{s.kind}</Link></div>
                  <div className="mono secret-v">{s.masked}</div>
                  <div className="secret-l"><span className="mono faint">{s.loc}</span>
                    {done ? <Badge size="sm" tone="success">révocation demandée</Badge>
                      : <Badge size="sm" tone={s.valid === "active" ? "danger" : "neutral"}>{s.valid === "active" ? "active" : s.valid}</Badge>}
                  </div>
                </div>
                <div className="secret-act">
                  {done ? null : asking ? (
                    <div className="confirm-slide bencho">
                      <SlideConfirm width={250} label="Glisser pour révoquer" doneLabel="Révoquée" onConfirm={() => {
                        setTimeout(() => { setRevoked((r) => [...r, s.finding]); setConfirm(null); }, 700);
                        toast({ type: "success", title: `${s.kind}: révocation demandée`, description: "Pensez à la remplacer côté serveur." });
                      }} />
                      <button type="button" className="iconbtn sm" aria-label="Annuler" onClick={() => setConfirm(null)}><X size={15} /></button>
                    </div>
                  ) : (
                    <Button size="sm" variant="ghost" onClick={() => setConfirm(s.finding)}><RotateCcw size={13} /> Révoquer</Button>
                  )}
                  <DropdownMenu iconOnly label={`Actions pour ${s.kind}`} icon={<MoreHorizontal size={16} />} items={[
                    { label: "Voir la preuve", icon: <ExternalLink size={14} />, onSelect: () => navigate(`/app/findings/${s.finding}`) },
                    { label: "Demander à l'agent", icon: <TerminalSquare size={14} />, onSelect: () => navigate("/app/agent", { state: { prompt: `/explain ${s.kind} (${s.loc})` } }) },
                  ]} />
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </>
  );
}
