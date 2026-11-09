import { Link, useNavigate } from "react-router-dom";
import { ExternalLink, KeyRound, MoreHorizontal, RotateCcw, TerminalSquare } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, SeverityChip } from "../components/ui.tsx";
import { Badge } from "../components/arc/badge/badge.tsx";
import { DropdownMenu } from "../components/arc/dropdown-menu/dropdown-menu.tsx";
import { Tooltip } from "../components/arc/tooltip/tooltip.tsx";
import { useData } from "../data/api.ts";
import { revokeHelp } from "../lib/console.ts";
import "../styles/console-a.css";

// Crenel cannot revoke a key: only its provider can. Each secret links to the
// provider's key page when the kind is recognisable, then /secrets re-checks.
import { cn } from "../lib/cn.ts";

export function Secrets() {
  const navigate = useNavigate();
  const { secrets, live } = useData();
  const active = secrets.filter((s) => s.valid === "active").length;
  const n = secrets.length;
  const pl = (k: number) => (k > 1 ? "s" : "");
  const insight = live
    ? (n ? <><b>{n} secret{pl(n)} exposé{pl(n)}</b>, validité non vérifiée: traitez-les comme actifs. Révoquez d'abord, déplacez ensuite.</> : <>Aucun secret exposé trouvé au dernier scan.</>)
    : <><b>{active} secret{pl(active)} actif{pl(active)}</b> lisible{pl(active)} par n'importe qui. Révoquez d'abord, déplacez ensuite.</>;
  const recheck = () => navigate("/app/agent", { state: { prompt: "/secrets" } });

  return (
    <>
      <Topbar width="mid" scoped title="Secrets" insight={insight}
        actions={<Button size="sm" variant="ghost" onClick={recheck}><RotateCcw size={13} /> Revérifier</Button>} />
      <div className="content mid">
        <ul className="secrets">
          {secrets.map((s) => {
            const help = revokeHelp(s.kind, s.masked);
            return (
              <li key={s.finding} className="secret">
                <span className={cn("ichip", s.sev === "crit" && "danger")} aria-hidden="true"><KeyRound size={16} /></span>
                <div className="secret-main">
                  <div className="secret-top"><SeverityChip sev={s.sev} /><Link to={`/app/findings/${s.finding}`} className="secret-t">{s.kind}</Link></div>
                  <div className="mono secret-v">{s.masked}</div>
                  <div className="secret-l"><span className="mono faint">{s.loc}</span>
                    <Badge size="sm" tone={s.valid === "active" ? "danger" : "neutral"}>{s.valid === "active" ? "active" : live ? "validité inconnue" : s.valid}</Badge>
                  </div>
                  {!help && <div className="secret-help">Révoquez la clé chez le fournisseur, retirez-la du code, puis relancez /secrets.</div>}
                </div>
                <div className="secret-act">
                  {help && (
                    <Tooltip content={`Gestion des clés ${help.provider}: révoquez, puis remplacez côté serveur`}>
                      <span><Button size="sm" variant="ghost" href={help.url}><ExternalLink size={13} /> Révoquer chez {help.provider}</Button></span>
                    </Tooltip>
                  )}
                  <DropdownMenu iconOnly label={`Actions pour ${s.kind}`} icon={<MoreHorizontal size={16} />} items={[
                    { label: "Voir la preuve", icon: <ExternalLink size={14} />, onSelect: () => navigate(`/app/findings/${s.finding}`) },
                    { label: "Demander à l'agent", icon: <TerminalSquare size={14} />, onSelect: () => navigate("/app/agent", { state: { prompt: `/explain ${s.kind} (${s.loc})` } }) },
                    { label: "Revérifier (/secrets)", icon: <RotateCcw size={14} />, onSelect: recheck },
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
