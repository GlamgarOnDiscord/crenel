import { useState } from "react";
import { Link } from "react-router-dom";
import { KeyRound, RotateCcw } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, SeverityChip } from "../components/ui.tsx";
import { secrets } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";

export function Secrets() {
  const [confirm, setConfirm] = useState<string | null>(null);
  const [revoked, setRevoked] = useState<string[]>([]);
  const [announce, setAnnounce] = useState("");
  return (
    <>
      <Topbar scoped title="Secrets" insight={<><b>2 secrets actifs</b> sont lisibles par n'importe qui. Révoquez d'abord, déplacez ensuite.</>} />
      <div className="content mid">
        <ul className="secrets">
          {secrets.map((s) => {
            const done = revoked.includes(s.finding);
            const asking = confirm === s.finding;
            return (
              <li key={s.finding} className={cn("secret", done && "revoked")}>
                <span className={cn("ichip", s.sev === "crit" && "danger")} aria-hidden="true"><KeyRound size={16} /></span>
                <div className="secret-main">
                  <div className="secret-top"><SeverityChip sev={s.sev} /><Link to={`/app/findings/${s.finding}`} className="secret-t">{s.kind}</Link></div>
                  <div className="mono secret-v">{s.masked}</div>
                  <div className="mono faint secret-l">{s.loc} · validité <span className={cn(s.valid === "active" && !done && "crit-ink")}>{done ? "révocation demandée" : s.valid}</span></div>
                </div>
                <div className="secret-act">
                  {done ? (
                    <span className="state fixed">révocation demandée</span>
                  ) : asking ? (
                    <div className="confirm" role="group" aria-label={`Confirmer la révocation de ${s.kind}`}>
                      <Button size="sm" variant="danger" autoFocus onClick={() => { setRevoked((r) => [...r, s.finding]); setConfirm(null); setAnnounce(`${s.kind}: révocation demandée`); }}>Confirmer</Button>
                      <Button size="sm" variant="quiet" onClick={() => setConfirm(null)}>Annuler</Button>
                    </div>
                  ) : (
                    <Button size="sm" variant="ghost" onClick={() => setConfirm(s.finding)}><RotateCcw size={13} /> Révoquer</Button>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
        <span className="sr-only" aria-live="polite">{announce}</span>
      </div>
    </>
  );
}
