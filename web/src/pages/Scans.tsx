import { Link } from "react-router-dom";
import { Play } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button } from "../components/ui.tsx";

const runs = [
  { when: "il y a 12 min", trigger: "planifié", found: 14, proven: 2, dur: "1m 12s", status: "terminé" },
  { when: "il y a 2 h", trigger: "sur push", found: 13, proven: 3, dur: "1m 04s", status: "terminé" },
  { when: "hier 23:30", trigger: "planifié", found: 15, proven: 3, dur: "1m 20s", status: "terminé" },
  { when: "hier 09:12", trigger: "manuel", found: 16, proven: 4, dur: "1m 31s", status: "terminé" },
];

export function Scans() {
  return (
    <>
      <Topbar crumb="acme-app · staging" title="Scans" actions={<Link to="/app/scan/run"><Button><Play size={14} /> Lancer un scan</Button></Link>} />
      <div className="content">
        <section className="card">
          <div style={{ overflowX: "auto" }}>
            <table className="table">
              <thead><tr><th>Quand</th><th>Déclencheur</th><th>Findings</th><th>Prouvés</th><th className="hide-sm">Durée</th><th>Statut</th></tr></thead>
              <tbody>
                {runs.map((r, i) => (
                  <tr key={i} onClick={() => { location.hash = "#/app/scan/run"; }}>
                    <td className="t-title">{r.when}</td>
                    <td className="mono faint">{r.trigger}</td>
                    <td className="mono">{r.found}</td>
                    <td className="mono" style={{ color: "var(--crit-ink)" }}>{r.proven}</td>
                    <td className="hide-sm mono faint">{r.dur}</td>
                    <td><span className="state proven"><span className="d" />{r.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  );
}
