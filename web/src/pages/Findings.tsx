import { Link } from "react-router-dom";
import { Topbar } from "../components/Shell.tsx";
import { Button, SeverityChip, StateBadge } from "../components/ui.tsx";
import { findings } from "../data/mock.ts";

export function Findings() {
  return (
    <>
      <Topbar crumb="acme-app · staging" title="Findings" actions={<Button variant="ghost" size="sm">Exporter SARIF</Button>} />
      <div className="content">
        <div className="seg" style={{ width: "fit-content" }}>
          <button className="on">Tous (7)</button><button>Prouvés (3)</button><button>Leads (4)</button><button>Corrigés</button>
        </div>
        <section className="card">
          <div style={{ overflowX: "auto" }}>
            <table className="table">
              <thead><tr><th>Sév.</th><th>Intitulé</th><th className="hide-sm">Emplacement</th><th className="hide-sm">Check</th><th>État</th><th className="hide-sm">Vu</th><th /></tr></thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} onClick={() => { location.hash = `#/app/findings/${f.id}`; }}>
                    <td><SeverityChip sev={f.sev} /></td>
                    <td className="t-title">{f.title}</td>
                    <td className="hide-sm mono faint">{f.location}</td>
                    <td className="hide-sm mono faint">{f.check}</td>
                    <td><StateBadge state={f.state} /></td>
                    <td className="hide-sm mono faint">{f.seen}</td>
                    <td><Link className="linkish" to={`/app/findings/${f.id}`}>Voir</Link></td>
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
