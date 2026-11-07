import { Topbar } from "../components/Shell.tsx";
import { Button } from "../components/ui.tsx";
import { authzRows } from "../data/mock.ts";

export function Authorization() {
  return (
    <>
      <Topbar crumb="acme-app · staging" title="Autorisation" actions={<Button size="sm">Générer les tests</Button>} />
      <div className="content" style={{ maxWidth: 900 }}>
        <p className="muted" style={{ margin: 0, maxWidth: "64ch" }}>Matrice inter-tenant: le compte A tente d'atteindre les ressources du compte B. Tout ce qui n'est pas refusé (401/403/404) est une faille d'autorisation prouvée. C'est déterministe, sans LLM dans le verdict.</p>
        <section className="card">
          <div style={{ overflowX: "auto" }}>
            <table className="table">
              <thead><tr><th>Ressource</th><th>Route</th><th>Méthode</th><th>Réponse</th><th>Verdict</th></tr></thead>
              <tbody>
                {authzRows.map((r, i) => (
                  <tr key={i}>
                    <td className="t-title">{r.resource}</td>
                    <td className="mono faint">{r.route}</td>
                    <td className="mono">{r.method}</td>
                    <td className="mono" style={{ color: r.verdict === "fail" ? "var(--crit-ink)" : "var(--fg-muted)" }}>{r.result}</td>
                    <td>{r.verdict === "fail"
                      ? <span className="chip crit">fail</span>
                      : <span className="chip low">pass</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        <section className="card">
          <div className="hd"><h2>Preuve rejouable</h2><span className="meta">le cas en échec</span></div>
          <div style={{ padding: 18 }}>
            <div className="toolcall"><span className="k">$</span> curl -i -H 'authorization: Bearer A' https://staging.acme.app/api/projects/proj_b_1
{"\n"}→ HTTP 200  (attendu: 401/403/404)</div>
          </div>
        </section>
      </div>
    </>
  );
}
