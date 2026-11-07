import { Topbar } from "../components/Shell.tsx";
import { Button } from "../components/ui.tsx";

const tests = [
  { name: "A ne peut pas lire le projet de B", check: "authz-matrix", status: "en CI", when: "il y a 11 min" },
  { name: "Le bundle ne contient pas sk_live_", check: "exposed-secrets", status: "en CI", when: "il y a 2 h" },
  { name: "Le lockfile ne contient pas @tanstack@1.169.5", check: "dependency-risk", status: "en CI", when: "il y a 12 min" },
  { name: "A ne peut pas lire le rendu de B", check: "authz-matrix", status: "brouillon", when: "il y a 11 min" },
];

export function Tests() {
  return (
    <>
      <Topbar crumb="Correctifs" title="Tests générés" actions={<Button variant="ghost" size="sm">Ouvrir la PR</Button>} />
      <div className="content">
        <p className="muted" style={{ margin: 0, maxWidth: "64ch" }}>Chaque finding prouvé devient un test de régression. Une fois en CI, la faille ne peut plus revenir sans casser le build.</p>
        <section className="card">
          <div style={{ overflowX: "auto" }}>
            <table className="table">
              <thead><tr><th>Test</th><th className="hide-sm">Check</th><th>Statut</th><th className="hide-sm">Généré</th></tr></thead>
              <tbody>
                {tests.map((t, i) => (
                  <tr key={i}>
                    <td className="t-title">{t.name}</td>
                    <td className="hide-sm mono faint">{t.check}</td>
                    <td><span className={`chip ${t.status === "en CI" ? "low" : "med"}`}>{t.status}</span></td>
                    <td className="hide-sm mono faint">{t.when}</td>
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
