import { Topbar } from "../components/Shell.tsx";
import { SeverityChip } from "../components/ui.tsx";
import { secrets } from "../data/mock.ts";

export function Secrets() {
  return (
    <>
      <Topbar crumb="acme-app · staging" title="Secrets" />
      <div className="content">
        <p className="muted" style={{ margin: 0, maxWidth: "62ch" }}>Secrets détectés dans le code et les bundles. Un secret trouvé est considéré comme compromis: révoquez d'abord, déplacez côté serveur ensuite.</p>
        <section className="card">
          <div style={{ overflowX: "auto" }}>
            <table className="table">
              <thead><tr><th>Sév.</th><th>Type</th><th className="hide-sm">Emplacement</th><th>Validité</th><th /></tr></thead>
              <tbody>
                {secrets.map((s, i) => (
                  <tr key={i}>
                    <td><SeverityChip sev={s.sev} /></td>
                    <td className="t-title">{s.kind}</td>
                    <td className="hide-sm mono faint">{s.loc}</td>
                    <td><span className="mono" style={{ fontSize: 12, color: s.valid === "active" ? "var(--crit-ink)" : "var(--fg-muted)" }}>{s.valid}</span></td>
                    <td><span className="linkish">Révoquer</span></td>
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
