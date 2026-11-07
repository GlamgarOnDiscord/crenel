import { useState } from "react";
import { Link } from "react-router-dom";
import { Topbar } from "../components/Shell.tsx";
import { Button, SeverityChip, StateBadge, EmptyState } from "../components/ui.tsx";
import { CheckCheck } from "lucide-react";
import { findings } from "../data/mock.ts";
import { SEV_RANK } from "../lib/types.ts";

const sorted = [...findings].sort((a, b) =>
  (a.state === "proven" ? 0 : 1) - (b.state === "proven" ? 0 : 1) || SEV_RANK[a.sev] - SEV_RANK[b.sev],
);

type Filter = "all" | "proven" | "lead" | "fixed";

export function Findings() {
  const [filter, setFilter] = useState<Filter>("all");
  const counts = {
    all: sorted.length,
    proven: sorted.filter((f) => f.state === "proven").length,
    lead: sorted.filter((f) => f.state === "lead").length,
    fixed: sorted.filter((f) => f.state === "fixed").length,
  };
  const rows = filter === "all" ? sorted : sorted.filter((f) => f.state === filter);
  const tabs: [Filter, string][] = [["all", "Tous"], ["proven", "Prouvés"], ["lead", "Leads"], ["fixed", "Corrigés"]];
  return (
    <>
      <Topbar crumb="acme-app · staging" title="Findings" actions={<Button variant="ghost" size="sm">Exporter SARIF</Button>} />
      <div className="content">
        <div className="seg" style={{ width: "fit-content" }}>
          {tabs.map(([key, label]) => (
            <button key={key} aria-pressed={filter === key} className={filter === key ? "on" : ""} onClick={() => setFilter(key)}>
              {label} ({counts[key]})
            </button>
          ))}
        </div>
        <section className="card">
          {rows.length === 0 ? (
            <EmptyState icon={<CheckCheck size={22} />} title="Aucun finding ici">
              {filter === "fixed" ? "Rien n'a encore été marqué corrigé." : "Aucun finding dans ce filtre."}
            </EmptyState>
          ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="table">
              <thead><tr><th>Sév.</th><th>Intitulé</th><th className="hide-sm">Emplacement</th><th className="hide-sm">Check</th><th>État</th><th className="hide-sm">Vu</th><th /></tr></thead>
              <tbody>
                {rows.map((f) => (
                  <tr key={f.id}>
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
          )}
        </section>
      </div>
    </>
  );
}
