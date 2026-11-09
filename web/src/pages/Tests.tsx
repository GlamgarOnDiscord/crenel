import { Link } from "react-router-dom";
import { Download } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, GuardBadge } from "../components/ui.tsx";
import { Badge } from "../components/arc/badge/badge.tsx";
import { SortableDataTable, type DataColumn } from "../components/arc/sortable-data-table/sortable-data-table.tsx";
import { useServerAction } from "../components/console-actions.tsx";
import { downloadRegressionFile } from "../data/actions.ts";
import { useData } from "../data/api.ts";

type Row = { name: string; check: string; status: string; when: string; finding: string; order: number };

export function Tests() {
  const run = useServerAction();
  const { guardedCount, tests } = useData();
  const drafts = tests.length - guardedCount;
  const s = (n: number) => (n > 1 ? "s" : "");
  // Crenel cannot see your CI: only claim guarded tests when there are some.
  const insight = guardedCount > 0
    ? <><b>{guardedCount} faille{s(guardedCount)}</b> ne peu{guardedCount > 1 ? "vent" : "t"} plus revenir sans casser le build.{drafts > 0 ? ` ${drafts} brouillon${s(drafts)} à ajouter à la CI.` : ""}</>
    : tests.length > 0
      ? <><b>{tests.length} test{s(tests.length)} généré{s(tests.length)}</b>, pas encore dans votre CI. Téléchargez le fichier et ajoutez-le au dépôt.</>
      : <>Aucun test généré pour l'instant. Lancez /test dans l'agent sur un finding prouvé.</>;
  const rows: Row[] = tests.map((t, i) => ({ ...t, order: i }));
  const columns: DataColumn<Row>[] = [
    { key: "name", label: "Test", sortable: true, render: (_, r) => <Link to={`/app/findings/${r.finding}`} className="tbl-link">{r.name}</Link> },
    { key: "check", label: "Check", sortable: true, width: 170, render: (v) => <span className="mono faint">{String(v)}</span> },
    { key: "status", label: "Statut", sortable: true, width: 120, render: (v) => v === "ci" ? <GuardBadge label="en CI" /> : <Badge size="sm" tone="neutral">brouillon</Badge> },
    { key: "when", label: "Généré", sortable: false, width: 120, render: (v) => <span className="faint">{String(v)}</span> },
  ];

  return (
    <>
      <Topbar scoped title="Tests gardés" insight={insight}
        actions={<Button size="sm" onClick={() => void run(downloadRegressionFile, () => ({ title: "Fichier de tests téléchargé", description: "À placer dans tests/crenel/ de votre dépôt." }), "Pas de fichier de tests")}><Download size={14} /> Télécharger le fichier de tests</Button>} />
      <div className="content">
        <section className="card flat table-card">
          <SortableDataTable rows={rows} columns={columns} rowKey="name" caption="Tests de régression générés"
            defaultSort={{ key: "status", direction: "asc" }} itemName={{ one: "test", other: "tests" }} />
        </section>
      </div>
    </>
  );
}
