import { Link } from "react-router-dom";
import { GitPullRequest } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, GuardBadge } from "../components/ui.tsx";
import { Badge } from "../components/arc/badge/badge.tsx";
import { SortableDataTable, type DataColumn } from "../components/arc/sortable-data-table/sortable-data-table.tsx";
import { useToast } from "../components/toast.tsx";
import { useData } from "../data/api.ts";

type Row = { name: string; check: string; status: string; when: string; finding: string; order: number };

export function Tests() {
  const toast = useToast();
  const { guardedCount, tests } = useData();
  const drafts = tests.length - guardedCount;
  const rows: Row[] = tests.map((t, i) => ({ ...t, order: i }));
  const columns: DataColumn<Row>[] = [
    { key: "name", label: "Test", sortable: true, render: (_, r) => <Link to={`/app/findings/${r.finding}`} className="tbl-link">{r.name}</Link> },
    { key: "check", label: "Check", sortable: true, width: 170, render: (v) => <span className="mono faint">{String(v)}</span> },
    { key: "status", label: "Statut", sortable: true, width: 120, render: (v) => v === "ci" ? <GuardBadge label="en CI" /> : <Badge size="sm" tone="neutral">brouillon</Badge> },
    { key: "when", label: "Généré", sortable: false, width: 120, render: (v) => <span className="faint">{String(v)}</span> },
  ];

  return (
    <>
      <Topbar scoped title="Tests gardés" insight={<><b>{guardedCount} failles</b> ne peuvent plus revenir sans casser le build.</>}
        actions={<Button size="sm" onClick={() => toast({ type: "success", title: "PR ouverte", description: `${drafts} brouillon prêt pour la revue.` })}><GitPullRequest size={14} /> Ouvrir la PR des brouillons</Button>} />
      <div className="content">
        <section className="card flat table-card">
          <SortableDataTable rows={rows} columns={columns} rowKey="name" caption="Tests de régression générés"
            defaultSort={{ key: "status", direction: "asc" }} itemName={{ one: "test", other: "tests" }} />
        </section>
      </div>
    </>
  );
}
