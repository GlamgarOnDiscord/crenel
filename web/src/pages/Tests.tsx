import { useMemo } from "react";
import { Link } from "react-router-dom";
import { GitPullRequest } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, Card, GuardBadge } from "../components/ui.tsx";
import { Badge } from "../components/arc/badge/badge.tsx";
import { Gauge } from "../components/arc/gauge/gauge.tsx";
import { LineChart } from "../components/arc/line-chart/line-chart.tsx";
import { SortableDataTable, type DataColumn } from "../components/arc/sortable-data-table/sortable-data-table.tsx";
import { useToast } from "../components/toast.tsx";
import { useData } from "../data/api.ts";

type Row = { name: string; check: string; status: string; when: string; finding: string; order: number };
const DAY = 86400000;
const DEMO_LAST = Date.UTC(2026, 10, 7);
const dayFmt = new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", timeZone: "UTC" });

export function Tests() {
  const toast = useToast();
  const { daily, findings, guardedCount, tests, live } = useData();
  const LAST = live ? Math.floor(Date.now() / DAY) * DAY : DEMO_LAST;
  const drafts = tests.length - guardedCount;
  const provenEver = findings.filter((f) => f.state === "proven" || (f.state === "fixed" && f.proof)).length;
  const provenGuarded = findings.filter((f) => (f.state === "proven" || (f.state === "fixed" && f.proof)) && f.guarded).length;

  const series = useMemo(() => {
    let g = 0, p = 0;
    return daily.guarded.slice(-30).map((v, i) => {
      g += v; p += daily.proven.slice(-30)[i]!;
      const t = LAST - (29 - i) * DAY;
      return { key: String(t), label: dayFmt.format(t), axisLabel: i % 7 === 0 ? dayFmt.format(t) : undefined, values: { guarded: g, proven: p } };
    });
  }, [daily]);

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
        <div className="cols rev">
          <Card title="Couverture des failles prouvées">
            <div className="pad gauge-wrap">
              <Gauge value={provenEver ? Math.round((provenGuarded / provenEver) * 100) : 0} label="Failles prouvées gardées en CI" detail={`${provenGuarded} sur ${provenEver} prouvées`}
                thresholds={[{ from: 0, tone: "danger", label: "à risque" }, { from: 50, tone: "warning", label: "partiel" }, { from: 80, tone: "success", label: "gardé" }]} />
            </div>
          </Card>
          <Card title="Gardés et prouvés, cumulés" meta="30 derniers jours">
            <div className="pad">
              <LineChart data={series} label="Tests gardés et failles prouvées cumulés" height={200}
                series={[{ key: "guarded", label: "Gardés en CI", color: "var(--brand)", area: true }, { key: "proven", label: "Prouvés", color: "var(--fg-faint)", dashed: true, area: false }]} />
            </div>
          </Card>
        </div>
        <section className="card flat table-card">
          <SortableDataTable rows={rows} columns={columns} rowKey="name" caption="Tests de régression générés"
            defaultSort={{ key: "status", direction: "asc" }} itemName={{ one: "test", other: "tests" }} />
        </section>
      </div>
    </>
  );
}
