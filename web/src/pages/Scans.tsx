import { useMemo, useState } from "react";
import { CheckCheck, CircleDashed, Clock, ListTodo, ShieldAlert, ShieldCheck, SquarePen } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { ActivityList, Button, Card, EmptyState, KpiTile, PERIODS, Segmented, TaskList, type Period } from "../components/ui.tsx";
import { ActivityHeatmap, type ActivityDay } from "../components/arc/activity-heatmap/activity-heatmap.tsx";
import { SearchField } from "../components/arc/search-field/search-field.tsx";
import { activity, daily, tasks } from "../data/mock.ts";
import type { TaskStatus } from "../lib/types.ts";

type Filter = "all" | "live" | "done" | "archived";
const DAY = 86400000;
const LAST = Date.UTC(2026, 10, 7);

export function Scans() {
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const [period, setPeriod] = useState<Period>("30");
  const [picked, setPicked] = useState<string | null>(null);
  const days = Number(period);
  const win = (a: number[]) => a.slice(-days);
  const total = win(daily.tasks).reduce((n, x) => n + x, 0);
  const provenN = win(daily.proven).reduce((n, x) => n + x, 0);
  const med = [...win(daily.minutes)].sort((a, b) => a - b)[Math.floor(days / 2)] ?? 0;
  // A year of agent activity for the heatmap: the last 90 days are the real
  // series, the earlier weeks a quieter deterministic ramp-up.
  const heat: ActivityDay[] = useMemo(() => {
    let x = 31;
    return Array.from({ length: 364 }, (_, i) => {
      const back = 363 - i;
      x = (x * 9301 + 49297) % 233280;
      const wd = new Date(LAST - back * DAY).getUTCDay();
      const early = Math.max(0, Math.round((x / 233280) * 5 * (i / 364) * (wd === 0 || wd === 6 ? 0.3 : 1)));
      const count = back < daily.tasks.length ? daily.tasks[daily.tasks.length - 1 - back]! : early;
      return { date: new Date(LAST - back * DAY).toISOString().slice(0, 10), count };
    });
  }, []);

  const match = (s: TaskStatus, archived?: boolean): Record<Filter, boolean> => ({
    all: !archived, live: s === "running" || s === "waiting", done: (s === "done" || s === "stopped") && !archived, archived: !!archived,
  });
  const ql = q.trim().toLowerCase();
  const rows = tasks.filter((t) => match(t.status, t.archived)[filter] && (!ql || (t.title + " " + t.target).toLowerCase().includes(ql)));
  const count = (f: Filter) => tasks.filter((t) => match(t.status, t.archived)[f]).length;
  const tabs: { id: Filter; label: string; count: number }[] = [
    { id: "all", label: "Tâches", count: count("all") }, { id: "live", label: "En cours", count: count("live") },
    { id: "done", label: "Terminées", count: count("done") }, { id: "archived", label: "Archivées", count: count("archived") }];

  return (
    <>
      <Topbar crumb="Agent" title="Tâches" bar={<Segmented items={PERIODS} value={period} onChange={setPeriod} label="Période" />}
        insight={<>Une tâche <b>attend votre accord</b> pour envoyer des requêtes à staging.</>}
        actions={<Button to="/app/overview"><SquarePen size={14} /> Nouvelle tâche</Button>} />
      <div className="content">
        <div className="kpis three">
          <KpiTile label="Tâches lancées" icon={<ListTodo size={14} />} value={total} delta={4} comparison={`vs ${days} j`} data={win(daily.tasks)} />
          <KpiTile label="Failles prouvées" icon={<ShieldAlert size={14} />} value={provenN} delta={1} bad="up" comparison={`vs ${days} j`} data={win(daily.proven)} tone="danger" />
          <KpiTile label="Durée médiane" icon={<Clock size={14} />} value={`${Math.floor(med / 60)} min ${String(med % 60).padStart(2, "0")}`} delta={-6} deltaUnit=" s" comparison={`vs ${days} j`} data={win(daily.minutes)} />
        </div>

        <Card title="Activité de l'agent" meta="12 derniers mois" className="chart-card">
          <div className="pad">
            <ActivityHeatmap days={heat} label="Tâches lancées par jour" period="12 mois" unit={{ one: "tâche", other: "tâches" }}
              weekStartsOn={1} selectedDate={picked} onSelectDate={(d) => setPicked((p) => (p === d ? null : d))} />
          </div>
        </Card>

        <div className="filters">
          <SearchField hideLabel label="Rechercher une tâche" value={q} onValueChange={setQ} placeholder="Tâche ou cible" className="filter-search" />
          <Segmented items={tabs} value={filter} onChange={setFilter} label="Filtrer les tâches" />
        </div>
        <div className="cols">
          <section className="card flat">
            {rows.length ? <TaskList items={rows} /> : (
              <EmptyState icon={<Mascot size={84} />} title="Aucune tâche ici" action={<Button variant="ghost" size="sm" to="/app/overview">Lancer une tâche</Button>}>
                Rien ne correspond à ce filtre.
              </EmptyState>
            )}
          </section>
          <Card title="Activité" meta={<><span className="live" aria-hidden="true" /> en direct</>}>
            <ActivityList items={activity.map((a) => ({
              icon: a.kind === "proven" ? <ShieldAlert size={15} /> : a.kind === "guard" ? <ShieldCheck size={15} /> : a.kind === "fixed" ? <CheckCheck size={15} /> : a.kind === "lead" ? <CircleDashed size={15} /> : <ListTodo size={15} />,
              title: a.title, meta: a.meta, tone: a.kind === "proven" ? "danger" as const : a.kind === "guard" ? "brand" as const : undefined,
            }))} />
          </Card>
        </div>
      </div>
    </>
  );
}
