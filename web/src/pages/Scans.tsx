import { useState } from "react";
import { CheckCheck, CircleDashed, Clock, ListTodo, Search, ShieldAlert, ShieldCheck, SquarePen } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { ActivityList, Card, Button, EmptyState, KpiTile, PERIODS, Segmented, TaskList, type Period } from "../components/ui.tsx";
import { activity, daily, tasks } from "../data/mock.ts";
import type { TaskStatus } from "../lib/types.ts";

type Filter = "all" | "live" | "done" | "archived";

export function Scans() {
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const [period, setPeriod] = useState<Period>("30");
  const days = Number(period);
  const win = (a: number[]) => a.slice(-days);
  const total = win(daily.tasks).reduce((n, x) => n + x, 0);
  const provenN = win(daily.proven).reduce((n, x) => n + x, 0);
  const med = [...win(daily.minutes)].sort((a, b) => a - b)[Math.floor(days / 2)] ?? 0;
  const match = (s: TaskStatus, archived?: boolean): Record<Filter, boolean> => ({
    all: !archived, live: s === "running" || s === "waiting", done: (s === "done" || s === "stopped") && !archived, archived: !!archived,
  });
  const ql = q.trim().toLowerCase();
  const rows = tasks.filter((t) => match(t.status, t.archived)[filter] && (!ql || (t.title + " " + t.target).toLowerCase().includes(ql)));
  const count = (f: Filter) => tasks.filter((t) => match(t.status, t.archived)[f]).length;
  const tabs: [Filter, string][] = [["all", "Tâches"], ["live", "En cours"], ["done", "Terminées"], ["archived", "Archivées"]];
  return (
    <>
      <Topbar crumb="Agent" title="Tâches" bar={<Segmented items={PERIODS} value={period} onChange={setPeriod} label="Période" />}
        insight={<>Une tâche <b>attend votre accord</b> pour envoyer des requêtes à staging.</>}
        actions={<Button to="/app/overview"><SquarePen size={14} /> Nouvelle tâche</Button>} />
      <div className="content">
        <div className="kpis three">
          <KpiTile label="Tâches lancées" icon={<ListTodo size={14} />} value={total} delta={4} comparison={`vs ${days} j`} data={win(daily.tasks)} />
          <KpiTile label="Failles prouvées" icon={<ShieldAlert size={14} />} value={provenN} delta={1} bad="up" comparison={`vs ${days} j`} data={win(daily.proven)} tone="danger" />
          <KpiTile label="Durée médiane" icon={<Clock size={14} />} value={Math.floor(med / 60) ? `${Math.floor(med / 60)} min ${String(med % 60).padStart(2, "0")}` : `${med} s`} delta={-6} deltaUnit=" s" comparison="vs 30 j" data={win(daily.minutes)} />
        </div>
        <div className="filters">
          <label className="searchfield">
            <Search size={15} aria-hidden="true" />
            <span className="sr-only">Rechercher une tâche</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Rechercher une tâche ou une cible" />
          </label>
          <div className="seg" role="group" aria-label="Filtrer les tâches">
            {tabs.map(([k, l]) => (
              <button type="button" key={k} aria-pressed={filter === k} className={filter === k ? "on" : ""} onClick={() => setFilter(k)}>{l} <span className="seg-n">{count(k)}</span></button>
            ))}
          </div>
        </div>
        <div className="cols">
          <section className="card flat">
          {rows.length ? <TaskList items={rows} /> : (
            <EmptyState icon={<Mascot size={84} />} title="Aucune tâche ici" action={<Button variant="ghost" size="sm" to="/app/overview">Lancer une tâche</Button>}>
              Rien ne correspond à ce filtre.
            </EmptyState>
          )}
        </section>
          <Card title="Activité" meta="en direct">
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
