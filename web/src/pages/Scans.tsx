import { useState } from "react";
import { CheckCheck, CircleDashed, ListTodo, ShieldAlert, ShieldCheck, SquarePen } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { ActivityList, Button, Card, EmptyState, Segmented, TaskList } from "../components/ui.tsx";
import { SearchField } from "../components/arc/search-field/search-field.tsx";
import { useData } from "../data/api.ts";
import type { TaskStatus } from "../lib/types.ts";

type Filter = "all" | "live" | "done" | "archived";

export function Scans() {
  const { activity, tasks, live } = useData();
  const waitingN = tasks.filter((t) => t.status === "waiting").length;
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const match = (s: TaskStatus, archived?: boolean): Record<Filter, boolean> => ({
    all: !archived, live: (s === "running" || s === "waiting") && !archived, done: (s === "done" || s === "stopped") && !archived, archived: !!archived,
  });
  const ql = q.trim().toLowerCase();
  const rows = tasks.filter((t) => match(t.status, t.archived)[filter] && (!ql || (t.title + " " + t.target).toLowerCase().includes(ql)));
  const count = (f: Filter) => tasks.filter((t) => match(t.status, t.archived)[f]).length;
  const tabs: { id: Filter; label: string; count: number }[] = [
    { id: "all", label: "Tâches", count: count("all") }, { id: "live", label: "En cours", count: count("live") },
    { id: "done", label: "Terminées", count: count("done") }, { id: "archived", label: "Archivées", count: count("archived") }];

  return (
    <>
      <Topbar crumb="Agent" title="Tâches"
        insight={!live || waitingN ? <>{waitingN > 1 ? `${waitingN} tâches` : "Une tâche"} <b>attend{waitingN > 1 ? "ent" : ""} votre accord</b> pour envoyer des requêtes à staging.</> : <>Aucune tâche n'attend votre accord.</>}
        actions={<Button to="/app/overview"><SquarePen size={14} /> Nouvelle tâche</Button>} />
      <div className="content">
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
