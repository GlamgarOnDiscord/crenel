import { useState } from "react";
import { Search, SquarePen } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { Button, EmptyState, TaskList } from "../components/ui.tsx";
import { tasks } from "../data/mock.ts";
import type { TaskStatus } from "../lib/types.ts";

type Filter = "all" | "live" | "done" | "archived";

export function Scans() {
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const match = (s: TaskStatus, archived?: boolean): Record<Filter, boolean> => ({
    all: !archived, live: s === "running" || s === "waiting", done: (s === "done" || s === "stopped") && !archived, archived: !!archived,
  });
  const ql = q.trim().toLowerCase();
  const rows = tasks.filter((t) => match(t.status, t.archived)[filter] && (!ql || (t.title + " " + t.target).toLowerCase().includes(ql)));
  const count = (f: Filter) => tasks.filter((t) => match(t.status, t.archived)[f]).length;
  const tabs: [Filter, string][] = [["all", "Tâches"], ["live", "En cours"], ["done", "Terminées"], ["archived", "Archivées"]];
  return (
    <>
      <Topbar crumb="Agent" title="Tâches" actions={<Button to="/app/overview"><SquarePen size={14} /> Nouvelle tâche</Button>} />
      <div className="content mid">
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
        <section className="card flat">
          {rows.length ? <TaskList items={rows} /> : (
            <EmptyState icon={<Mascot size={84} />} title="Aucune tâche ici" action={<Button variant="ghost" size="sm" to="/app/overview">Lancer une tâche</Button>}>
              Rien ne correspond à ce filtre.
            </EmptyState>
          )}
        </section>
        <p className="note">Chaque tâche rouvre l'agent avec son déroulé complet: outils appelés, preuves, permissions accordées.</p>
      </div>
    </>
  );
}
