import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { CircleCheck, CircleDashed, Search, ShieldAlert, ShieldCheck, X } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { SevMeter, Button, EmptyState, GuardBadge, KpiTile, PERIODS, Segmented, SeverityChip, StateBadge, type Period } from "../components/ui.tsx";
import { daily, findings, guardedCount } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import { SEV_LABEL, SEV_NAME, SEV_RANK, type Finding, type FindingState, type Severity } from "../lib/types.ts";

const STATE_ORDER: Record<FindingState, number> = { proven: 0, lead: 1, fixed: 2 };
const sorted = [...findings].sort((a, b) => STATE_ORDER[a.state] - STATE_ORDER[b.state] || SEV_RANK[a.sev] - SEV_RANK[b.sev]);

type Filter = "all" | FindingState;
const SEVS: Severity[] = ["crit", "high", "med", "low"];

export function FindingRow({ f }: { f: Finding }) {
  return (
    <li className={cn("frow", f.state)}>
      <SeverityChip sev={f.sev} />
      <div className="frow-main">
        <Link to={`/app/findings/${f.id}`} className="frow-t stretched">{f.title}</Link>
        <div className="frow-meta mono"><span>{f.location}</span><span className="hide-sm">{f.check}</span></div>
      </div>
      <div className="frow-side">
        <StateBadge state={f.state} />
        {f.guarded && <GuardBadge />}
      </div>
      <span className="frow-seen mono hide-sm">{f.seen}</span>
    </li>
  );
}

export function Findings() {
  const loc = useLocation();
  const initialFilter = ((loc.state as { filter?: Filter } | null)?.filter) ?? "all";
  const [filter, setFilter] = useState<Filter>(initialFilter);
  const [sevs, setSevs] = useState<Severity[]>([]);
  const [q, setQ] = useState("");
  const [period, setPeriod] = useState<Period>("30");
  const days = Number(period);
  const win = (a: number[]) => a.slice(-days);
  const prevSum = (a: number[]) => a.slice(-2 * days, -days).reduce((n, x) => n + x, 0);
  const curSum = (a: number[]) => win(a).reduce((n, x) => n + x, 0);
  const dl = (a: number[]) => curSum(a) - prevSum(a);

  const count = (s: Filter) => (s === "all" ? sorted.length : sorted.filter((f) => f.state === s).length);
  const ql = q.trim().toLowerCase();
  const rows = sorted.filter((f) =>
    (filter === "all" || f.state === filter) &&
    (sevs.length === 0 || sevs.includes(f.sev)) &&
    (!ql || (f.title + " " + f.location + " " + f.check).toLowerCase().includes(ql)));
  const tabs: [Filter, string][] = [["all", "Tous"], ["proven", "Prouvés"], ["lead", "Pistes"], ["fixed", "Corrigés"]];
  const toggleSev = (s: Severity) => setSevs((l) => (l.includes(s) ? l.filter((x) => x !== s) : [...l, s]));
  const reset = () => { setFilter("all"); setSevs([]); setQ(""); };

  return (
    <>
      <Topbar scoped title="Findings" bar={<Segmented items={PERIODS} value={period} onChange={setPeriod} label="Période" />}
        insight={<><b>{count("proven")} failles prouvées</b> à corriger, dont 3 critiques. Le reste n'est que des pistes.</>}
        actions={<Button variant="ghost" size="sm">Exporter SARIF</Button>} />
      <div className="content">
        <div className="kpis">
          <KpiTile label="Prouvés" icon={<ShieldAlert size={14} />} value={count("proven")} delta={Math.sign(dl(daily.proven)) * Math.min(3, Math.abs(dl(daily.proven)))} bad="up" comparison={`vs ${days} j`} data={win(daily.proven)} tone="danger" />
          <KpiTile label="Pistes" icon={<CircleDashed size={14} />} value={count("lead")} delta={Math.sign(dl(daily.leads)) * Math.min(4, Math.abs(dl(daily.leads)))} comparison={`vs ${days} j`} data={win(daily.leads)} />
          <KpiTile label="Corrigés" icon={<CircleCheck size={14} />} value={count("fixed")} delta={1} comparison={`vs ${days} j`} data={win(daily.fixed)} />
          <KpiTile label="Gardés en CI" icon={<ShieldCheck size={14} />} value={guardedCount} delta={2} comparison={`vs ${days} j`} data={win(daily.guarded)} tone="brand" to="/app/tests" />
        </div>
        <div className="filters">
          <label className="searchfield">
            <Search size={15} aria-hidden="true" />
            <span className="sr-only">Rechercher un finding</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Rechercher un intitulé, un fichier, un check" />
            {q && <button type="button" aria-label="Effacer la recherche" onClick={() => setQ("")}><X size={14} /></button>}
          </label>
          <div className="seg" role="group" aria-label="État">
            {tabs.map(([key, label]) => (
              <button type="button" key={key} aria-pressed={filter === key} className={filter === key ? "on" : ""} onClick={() => setFilter(key)}>
                {label} <span className="seg-n">{count(key)}</span>
              </button>
            ))}
          </div>
          <div className="sevfilter" role="group" aria-label="Sévérité">
            {SEVS.map((s) => (
              <button type="button" key={s} aria-pressed={sevs.includes(s)} aria-label={`Sévérité ${SEV_NAME[s]}`} className={cn("sevbtn", s, sevs.includes(s) && "on")} onClick={() => toggleSev(s)}>
                <SevMeter sev={s} />{SEV_LABEL[s]}
              </button>
            ))}
          </div>
        </div>

        <section className="card flat">
          {rows.length === 0 ? (
            <EmptyState icon={<Mascot size={84} />} title="Rien dans ce filtre" action={<Button variant="ghost" size="sm" onClick={reset}>Réinitialiser les filtres</Button>}>
              Aucun finding ne correspond. Le choucas a regardé partout.
            </EmptyState>
          ) : (
            <ul className="flist">{rows.map((f) => <FindingRow key={f.id} f={f} />)}</ul>
          )}
        </section>
      </div>
    </>
  );
}
