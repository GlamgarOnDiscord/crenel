import { useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { CircleCheck, CircleDashed, ExternalLink, Link2, MoreHorizontal, ShieldAlert, ShieldCheck, TerminalSquare } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { Button, Card, EmptyState, GuardBadge, KpiTile, PERIODS, Segmented, SevMeter, SeverityChip, StateBadge, type Period } from "../components/ui.tsx";
import { BarChart } from "../components/arc/bar-chart/bar-chart.tsx";
import { DonutChart } from "../components/arc/donut-chart/donut-chart.tsx";
import { DropdownMenu } from "../components/arc/dropdown-menu/dropdown-menu.tsx";
import { SearchField } from "../components/arc/search-field/search-field.tsx";
import { useToast } from "../components/toast.tsx";
import { daily, findings, guardedCount } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import { SEV_LABEL, SEV_NAME, SEV_RANK, type Finding, type FindingState, type Severity } from "../lib/types.ts";

const STATE_ORDER: Record<FindingState, number> = { proven: 0, lead: 1, fixed: 2 };
const sorted = [...findings].sort((a, b) => STATE_ORDER[a.state] - STATE_ORDER[b.state] || SEV_RANK[a.sev] - SEV_RANK[b.sev]);

type Filter = "all" | FindingState;
const SEVS: Severity[] = ["crit", "high", "med", "low"];
const DAY = 86400000;
const LAST = Date.UTC(2026, 10, 7);
const dayFmt = new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", timeZone: "UTC" });
const longFmt = new Intl.DateTimeFormat("fr-FR", { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" });

export function FindingRow({ f }: { f: Finding }) {
  const navigate = useNavigate();
  const toast = useToast();
  return (
    <li className={cn("frow", `is-${f.state}`)}>
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
      <span className="frow-menu">
        <DropdownMenu iconOnly label={`Actions pour ${f.title}`} icon={<MoreHorizontal size={16} />} items={[
          { label: "Ouvrir", icon: <ExternalLink size={14} />, onSelect: () => navigate(`/app/findings/${f.id}`) },
          { label: "Demander à l'agent", icon: <TerminalSquare size={14} />, onSelect: () => navigate("/app/agent", { state: { prompt: `/explain ${f.id}: ${f.title}` } }) },
          { label: "Copier le lien", icon: <Link2 size={14} />, onSelect: async () => { try { await navigator.clipboard.writeText(`${location.origin}${location.pathname}#/app/findings/${f.id}`); } catch { /* ignore */ } toast({ type: "success", title: "Lien copié" }); } },
          { label: "Marquer corrigé", icon: <CircleCheck size={14} />, separatorBefore: true, disabled: f.state === "fixed", onSelect: () => toast({ type: "success", title: "Marqué corrigé", description: "Le test reste gardé en CI." }) },
        ]} />
      </span>
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
  const sum = (a: number[]) => a.reduce((n, x) => n + x, 0);
  const dl = (a: number[]) => sum(win(a)) - sum(a.slice(-2 * days, -days));
  const clampD = (v: number, m: number) => Math.sign(v) * Math.min(m, Math.abs(v));

  const bars = useMemo(() => win(daily.detected).map((v, i, arr) => {
    const t = LAST - (arr.length - 1 - i) * DAY;
    return { key: String(t), label: longFmt.format(t), axisLabel: dayFmt.format(t), value: v };
  }), [days]); // eslint-disable-line
  const bySev = SEVS.map((s) => ({ key: s, label: SEV_NAME[s][0]!.toUpperCase() + SEV_NAME[s].slice(1), value: findings.filter((f) => f.sev === s && f.state !== "fixed").length,
    color: s === "crit" ? "var(--danger)" : s === "high" ? "var(--data-1)" : s === "med" ? "var(--data-2)" : "var(--data-3)" }));

  const count = (s: Filter) => (s === "all" ? sorted.length : sorted.filter((f) => f.state === s).length);
  const ql = q.trim().toLowerCase();
  const rows = sorted.filter((f) =>
    (filter === "all" || f.state === filter) &&
    (sevs.length === 0 || sevs.includes(f.sev)) &&
    (!ql || (f.title + " " + f.location + " " + f.check).toLowerCase().includes(ql)));
  const tabs: { id: Filter; label: string; count: number }[] = [
    { id: "all", label: "Tous", count: count("all") }, { id: "proven", label: "Prouvés", count: count("proven") },
    { id: "lead", label: "Pistes", count: count("lead") }, { id: "fixed", label: "Corrigés", count: count("fixed") }];
  const toggleSev = (s: Severity) => setSevs((l) => (l.includes(s) ? l.filter((x) => x !== s) : [...l, s]));
  const reset = () => { setFilter("all"); setSevs([]); setQ(""); };

  return (
    <>
      <Topbar scoped title="Findings" bar={<Segmented items={PERIODS} value={period} onChange={setPeriod} label="Période" />}
        insight={<><b>{count("proven")} failles prouvées</b> à corriger, dont 3 critiques. Le reste n'est que des pistes.</>}
        actions={<Button variant="ghost" size="sm">Exporter SARIF</Button>} />
      <div className="content">
        <div className="kpis">
          <KpiTile label="Prouvés" icon={<ShieldAlert size={14} />} value={count("proven")} delta={clampD(dl(daily.proven), 3)} bad="up" comparison={`vs ${days} j`} data={win(daily.proven)} tone="danger" />
          <KpiTile label="Pistes" icon={<CircleDashed size={14} />} value={count("lead")} delta={clampD(dl(daily.leads), 4)} comparison={`vs ${days} j`} data={win(daily.leads)} />
          <KpiTile label="Corrigés" icon={<CircleCheck size={14} />} value={count("fixed")} delta={1} comparison={`vs ${days} j`} data={win(daily.fixed)} />
          <KpiTile label="Gardés en CI" icon={<ShieldCheck size={14} />} value={guardedCount} delta={2} comparison={`vs ${days} j`} data={win(daily.guarded)} tone="brand" to="/app/tests" />
        </div>

        <div className="cols charts">
          <Card title="Détectés par jour" meta={`${days} derniers jours`} className="chart-card">
            <div className="pad"><BarChart data={bars} label="Findings détectés par jour" period={`${days} derniers jours`} unit=" findings" valueLabel="Total" /></div>
          </Card>
          <Card title="Ouverts par sévérité" className="chart-card">
            <div className="pad donut-wrap"><DonutChart data={bySev} label="Findings ouverts par sévérité" totalLabel="Ouverts" size={176} thickness={20} /></div>
          </Card>
        </div>

        <div className="filters">
          <SearchField hideLabel label="Rechercher un finding" value={q} onValueChange={setQ} placeholder="Intitulé, fichier ou check" className="filter-search" />
          <Segmented items={tabs} value={filter} onChange={setFilter} label="État" />
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
