import { Fragment, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { CircleCheck, CircleDashed, Download, Eye, EyeOff, ExternalLink, Link2, MoreHorizontal, ShieldAlert, ShieldCheck, TerminalSquare } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { Button, EmptyState, GuardBadge, KpiTile, Pill, Segmented, SevMeter, SeverityChip, StateBadge } from "../components/ui.tsx";
import { IgnoreFinding, useServerAction } from "../components/console-actions.tsx";
import { DropdownMenu } from "../components/arc/dropdown-menu/dropdown-menu.tsx";
import { SearchField } from "../components/arc/search-field/search-field.tsx";
import { useToast } from "../components/toast.tsx";
import { useData } from "../data/api.ts";
import { copyText, downloadSarif, ignoreFinding, linkTo } from "../data/actions.ts";
import { cn } from "../lib/cn.ts";
import { SEV_LABEL, SEV_NAME, SEV_RANK, type Finding, type FindingState, type Severity } from "../lib/types.ts";

const STATE_ORDER: Record<FindingState, number> = { proven: 0, lead: 1, fixed: 2 };

type Filter = "all" | FindingState | "ignored";
const SEVS: Severity[] = ["crit", "high", "med", "low"];

export function FindingRow({ f, asking, onAsk }: { f: Finding; asking?: boolean; onAsk?: (open: boolean) => void }) {
  const navigate = useNavigate();
  const toast = useToast();
  const run = useServerAction();
  return (
    <Fragment>
    <li className={cn("frow", `is-${f.state}`, f.ignored && "is-ignored")}>
      <SeverityChip sev={f.sev} />
      <div className="frow-main">
        <Link to={`/app/findings/${f.id}`} className="frow-t stretched">{f.title}</Link>
        <div className="frow-meta mono"><span>{f.location}</span><span className="hide-sm">{f.check}</span>
          {f.ignored?.reason && <span className="ignored-reason" title={f.ignored.reason}>ignoré: {f.ignored.reason}</span>}</div>
      </div>
      <div className="frow-side">
        <StateBadge state={f.state} />
        {f.guarded && <GuardBadge />}
        {f.ignored && <span title={f.ignored.reason ? `Ignoré: ${f.ignored.reason}` : "Ignoré dans la console"}><Pill><EyeOff size={11} aria-hidden="true" /> ignoré</Pill></span>}
      </div>
      <span className="frow-seen mono hide-sm">{f.seen}</span>
      <span className="frow-menu">
        <DropdownMenu iconOnly label={`Actions pour ${f.title}`} icon={<MoreHorizontal size={16} />} items={[
          { label: "Ouvrir", icon: <ExternalLink size={14} />, onSelect: () => navigate(`/app/findings/${f.id}`) },
          { label: "Demander à l'agent", icon: <TerminalSquare size={14} />, onSelect: () => navigate("/app/agent", { state: { prompt: `/explain ${f.id}: ${f.title}` } }) },
          { label: "Copier le lien", icon: <Link2 size={14} />, onSelect: async () => {
            const ok = await copyText(linkTo(`/app/findings/${f.id}`));
            toast(ok ? { type: "success", title: "Lien copié" } : { type: "error", title: "Lien non copié", description: "Le navigateur refuse l'accès au presse-papiers." });
          } },
          f.ignored
            ? { label: "Ne plus ignorer", icon: <Eye size={14} />, separatorBefore: true, onSelect: () => void run(() => ignoreFinding(f.id, false), () => ({ title: "Finding de nouveau suivi" }), "Finding toujours ignoré") }
            : { label: "Ignorer...", icon: <EyeOff size={14} />, separatorBefore: true, onSelect: () => onAsk?.(true) },
        ]} />
      </span>
    </li>
    {asking && <li className="ignore-li"><IgnoreFinding uid={f.id} title={f.title} onClose={() => onAsk?.(false)} /></li>}
    </Fragment>
  );
}

export function Findings() {
  const { daily, findings, guardedCount, live, project } = useData();
  const run = useServerAction();
  const [asking, setAsking] = useState<string | null>(null);
  const sorted = [...findings].sort((a, b) => STATE_ORDER[a.state] - STATE_ORDER[b.state] || SEV_RANK[a.sev] - SEV_RANK[b.sev]);
  const loc = useLocation();
  const initialFilter = ((loc.state as { filter?: Filter } | null)?.filter) ?? "all";
  const [filter, setFilter] = useState<Filter>(initialFilter);
  const [sevs, setSevs] = useState<Severity[]>([]);
  const [q, setQ] = useState("");
  const days = 30;
  const win = (a: number[]) => a.slice(-days);
  const sum = (a: number[]) => a.reduce((n, x) => n + x, 0);
  const dl = (a: number[]) => sum(win(a)) - sum(a.slice(-2 * days, -days));
  const clampD = (v: number, m: number) => Math.sign(v) * Math.min(m, Math.abs(v));

  // Ignored findings are shown apart (their own tab), never mixed with the rest.
  const followed = sorted.filter((f) => !f.ignored);
  const ignored = sorted.filter((f) => f.ignored);
  const count = (s: Filter) => (s === "ignored" ? ignored.length : s === "all" ? followed.length : followed.filter((f) => f.state === s).length);
  const ql = q.trim().toLowerCase();
  const rows = (filter === "ignored" ? ignored : followed).filter((f) =>
    (filter === "all" || filter === "ignored" || f.state === filter) &&
    (sevs.length === 0 || sevs.includes(f.sev)) &&
    (!ql || (f.title + " " + f.location + " " + f.check).toLowerCase().includes(ql)));
  const tabs: { id: Filter; label: string; count: number }[] = [
    { id: "all", label: "Tous", count: count("all") }, { id: "proven", label: "Prouvés", count: count("proven") },
    { id: "lead", label: "Pistes", count: count("lead") }, { id: "fixed", label: "Corrigés", count: count("fixed") },
    ...(ignored.length || filter === "ignored" ? [{ id: "ignored" as const, label: "Ignorés", count: count("ignored") }] : [])];
  const toggleSev = (s: Severity) => setSevs((l) => (l.includes(s) ? l.filter((x) => x !== s) : [...l, s]));
  const reset = () => { setFilter("all"); setSevs([]); setQ(""); };

  return (
    <>
      <Topbar scoped title="Findings"
        insight={<><b>{count("proven")} failles prouvées</b> à corriger, dont {followed.filter((f) => f.state === "proven" && f.sev === "crit").length} critiques. Le reste n'est que des pistes.{ignored.length ? ` ${ignored.length} ignoré${ignored.length > 1 ? "s" : ""} dans la console.` : ""}</>}
        actions={<Button variant="ghost" size="sm" onClick={() => void run(() => downloadSarif(project), () => ({ title: "SARIF téléchargé", description: "Le même fichier que crenel scan --sarif." }), "SARIF non exporté")}><Download size={14} /> Exporter SARIF</Button>} />
      <div className="content">
        <div className="kpis">
          <KpiTile label="Prouvés" icon={<ShieldAlert size={14} />} value={count("proven")} delta={clampD(dl(daily.proven), 3)} bad="up" data={win(daily.proven)} tone="danger" />
          <KpiTile label="Pistes" icon={<CircleDashed size={14} />} value={count("lead")} delta={clampD(dl(daily.leads), 4)} data={win(daily.leads)} />
          <KpiTile label="Corrigés" icon={<CircleCheck size={14} />} value={count("fixed")} delta={live ? undefined : 1} data={win(daily.fixed)} />
          <KpiTile label="Gardés en CI" icon={<ShieldCheck size={14} />} value={guardedCount} delta={live ? undefined : 2} data={win(daily.guarded)} tone="brand" to="/app/tests" />
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
            <>
              {filter === "ignored" && <p className="ignored-intro">Ignorés dans la console seulement: ils restent dans les rapports, le SARIF et la CI (fail-on).</p>}
              <ul className="flist">{rows.map((f) => <FindingRow key={f.id} f={f} asking={asking === f.id} onAsk={(o) => setAsking(o ? f.id : null)} />)}</ul>
            </>
          )}
        </section>
      </div>
    </>
  );
}
