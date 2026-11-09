import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Archive, ArrowDownRight, ArrowUpRight, Check, Copy, FileCode2, Hand, Link2, Loader2, MoreHorizontal, RotateCcw, ShieldCheck, Square } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { DropdownMenu } from "./arc/dropdown-menu/dropdown-menu.tsx";
import { ShimmeringText } from "./bklit/shimmering-text.tsx";
import { useToast } from "./toast.tsx";
import { ModelLogo } from "../brand/ModelLogo.tsx";
import { cn } from "../lib/cn.ts";
import { SEV_LABEL, SEV_NAME, type FindingState, type Severity, type Task } from "../lib/types.ts";
import { modelOf, type ModelId } from "../lib/workspace.tsx";
import { useData } from "../data/api.ts";
import { NEEDS_SERVER, archiveRun, copyText, linkTo } from "../data/actions.ts";
import { taskRoute } from "../lib/runs.ts";
import { Badge } from "./arc/badge/badge.tsx";
import { AnimatedCounter } from "./arc/animated-counter/animated-counter.tsx";
import SegmentedControl from "./arc/segmented-control/segmented-control.tsx";

// A button, or (when `to` is given) a react-router Link styled as one, so we
// never nest a <button> inside an <a>.
export function Button({ children, variant = "primary", size, to, state, href, className, ...rest }: {
  children: ReactNode; variant?: "primary" | "ghost" | "quiet" | "danger"; size?: "sm"; to?: string; state?: unknown; href?: string;
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const cls = cn("btn", variant !== "primary" && variant, size === "sm" && "sm", className);
  if (to) return <Link to={to} state={state} className={cls}>{children}</Link>;
  if (href) return <a href={href} className={cls} target="_blank" rel="noopener noreferrer">{children}</a>;
  return <button type="button" className={cls} {...rest}>{children}</button>;
}

export function Card({ title, icon, meta, actions, children, className }: {
  title?: ReactNode; icon?: ReactNode; meta?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={cn("card", className)}>
      {(title || actions) && (
        <div className="hd">
          {icon && <span className="ichip sm" aria-hidden="true">{icon}</span>}
          {title && <h2>{title}</h2>}
          {meta && <span className="meta">{meta}</span>}
          <span className="sp" />
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

// Severity: one red (critical) and greys. A Linear-like 4-bar meter plus a
// text label, so the level never relies on colour alone.
const SEV_LEVEL: Record<Severity, number> = { crit: 4, high: 3, med: 2, low: 1, info: 0 };
export function SevMeter({ sev }: { sev: Severity }) {
  const n = SEV_LEVEL[sev];
  return (
    <span className={cn("sevmeter", sev)} aria-hidden="true">
      {[1, 2, 3, 4].map((i) => <i key={i} className={i <= n ? "on" : ""} />)}
    </span>
  );
}
export function SeverityChip({ sev }: { sev: Severity }) {
  return (
    <span className={cn("chip", sev)} title={`Sévérité ${SEV_NAME[sev]}`}>
      <SevMeter sev={sev} />
      <span className="sr-only">Sévérité </span>{SEV_LABEL[sev]}
    </span>
  );
}

// proven = red (danger), lead = hollow grey ring, fixed = grey check.
export function StateBadge({ state }: { state: FindingState }) {
  const label = state === "proven" ? "prouvé" : state === "fixed" ? "corrigé" : "piste";
  return (
    <span className={cn("state", `is-${state}`)}>
      {state === "fixed" ? <Check size={12} strokeWidth={3} aria-hidden="true" /> : <span className="d" aria-hidden="true" />}
      {label}
    </span>
  );
}

// "Gardé" = a regression test in CI: the Arc UI Badge, success tone (Crenel amber).
export function GuardBadge({ label = "gardé" }: { label?: string }) {
  return <Badge size="sm" tone="success" icon={<ShieldCheck size={12} />}>{label}</Badge>;
}

export function Pill({ children, tone = "neutral", dot }: { children: ReactNode; tone?: "neutral" | "brand" | "danger"; dot?: boolean }) {
  return <span className={cn("pill", tone)}>{dot && <i className="pill-dot" aria-hidden="true" />}{children}</span>;
}

export function Dots() {
  return <span className="dots" aria-hidden="true"><i /><i /><i /></span>;
}

// Text shimmer for work in progress (after prompt-kit TextShimmer / AI Elements
// Shimmer, re-implemented in CSS; reduced motion shows plain text).
export function Shimmer({ children }: { children: ReactNode }) {
  return <span className="shimmer">{children}</span>;
}

export function EmptyState({ icon, title, children, action }: {
  icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode;
}) {
  return (
    <div className="empty">
      {icon}
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function ModelChip({ id }: { id: ModelId }) {
  const m = modelOf(id);
  return <span className="modelchip"><ModelLogo provider={m.provider} size={13} />{m.label}</span>;
}

export function EffortBars({ level }: { level: number }) {
  return (
    <span className="ebars" aria-hidden="true">
      {[1, 2, 3, 4].map((n) => <i key={n} className={n <= level ? "on" : ""} style={{ height: 4 + n * 2 }} />)}
    </span>
  );
}

export function Toggle({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-label={label} className={cn("switch", on && "on")} onClick={() => onChange(!on)}>
      <span className="knob" />
    </button>
  );
}

async function writeClipboard(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } finally { ta.remove(); }
  }
}

export function CopyButton({ text, label = "Copier", what = "la commande", iconOnly }: { text: string; label?: string; what?: string; iconOnly?: boolean }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1600);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <button type="button" className={cn("copybtn", done && "done", iconOnly && "icon")} onClick={async () => { await writeClipboard(text); setDone(true); }}
      aria-label={done ? "Copié" : `${label} ${what}`} title={`${label} ${what}`}>
      <span className="t-iconswap" data-state={done ? "b" : "a"} aria-hidden="true"><Copy size={13} className="ia" /><Check size={13} className="ib" /></span>
      {!iconOnly && <span>{done ? "Copié" : label}</span>}
      <span className="sr-only" aria-live="polite">{done ? "Copié dans le presse-papiers" : ""}</span>
    </button>
  );
}

export function Cmd({ children }: { children: string }) {
  return (
    <div className="cmd">
      <code><span className="k" aria-hidden="true">$</span> {children}</code>
      <CopyButton text={children} iconOnly />
    </div>
  );
}

// Code block with a file header and copy (after AI Elements CodeBlock).
export function CodeBlock({ file, code }: { file: string; code: string }) {
  return (
    <div className="codeblock">
      <div className="cb-hd"><FileCode2 size={13} aria-hidden="true" /><span className="mono">{file}</span><span className="sp" /><CopyButton text={code} what="le code" iconOnly /></div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

/* ---------- Period segment, delta, block bars, KPI tile ---------- */

// Period and filter switches: the Arc UI SegmentedControl (sliding thumb).
export function Segmented<T extends string>({ items, value, onChange, label }: {
  items: { id: T; label: string; count?: number }[]; value: T; onChange: (v: T) => void; label: string;
}) {
  return (
    <SegmentedControl label={label} value={value} onValueChange={(v: string) => onChange(v as T)}
      options={items.map((it) => ({ value: it.id, label: it.label, accessory: it.count !== undefined ? <span className="seg-n">{it.count}</span> : undefined }))} />
  );
}

export type Period = "7" | "30" | "90";
export const PERIODS: { id: Period; label: string }[] = [{ id: "7", label: "7 j" }, { id: "30", label: "30 j" }, { id: "90", label: "90 j" }];

// Delta pill. `bad` says whether a rise is bad news (more proven flaws): only
// bad news is red; everything else stays grey.
export function Delta({ value, bad, unit = "" }: { value: number; bad?: "up" | "down"; unit?: string }) {
  if (value === 0) return <span className="delta">stable</span>;
  const up = value > 0;
  const isBad = bad === "up" ? up : bad === "down" ? !up : false;
  return (
    <span className={cn("delta", isBad && "bad")}>
      {up ? <ArrowUpRight size={12} aria-hidden="true" /> : <ArrowDownRight size={12} aria-hidden="true" />}
      {up ? "+" : "−"}{Math.abs(value)}{unit}
    </span>
  );
}

// "Pixel" bars: each column is a stack of small blocks, unlit blocks drawn in
// the faintest grey. The last column is lit in the tile's tone.
export function BlockBars({ data, tone = "neutral", columns = 24 }: { data: number[]; tone?: "neutral" | "danger" | "brand"; columns?: number }) {
  const n = Math.min(columns, data.length);
  const per = data.length / n;
  const cols = Array.from({ length: n }, (_, i) => {
    let s = 0;
    for (let j = Math.floor(i * per); j < Math.floor((i + 1) * per); j++) s += data[j] ?? 0;
    return s;
  });
  const max = Math.max(1, ...cols);
  const rows = 7, bw = 4, gap = 2, bh = 3, vgap = 1.5;
  const W = n * (bw + gap) - gap, H = rows * (bh + vgap) - vgap;
  return (
    <svg className={cn("blockbars", tone)} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
      {cols.map((v, i) => {
        const lit = v > 0 ? Math.max(1, Math.round((v / max) * rows)) : 0;
        return Array.from({ length: rows }, (_, r) => {
          const on = r < lit;
          return <rect key={`${i}-${r}`} x={i * (bw + gap)} y={H - (r + 1) * bh - r * vgap} width={bw} height={bh} rx={0.8}
            className={on ? (i === n - 1 ? "hi" : "on") : "off"} />;
        });
      })}
    </svg>
  );
}

export function KpiTile({ label, icon, value, unit, delta, deltaUnit, bad, comparison, data, tone, to }: {
  label: string; icon: ReactNode; value: number | string; unit?: string; delta?: number; deltaUnit?: string; bad?: "up" | "down";
  comparison?: string; data?: number[]; tone?: "neutral" | "danger" | "brand"; to?: string;
}) {
  return (
    <section className="kpi">
      <div className="kpi-hd">
        <span className="ichip sm" aria-hidden="true">{icon}</span>
        {to ? <Link to={to} className="kpi-l stretched">{label}</Link> : <span className="kpi-l">{label}</span>}
      </div>
      <div className="kpi-in">
        <div className="kpi-v">
          <span className="kpi-n">{typeof value === "number" ? <AnimatedCounter value={value} /> : value}{unit && <small>{unit}</small>}</span>
          <span className="kpi-d">{delta !== undefined && <Delta value={delta} bad={bad} unit={deltaUnit} />}{comparison && <span className="kpi-c">{comparison}</span>}</span>
        </div>
        {data && <div className="kpi-g"><BlockBars data={data} tone={tone} /></div>}
      </div>
    </section>
  );
}

// Token gauge (after AI Elements Context): ring + percentage, detail in title.
export function ContextGauge({ used, total }: { used: number; total: number }) {
  const pct = Math.min(1, used / total);
  const r = 7, c = 2 * Math.PI * r;
  const k = (n: number) => `${(n / 1000).toLocaleString("fr-FR", { maximumFractionDigits: n < 10000 ? 1 : 0 })} k`;
  return (
    <span className="ctxgauge" title={`${k(used)} sur ${k(total)} tokens de contexte`}>
      <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
        <circle cx="9" cy="9" r={r} className="cg-track" />
        <circle cx="9" cy="9" r={r} className="cg-fill" strokeDasharray={`${c * pct} ${c}`} transform="rotate(-90 9 9)" />
      </svg>
      <span className="mono">{(Math.round(pct * 1000) / 10).toLocaleString("fr-FR")} %</span>
      <span className="sr-only">du contexte utilisé, {k(used)} sur {k(total)} tokens</span>
    </span>
  );
}

/* ---------- Picker: an accessible listbox popover ---------- */

export interface PickerOption<T extends string> { value: T; label: string; desc?: string; icon?: ReactNode; aside?: ReactNode }

export function Picker<T extends string>({ label, value, options, onChange, children, align = "left", placement = "down", footer, className, buttonClassName }: {
  label: string; value: T; options: PickerOption<T>[]; onChange: (v: T) => void; children: ReactNode;
  align?: "left" | "right"; placement?: "down" | "up"; footer?: ReactNode; className?: string; buttonClassName?: string;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const id = useId();
  const btnRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    setActive(Math.max(0, options.findIndex((o) => o.value === value)));
    listRef.current?.focus({ preventScroll: true });
    function onDown(e: MouseEvent) {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  function close(refocus = true) {
    setOpen(false);
    if (refocus) btnRef.current?.focus();
  }
  function pick(v: T) { onChange(v); close(); }

  function onKey(e: React.KeyboardEvent) {
    const n = options.length;
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => (a + 1) % n); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => (a - 1 + n) % n); }
    else if (e.key === "Home") { e.preventDefault(); setActive(0); }
    else if (e.key === "End") { e.preventDefault(); setActive(n - 1); }
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); const o = options[active]; if (o) pick(o.value); }
    else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === "Tab") { close(false); }
  }

  return (
    <div className={cn("picker", className)} ref={wrapRef}>
      <button
        ref={btnRef} type="button" className={cn("pickbtn", buttonClassName)}
        aria-haspopup="listbox" aria-expanded={open} aria-controls={open ? `${id}-list` : undefined}
        aria-label={label}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => { if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); setOpen(true); } }}
      >
        {children}
      </button>
      {open && (
        <div className={cn("pop", align === "right" && "right", placement === "up" && "up")}>
          <div className="pop-label" id={`${id}-label`}>{label}</div>
          <div
            ref={listRef} id={`${id}-list`} role="listbox" tabIndex={-1} aria-labelledby={`${id}-label`}
            aria-activedescendant={`${id}-opt-${active}`} onKeyDown={onKey} className="pop-list"
          >
            {options.map((o, i) => (
              <div
                key={o.value} id={`${id}-opt-${i}`} role="option" aria-selected={o.value === value}
                className={cn("pop-opt", i === active && "on")}
                onMouseEnter={() => setActive(i)} onClick={() => pick(o.value)}
              >
                {o.icon && <span className="pop-ic">{o.icon}</span>}
                <span className="pop-tx">
                  <span className="pop-l">{o.label}</span>
                  {o.desc && <span className="pop-d">{o.desc}</span>}
                </span>
                {o.aside}
                <Check size={14} className="pop-check" aria-hidden="true" />
              </div>
            ))}
          </div>
          {footer && <div className="pop-foot" onClick={() => setOpen(false)}>{footer}</div>}
        </div>
      )}
    </div>
  );
}

/* ---------- Activity list (icon chip, one sentence, grey meta) ---------- */

export function ActivityList({ items }: { items: { icon: ReactNode; title: string; meta: string; tone?: "danger" | "brand" }[] }) {
  return (
    <ul className="alist">
      {items.map((a, i) => (
        <li key={i}>
          <span className={cn("ichip", a.tone)} aria-hidden="true">{a.icon}</span>
          <div className="alist-tx"><span className="alist-t">{a.title}</span><span className="alist-m">{a.meta}</span></div>
        </li>
      ))}
    </ul>
  );
}

/* ---------- Tasks (agent runs), Codex-style list ---------- */

const STATUS_LABEL: Record<Task["status"], string> = {
  running: "en cours", waiting: "attend votre accord", done: "terminée", stopped: "interrompue",
};

export function TaskIcon({ status }: { status: Task["status"] }) {
  return (
    <span className={cn("task-ic", status)} aria-hidden="true">
      {status === "running" ? <Loader2 size={14} className="spin" />
        : status === "waiting" ? <Hand size={14} />
        : status === "done" ? <Check size={14} strokeWidth={2.5} />
        : <Square size={11} />}
    </span>
  );
}

export function TaskRow({ t }: { t: Task }) {
  const navigate = useNavigate();
  const toast = useToast();
  const { live } = useData();
  async function copyLink() {
    if (await copyText(linkTo(taskRoute(t.id)))) toast({ type: "success", title: "Lien de la tâche copié" });
    else toast({ type: "error", title: "Copie refusée par le navigateur", description: linkTo(taskRoute(t.id)) });
  }
  async function toggleArchive() {
    if (!live) { toast({ type: "info", title: t.archived ? "Désarchiver" : "Archiver", description: NEEDS_SERVER }); return; }
    try {
      await archiveRun(t.id, !t.archived);
      toast({ type: "success", title: t.archived ? "Tâche désarchivée" : "Tâche archivée" });
    } catch (err) {
      toast({ type: "error", title: t.archived ? "Désarchivage impossible" : "Archivage impossible", description: (err as Error).message });
    }
  }
  return (
    <li className="task">
      <TaskIcon status={t.status} />
      <div className="task-main">
        <Link to="/app/agent" state={{ taskId: t.id }} className="task-title stretched">{t.title}</Link>
        <div className="task-meta">
          <span className="sr-only">Statut: {STATUS_LABEL[t.status]}. </span>
          {t.status === "waiting" && <ShimmeringText text="attend votre accord" className="task-wait [--color:var(--brand-ink)] [--shimmering-color:var(--fg)]" />}
          <span className="mono">{t.target}</span><span>{t.trigger}</span><span>{t.when}</span>{t.dur && <span className="hide-sm">{t.dur}</span>}
        </div>
      </div>
      <div className="task-stats">
        {!!t.proven && <span className="st proven">+{t.proven} prouvé{t.proven > 1 ? "s" : ""}</span>}
        {!!t.fixed && <span className="st">{t.fixed} corrigé{t.fixed > 1 ? "s" : ""}</span>}
        {!!t.guarded && <span className="st guarded">{t.guarded} gardé{t.guarded > 1 ? "s" : ""}</span>}
        {!!t.leads && <span className="st hide-sm">{t.leads} piste{t.leads > 1 ? "s" : ""}</span>}
        {!t.proven && !t.fixed && !t.guarded && !t.leads && <span className="st">rien de neuf</span>}
      </div>
      <span className="task-menu">
        <DropdownMenu iconOnly label={`Actions pour ${t.title}`} icon={<MoreHorizontal size={16} />} items={[
          { label: "Rouvrir dans l'agent", icon: <RotateCcw size={14} />, onSelect: () => navigate("/app/agent", { state: { taskId: t.id } }) },
          { label: "Copier le lien", icon: <Link2 size={14} />, onSelect: () => void copyLink() },
          { label: t.archived ? "Désarchiver" : "Archiver", icon: <Archive size={14} />, separatorBefore: true, onSelect: () => void toggleArchive() },
        ]} />
      </span>
    </li>
  );
}

export function TaskList({ items }: { items: Task[] }) {
  return <ul className="tasks">{items.map((t) => <TaskRow key={t.id} t={t} />)}</ul>;
}
