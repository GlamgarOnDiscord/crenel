import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Check, Copy, Hand, Loader2, ShieldCheck, Square } from "lucide-react";
import { cn } from "../lib/cn.ts";
import { SEV_LABEL, SEV_NAME, type FindingState, type Severity, type Task } from "../lib/types.ts";

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

export function Card({ title, meta, actions, children, className }: {
  title?: ReactNode; meta?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={cn("card", className)}>
      {(title || actions) && (
        <div className="hd">
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

export function SeverityChip({ sev }: { sev: Severity }) {
  return <span className={cn("chip", sev)} title={`Sévérité ${SEV_NAME[sev]}`}><span className="sr-only">Sévérité </span>{SEV_LABEL[sev]}</span>;
}

// proven = danger red (a proven flaw is bad news), lead = hollow slate ring,
// fixed = slate check. "Gardé" (test in CI) is the amber GuardBadge.
export function StateBadge({ state }: { state: FindingState }) {
  const label = state === "proven" ? "prouvé" : state === "fixed" ? "corrigé" : "piste";
  return (
    <span className={cn("state", state)}>
      {state === "fixed" ? <Check size={12} strokeWidth={3} aria-hidden="true" /> : <span className="d" aria-hidden="true" />}
      {label}
    </span>
  );
}

export function GuardBadge({ label = "gardé" }: { label?: string }) {
  return <span className="guard"><ShieldCheck size={12} aria-hidden="true" />{label}</span>;
}

export function Dots() {
  return <span className="dots" aria-hidden="true"><i /><i /><i /></span>;
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

// Neutral model pill: no provider logo, a plain glyph.
export function ModelChip({ name }: { name: string }) {
  return (
    <span className="modelchip">
      <span className="glyph" aria-hidden="true" />
      {name}
    </span>
  );
}

export function EffortBars({ level }: { level: number }) {
  return (
    <span className="ebars" aria-hidden="true">
      {[1, 2, 3, 4].map((n) => <i key={n} className={n <= level ? "on" : ""} style={{ height: 4 + n * 2.5 }} />)}
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

export function CopyButton({ text, label = "Copier" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1600);
    return () => clearTimeout(t);
  }, [done]);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } finally { ta.remove(); }
    }
    setDone(true);
  }
  return (
    <button type="button" className={cn("copybtn", done && "done")} onClick={copy} aria-label={done ? "Copié" : `${label} la commande`}>
      {done ? <Check size={13} /> : <Copy size={13} />}
      <span>{done ? "Copié" : label}</span>
      <span className="sr-only" aria-live="polite">{done ? "Commande copiée dans le presse-papiers" : ""}</span>
    </button>
  );
}

export function Cmd({ children, copy }: { children: string; copy?: boolean }) {
  return (
    <div className="cmd">
      <code><span className="k" aria-hidden="true">$</span> {children}</code>
      {copy && <CopyButton text={children} />}
    </div>
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
    listRef.current?.focus();
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
  return (
    <li className="task">
      <TaskIcon status={t.status} />
      <div className="task-main">
        <Link to="/app/agent" state={{ taskId: t.id }} className="task-title stretched">{t.title}</Link>
        <div className="task-meta">
          <span className="sr-only">Statut: {STATUS_LABEL[t.status]}. </span>
          {t.status === "waiting" && <span className="task-wait">attend votre accord</span>}
          <span className="mono">{t.target}</span><span>{t.trigger}</span><span>{t.when}</span>{t.dur && <span className="hide-sm">{t.dur}</span>}
        </div>
      </div>
      <div className="task-stats">
        {!!t.proven && <span className="st proven">+{t.proven} prouvé{t.proven > 1 ? "s" : ""}</span>}
        {!!t.fixed && <span className="st fixed">{t.fixed} corrigé{t.fixed > 1 ? "s" : ""}</span>}
        {!!t.guarded && <span className="st guarded">{t.guarded} gardé{t.guarded > 1 ? "s" : ""}</span>}
        {!!t.leads && <span className="st lead hide-sm">{t.leads} piste{t.leads > 1 ? "s" : ""}</span>}
        {!t.proven && !t.fixed && !t.guarded && !t.leads && <span className="st lead">rien de neuf</span>}
      </div>
    </li>
  );
}

export function TaskList({ items }: { items: Task[] }) {
  return <ul className="tasks">{items.map((t) => <TaskRow key={t.id} t={t} />)}</ul>;
}
