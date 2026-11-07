import type { ReactNode } from "react";
import { cn } from "../lib/cn.ts";
import type { FindingState, Severity } from "../lib/types.ts";

export function Button({ children, variant = "primary", size, ...rest }: {
  children: ReactNode; variant?: "primary" | "ghost"; size?: "sm";
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button className={cn("btn", variant === "ghost" && "ghost", size === "sm" && "sm")} {...rest}>
      {children}
    </button>
  );
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
  return <span className={cn("chip", sev)}>{sev}</span>;
}

export function StateBadge({ state }: { state: FindingState }) {
  const label = state === "proven" ? "prouvé" : state === "fixed" ? "corrigé" : "lead";
  return (
    <span className={cn("state", state === "proven" && "proven", state === "fixed" && "fixed")}>
      <span className="d" />
      {label}
    </span>
  );
}

export function Dots() {
  return <span className="dots"><i /><i /><i /></span>;
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

// Smooth sparkline used in KPI tiles.
export function Sparkline({ points, color = "var(--brand)", glow = true }: {
  points: number[]; color?: string; glow?: boolean;
}) {
  const w = 160, h = 30;
  if (points.length < 2) points = [points[0] ?? 0, points[0] ?? 0];
  const max = Math.max(...points), min = Math.min(...points);
  const span = max - min || 1;
  const d = points
    .map((p, i) => `${(i / (points.length - 1)) * w},${h - 2 - ((p - min) / span) * (h - 4)}`)
    .join(" L ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" fill="none" aria-hidden="true">
      <path d={`M ${d}`} stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
        style={glow ? { filter: `drop-shadow(0 0 4px color-mix(in oklab, ${color} 55%, transparent))` } : undefined} />
    </svg>
  );
}

// Stacked bars (proven at the base, leads above), with the peak day lit.
export function Bars({ proven, leads }: { proven: number[]; leads: number[] }) {
  const L = 44, R = 708, T = 30, B = 174, MAX = 20, n = proven.length;
  const step = (R - L) / n, bw = Math.min(28, step - 10);
  const y = (v: number) => B - (v / MAX) * (B - T);
  let peak = 0;
  for (let i = 0; i < n; i++) if (proven[i] + leads[i] > proven[peak] + leads[peak]) peak = i;
  return (
    <svg viewBox="0 0 720 220" role="img" aria-label="Findings par jour, barres empilées">
      {[0, 7, 14, 20].map((v) => (
        <g key={v}>
          <line x1={L} y1={y(v)} x2={R} y2={y(v)} stroke="var(--line)" strokeWidth="1" />
          <text x={8} y={y(v) + 4} fill="var(--fg-ghost)" fontFamily="var(--f-mono)" fontSize="11">{v}</text>
        </g>
      ))}
      {["J-14", "J-7", "auj."].map((lab, i) => (
        <text key={lab} x={L + i * ((R - L) / 2) - (i === 2 ? 24 : 0)} y={196} fill="var(--fg-ghost)" fontFamily="var(--f-mono)" fontSize="11">{lab}</text>
      ))}
      {proven.map((pv, i) => {
        const cx = L + i * step + step / 2, x = cx - bw / 2;
        const dim = i === peak ? 1 : 0.82;
        const yP = y(pv), yTop = y(pv + leads[i]);
        return (
          <g key={i} opacity={dim}>
            {pv > 0 && <rect x={x} y={yP} width={bw} height={B - yP} rx="2" fill="var(--crit)" />}
            <path d={`M${x},${yP} L${x},${yTop + 4} Q${x},${yTop} ${x + 4},${yTop} L${x + bw - 4},${yTop} Q${x + bw},${yTop} ${x + bw},${yTop + 4} L${x + bw},${yP} Z`} fill="var(--brand)" />
            {i === peak && (
              <g opacity={1}>
                <rect x={cx - 16} y={yTop - 24} width="32" height="18" rx="9" fill="var(--panel-raised)" stroke="var(--line-strong)" />
                <text x={cx} y={yTop - 11} fill="var(--fg)" fontFamily="var(--f-mono)" fontSize="11" textAnchor="middle">{pv + leads[i]}</text>
              </g>
            )}
          </g>
        );
      })}
    </svg>
  );
}

// Neutral model chip (provider marks are trademarked; we keep a neutral glyph).
export function ModelChip({ name }: { name: string }) {
  return (
    <span className="modelchip">
      <svg className="glyph" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6" stroke="var(--brand-ink)" strokeWidth="1.5" /><circle cx="8" cy="8" r="2" fill="var(--brand-ink)" /></svg>
      {name}
    </span>
  );
}
