// Effort control for the composer, recreated from the Codex model menu:
// "Plus rapide" / "Plus fin" captions over a pill slider whose brand fill
// runs up to a light thumb, with a dot on each of the four stops. It is a
// single role="slider": arrows, Home/End and pointer drag all snap to a stop.
import { useRef, type CSSProperties, type PointerEvent as RPointerEvent } from "react";
import { cn } from "../lib/utils";
import { EFFORTS, type EffortId } from "../lib/workspace";

// Half-ring gauge: a track arc and an amber arc that grows with the level.
export function EffortGauge({ level, size = 16, tone = "brand" }: { level: number; size?: number; tone?: "brand" | "muted" }) {
  const r = 7, cx = 9, cy = 12, len = Math.PI * r;
  const f = Math.max(0, Math.min(1, level / 4));
  const a = Math.PI * (1 - f);
  const nx = cx + r * Math.cos(a), ny = cy - r * Math.sin(a);
  return (
    <svg className={cn("egauge", `eg-${tone}`)} width={size} height={size} viewBox="0 0 18 18" aria-hidden="true">
      <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} className="eg-track" />
      <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} className="eg-fill" strokeDasharray={`${len} ${len}`} strokeDashoffset={len * (1 - f)} />
      <circle cx={nx} cy={ny} r="1.9" className="eg-dot" />
      <line x1={cx} y1={cy} x2={cx + (nx - cx) * .62} y2={cy + (ny - cy) * .62} className="eg-needle" /><circle cx={cx} cy={cy} r="1.3" className="eg-hub" />
    </svg>
  );
}

export function EffortControl({ value, onChange }: { value: EffortId; onChange: (v: EffortId) => void }) {
  const trackRef = useRef<HTMLDivElement | null>(null);
  const dragging = useRef(false);
  const last = EFFORTS.length - 1;
  const idx = Math.max(0, EFFORTS.findIndex((e) => e.id === value));
  const current = EFFORTS[idx]!;
  function set(n: number) {
    const i = Math.max(0, Math.min(last, n));
    if (i !== idx) onChange(EFFORTS[i]!.id);
  }
  function fromPointer(e: RPointerEvent<HTMLDivElement>) {
    const r = trackRef.current?.getBoundingClientRect();
    if (!r || r.width === 0) return;
    set(Math.round(((e.clientX - r.left) / r.width) * last));
  }
  return (
    <div className="effort">
      <div className="effort-ends" aria-hidden="true"><span>Plus rapide</span><span>Plus fin</span></div>
      <div ref={trackRef} className="eslider" role="slider" tabIndex={0}
        aria-label="Effort" aria-valuemin={1} aria-valuemax={EFFORTS.length} aria-valuenow={current.level} aria-valuetext={current.label}
        style={{ "--f": idx / last } as CSSProperties}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight" || e.key === "ArrowUp") { e.preventDefault(); set(idx + 1); }
          else if (e.key === "ArrowLeft" || e.key === "ArrowDown") { e.preventDefault(); set(idx - 1); }
          else if (e.key === "Home") { e.preventDefault(); set(0); }
          else if (e.key === "End") { e.preventDefault(); set(last); }
        }}
        onPointerDown={(e) => { dragging.current = true; e.currentTarget.setPointerCapture?.(e.pointerId); fromPointer(e); }}
        onPointerMove={(e) => { if (dragging.current) fromPointer(e); }}
        onPointerUp={() => { dragging.current = false; }}
        onPointerCancel={() => { dragging.current = false; }}>
        <span className="eslider-fill" aria-hidden="true" />
        {EFFORTS.map((e, i) => (
          <span key={e.id} aria-hidden="true" className={cn("eslider-dot", i <= idx && "in")} style={{ "--p": i / last } as CSSProperties} />
        ))}
        <span className="eslider-thumb" aria-hidden="true" />
      </div>
    </div>
  );
}
