// Effort control for the composer, after the Codex model menu and taken
// further: "Plus rapide" / "Plus fin" captions frame the name of the current
// level (morphing on change), and a pill slider whose brand fill deepens as
// effort rises runs up to a light thumb, with a dot on each of the four stops.
// Hovering previews a stop (ghost thumb, its name in the caption) before the
// click commits it. A single role="slider": arrows, PageUp/PageDown, Home/End
// and pointer drag all snap to a stop.
import { useRef, useState, type CSSProperties, type PointerEvent as RPointerEvent } from "react";
import { cn } from "../lib/utils";
import { EFFORTS, type EffortId } from "../lib/workspace";
import { TextMorph } from "./kit/text-morph";

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
  const [dragging, setDragging] = useState(false);
  const [hover, setHover] = useState<number | null>(null);
  const last = EFFORTS.length - 1;
  const idx = Math.max(0, EFFORTS.findIndex((e) => e.id === value));
  const current = EFFORTS[idx]!;
  // A hovered stop other than the current one is a preview, not a choice.
  const preview = hover !== null && hover !== idx && !dragging ? hover : null;
  const shown = EFFORTS[preview ?? idx]!;
  function set(n: number) {
    const i = Math.max(0, Math.min(last, n));
    if (i !== idx) onChange(EFFORTS[i]!.id);
  }
  function stopAt(e: RPointerEvent<HTMLDivElement>) {
    const r = trackRef.current?.getBoundingClientRect();
    if (!r || r.width === 0) return null;
    return Math.max(0, Math.min(last, Math.round(((e.clientX - r.left) / r.width) * last)));
  }
  return (
    <div className="effort">
      <div className="effort-ends">
        <span aria-hidden="true">Plus rapide</span>
        <TextMorph className={cn("effort-now", preview !== null && "preview")}>{shown.label}</TextMorph>
        <span aria-hidden="true">Plus fin</span>
      </div>
      <div ref={trackRef} className={cn("eslider", dragging && "drag")} role="slider" tabIndex={0}
        aria-label="Effort" aria-valuemin={1} aria-valuemax={EFFORTS.length} aria-valuenow={current.level} aria-valuetext={current.label}
        style={{ "--f": idx / last, "--g": (preview ?? idx) / last, "--lv": current.level } as CSSProperties}
        onKeyDown={(e) => {
          const k = e.key;
          if (k === "ArrowRight" || k === "ArrowUp" || k === "PageUp") { e.preventDefault(); set(idx + 1); }
          else if (k === "ArrowLeft" || k === "ArrowDown" || k === "PageDown") { e.preventDefault(); set(idx - 1); }
          else if (k === "Home") { e.preventDefault(); set(0); }
          else if (k === "End") { e.preventDefault(); set(last); }
        }}
        onPointerDown={(e) => { setDragging(true); e.currentTarget.setPointerCapture?.(e.pointerId); const i = stopAt(e); if (i !== null) set(i); }}
        onPointerMove={(e) => { const i = stopAt(e); if (dragging) { if (i !== null) set(i); } else setHover(i); }}
        onPointerUp={() => setDragging(false)}
        onPointerCancel={() => setDragging(false)}
        onPointerLeave={() => setHover(null)}>
        <span className="eslider-fill" aria-hidden="true" />
        {EFFORTS.map((e, i) => (
          <span key={e.id} aria-hidden="true" className={cn("eslider-dot", i <= idx && "in", i === preview && "aim")} style={{ "--p": i / last } as CSSProperties} />
        ))}
        <span className={cn("eslider-ghost", preview !== null && "on")} aria-hidden="true" />
        <span className="eslider-thumb" aria-hidden="true" />
      </div>
    </div>
  );
}
