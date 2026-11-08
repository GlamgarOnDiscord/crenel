// Effort control for the composer. Started from the Codex model menu and
// pushed further: instead of a plain track, a ramp of thin bars (short on the
// "Plus rapide" side, tall on the "Plus fin" side) lights up to a glowing
// cursor. One spring-driven value (--x, 0..1) feeds every bar through CSS, so
// the fill flows continuously: the cursor follows the pointer while dragging,
// then snaps to the nearest of the four stops with a slight overshoot. A
// light wave runs through the lit bars, faster as effort rises; each change
// sends a ripple from the cursor. Hovering previews a stop (its name in the
// caption, its tick lit) before a click commits it. A single role="slider":
// arrows, PageUp/PageDown, Home/End and pointer drag. Reduced motion: no
// spring, no wave, no ripple.
import { AnimatePresence, motion, useMotionValue, useReducedMotion, useSpring } from "motion/react";
import { useEffect, useRef, useState, type CSSProperties, type PointerEvent as RPointerEvent } from "react";
import { cn } from "../lib/utils";
import { EFFORTS, type EffortId } from "../lib/workspace";
import { TextMorph } from "./kit/text-morph";

const BARS = 32;
const BAR_T = Array.from({ length: BARS }, (_, i) => i / (BARS - 1));

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
  const areaRef = useRef<HTMLDivElement | null>(null);
  const reduced = useReducedMotion();
  const [dragging, setDragging] = useState(false);
  const [hover, setHover] = useState<number | null>(null);
  const last = EFFORTS.length - 1;
  const idx = Math.max(0, EFFORTS.findIndex((e) => e.id === value));
  const current = EFFORTS[idx]!;
  const preview = hover !== null && hover !== idx && !dragging ? hover : null;
  const shown = EFFORTS[preview ?? idx]!;

  // Raw target (stop, or pointer while dragging) and its spring-smoothed twin.
  const target = useMotionValue(idx / last);
  const x = useSpring(target, reduced ? { duration: 0 } : { stiffness: 420, damping: 30, mass: 0.7 });
  useEffect(() => { if (!dragging) target.set(idx / last); }, [idx, last, dragging, target]);

  // Ripple key: bumps on every committed change (not on first paint).
  const [pulse, setPulse] = useState(0);
  const prev = useRef(idx);
  useEffect(() => { if (prev.current !== idx) { prev.current = idx; setPulse((p) => p + 1); } }, [idx]);

  function set(n: number) {
    const i = Math.max(0, Math.min(last, n));
    if (i !== idx) onChange(EFFORTS[i]!.id);
  }
  function frac(e: RPointerEvent<HTMLDivElement>) {
    const r = areaRef.current?.getBoundingClientRect();
    if (!r || r.width === 0) return null;
    return Math.max(0, Math.min(1, (e.clientX - r.left) / r.width));
  }
  return (
    <div className={cn("effort", dragging && "drag")} style={{ "--lv": current.level } as CSSProperties}>
      <div className="effort-ends">
        <span aria-hidden="true">Plus rapide</span>
        <TextMorph className={cn("effort-now", preview !== null && "preview")}>{shown.label}</TextMorph>
        <span aria-hidden="true">Plus fin</span>
      </div>
      <div className="eq" role="slider" tabIndex={0}
        aria-label="Effort" aria-valuemin={1} aria-valuemax={EFFORTS.length} aria-valuenow={current.level} aria-valuetext={current.label}
        onKeyDown={(e) => {
          const k = e.key;
          if (k === "ArrowRight" || k === "ArrowUp" || k === "PageUp") { e.preventDefault(); set(idx + 1); }
          else if (k === "ArrowLeft" || k === "ArrowDown" || k === "PageDown") { e.preventDefault(); set(idx - 1); }
          else if (k === "Home") { e.preventDefault(); set(0); }
          else if (k === "End") { e.preventDefault(); set(last); }
        }}
        onPointerDown={(e) => {
          const f = frac(e); if (f === null) return;
          setDragging(true); e.currentTarget.setPointerCapture?.(e.pointerId);
          target.set(f); set(Math.round(f * last));
        }}
        onPointerMove={(e) => {
          const f = frac(e); if (f === null) return;
          if (dragging) { target.set(f); set(Math.round(f * last)); } else setHover(Math.round(f * last));
        }}
        onPointerUp={() => setDragging(false)}
        onPointerCancel={() => setDragging(false)}
        onPointerLeave={() => setHover(null)}>
        <motion.div ref={areaRef} className="eq-area" style={{ "--x": x } as unknown as CSSProperties}>
          <div className="eq-bars" aria-hidden="true">
            {BAR_T.map((t, i) => (
              <span key={i} className="eq-bar" style={{ "--t": t, "--i": i } as CSSProperties}><i /></span>
            ))}
          </div>
          <span className="eq-cursor" aria-hidden="true" />
          <AnimatePresence>
            {pulse > 0 && !reduced && (
              <motion.span key={pulse} className="eq-ripple" aria-hidden="true" style={{ left: `${(idx / last) * 100}%` }}
                initial={{ scale: 0.3, opacity: 0.7 }} animate={{ scale: 3.2, opacity: 0 }} exit={{ opacity: 0 }}
                transition={{ duration: 0.6, ease: [0.2, 0.8, 0.2, 1] }} />
            )}
          </AnimatePresence>
        </motion.div>
        <div className="eq-stops" aria-hidden="true">
          {EFFORTS.map((e, i) => (
            <span key={e.id} className={cn("eq-stop", i === idx && "on", i < idx && "past", i === preview && "aim")} style={{ "--p": i / last } as CSSProperties}>
              <b />{e.label}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
