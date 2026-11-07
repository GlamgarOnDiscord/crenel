// Effort control for the composer: a gauge glyph and a four-stop segmented
// track (radiogroup) whose thumb glides on a motion spring (Arc UI motion
// tokens), with "Plus rapide" / "Plus fin" captions as in the Codex composer.
import { motion, useReducedMotion } from "motion/react";
import { useId, useRef } from "react";
import { cn } from "../lib/utils";
import { EFFORTS, type EffortId } from "../lib/workspace";
import { motionTokens } from "./arc/lib/motion-tokens";
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
  const id = useId();
  const reduced = useReducedMotion();
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const idx = EFFORTS.findIndex((e) => e.id === value);
  const current = EFFORTS[idx]!;
  function move(to: number) {
    const n = Math.max(0, Math.min(EFFORTS.length - 1, to));
    onChange(EFFORTS[n]!.id);
    refs.current[n]?.focus();
  }
  return (
    <div className="effort">
      <div className="effort-hd">
        <EffortGauge level={current.level} size={20} />
        <span className="effort-l" id={`${id}-l`}>Effort</span>
        <span className="sp" />
        <TextMorph className="effort-v">{current.label}</TextMorph>
      </div>
      <div className="effort-track" role="radiogroup" aria-labelledby={`${id}-l`}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight" || e.key === "ArrowUp") { e.preventDefault(); move(idx + 1); }
          else if (e.key === "ArrowLeft" || e.key === "ArrowDown") { e.preventDefault(); move(idx - 1); }
          else if (e.key === "Home") { e.preventDefault(); move(0); }
          else if (e.key === "End") { e.preventDefault(); move(EFFORTS.length - 1); }
        }}>
        {EFFORTS.map((e, i) => {
          const on = e.id === value;
          return (
            <button key={e.id} ref={(el) => { refs.current[i] = el; }} type="button" role="radio" aria-checked={on} tabIndex={on ? 0 : -1}
              className={cn("effort-opt", on && "on", i < idx && "past")} onClick={() => onChange(e.id)}>
              {on && <motion.span layoutId={`${id}-thumb`} className="effort-thumb" transition={reduced ? { duration: 0 } : motionTokens.spring.snappy} />}
              <span className="effort-pips" aria-hidden="true">{[1, 2, 3, 4].map((p) => <i key={p} className={p <= e.level ? "f" : ""} />)}</span>
              <span className="effort-name">{e.label}</span>
            </button>
          );
        })}
      </div>
      <div className="effort-ends" aria-hidden="true"><span>Plus rapide</span><span>Plus fin</span></div>
    </div>
  );
}
