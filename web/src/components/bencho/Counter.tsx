/* Ported from Bencho (https://bencho.dev, github.com/cabralorenzo/bencho), MIT License, Copyright (c) 2026 Lorenzo Cabra.
   Adapted for Crenel: French copy, Crenel data and tokens (see .bencho in base.css), motion/react. */
import { useEffect, useRef, useState } from "react";
import { Minus, Plus } from "lucide-react";

/* ══ Rolling counter ══════════════════════════════════════
   A number between a minus and a plus. Every digit is a strip
   of 0–9 behind a window, and changing the number rolls the
   strips to their new digits like an odometer.

   ── EACH COLUMN COUNTS, IT DOES NOT SHOW ───────────────
   A column's target is not its digit but the number of whole
   tens, hundreds… in the value: 1284 is 1284 for the ones
   column, 128 for the tens, 12 for the hundreds. So 9 → 10 is
   the ones column moving FORWARD one more step (9 → 0) and the
   tens moving forward one — never a strip running back down
   through eight digits to reach zero. The strip is 0–9 and a
   second 0, and where it sits is the count taken round ten.

   ── ONE SPRING PER COLUMN, AND THEY GO IN TURN ─────────
   A change reaches the ones first and each column to the left
   a little later — Stagger — so a carry reads as a carry,
   rippling up the number, rather than the whole row jumping.

   ── THREE WAYS TO CHANGE IT ────────────────────────────
   Press a button for one step; hold it and it repeats, faster
   and in bigger steps the longer you hold. Or take the number
   itself and drag it up or down, a step every few pixels; let
   go while it is moving and it keeps rolling and runs down. */

/* ── inlined from lab/spring ──────────────────────── */
/* ── one spring, for everything that settles ───────────────
   The maths was already on this bench twice, copied by hand:
   Humidity's wheel and Brightness's column both accumulate
   velocity toward a target, damp it, and snap when both the
   delta and the velocity fall under 0.02. Two copies is a
   coincidence; five would be a policy, so it comes out here
   before the elastic blocks are written against it.

   The two shipped copies are deliberately NOT refactored onto
   this. They work, they are tuned, and rewriting the innards
   of two live components to prove a point about duplication
   is how a good afternoon becomes a bad one. This is the one
   new code uses.

   Frames, not milliseconds. `dt` is expressed in sixtieths of
   a second and the damping is RAISED to it rather than
   multiplied by it, so a dropped frame decays the same amount
   of energy as the two frames it replaced. Multiplying is the
   version that makes a spring behave differently on a busy
   page, which is the hardest kind of bug to see.

   The loop parks itself the moment the value has settled.
   CLAUDE.md is not complimentary about the one permanent
   requestAnimationFrame already on this bench and there is no
   case for five more. */

/* 0..100 into the two numbers a spring actually has.

   50 is what Humidity and Brightness were tuned at, which is
   the rule every elastic knob on this bench follows — see
   lab/motion. Turn the panel to the middle and nothing has
   changed.

   Both ends have to be usable, which is what fixes the range:
   at 0 it is slow and heavy and still arrives, at 100 it is
   quick with a visible overshoot, and nowhere in between does
   it ring for longer than it takes to read. */
/* The pair is chosen by DAMPING RATIO and then written back
   as stiffness and decay, because the ratio is the thing a
   person is actually setting and the two numbers on their own
   do not say what they add up to.

     zeta = -ln(d) / (2 * sqrt(k))

   The first version of this ran 0.06..0.26 stiffness against
   0.93..0.74 decay, which reads as a sensible spread and is
   not one: it puts zeta between 0.15 and 0.16 across the
   WHOLE range, so every setting overshot by about sixty per
   cent and the knob only changed how fast it did it. Pull's
   return went 130px past its own resting position and lifted
   the content off the top of the card.

     0   → zeta ~0.85, heavy, arrives without a ring
     50  → zeta ~0.41, near where Humidity and Brightness sit
     100 → zeta ~0.20, lively, two visible rebounds

   Both ends shippable, which is the constraint that fixed the
   numbers rather than taste. */
const springOf = (tune: number) => ({
  /* stiffness: how hard it is pulled toward the target */
  k: 0.08 + (tune / 100) * 0.16,
  /* decay, per frame: how much of the velocity survives */
  d: 0.62 + (tune / 100) * 0.2,
});

/* Read once, the way the wheel and the pill nav do. A
   preference, not a live input. */
const stillness = () =>
  typeof window !== "undefined" &&
  !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

const PLACES = 5;
const MAX = 10 ** PLACES - 1;
/* the window a digit is seen through, and the type in it */
const CELL = 46;
/* a step of drag, px */
const PX = 12;
/* the slab's inset round the buttons */
const PAD = 5;
/* the buttons are upright keys the full height of the inside of
   the box, the same height as the window the digits roll in, so
   every edge of the box is the same 5px from something */
const BTN = CELL;
const H = BTN + PAD * 2;

const clamp = (v: number, a: number, b: number) => Math.min(b, Math.max(a, v));

type Col = { pos: number; vel: number; target: number; due: number[]; next: number[] };

export function Counter({
  /* how lively a digit lands, 0..100 */
  bounce = 45,
  /* ms between one column moving and the next, 0..120 */
  stagger = 45,
  /* how much a spinning digit smears, 0..100 */
  blur = 50,
  /* the slab's corner, px */
  corner = 16,
  start = 95,
  min = 0,
  max,
  label = "Valeur",
  onChange,
}: {
  bounce?: number;
  stagger?: number;
  blur?: number;
  corner?: number;
  start?: number;
  min?: number;
  max?: number;
  label?: string;
  onChange?: (value: number) => void;
} = {}) {
  const still = stillness();
  const [value, setValue] = useState(start);
  const val = useRef(start);
  const strips = useRef<(HTMLDivElement | null)[]>([]);
  const cols = useRef<Col[]>(
    Array.from({ length: PLACES }, (_, p) => {
      const n = Math.floor(start / 10 ** p);
      return { pos: n, vel: 0, target: n, due: [], next: [] };
    }),
  );
  const raf = useRef(0);
  const knobs = useRef({ bounce, stagger, blur });
  knobs.current = { bounce, stagger, blur };

  /* ── paint ─────────────────────────────────────────────── */
  const paint = () => {
    cols.current.forEach((c, p) => {
      const el = strips.current[p];
      if (!el) return;
      const m = ((c.pos % 10) + 10) % 10;
      const smear = Math.min(3, Math.abs(c.vel) * 2.4) * (knobs.current.blur / 50);
      el.style.transform = `translateY(${-m * CELL}px)`;
      el.style.filter = smear > 0.15 ? `blur(${smear.toFixed(2)}px)` : "";
    });
  };

  const run = () => {
    if (raf.current) return;
    let prev = 0;
    const tick = (t: number) => {
      const dt = prev ? clamp((t - prev) / 16.67, 0, 2.5) : 1;
      prev = t;
      const { k, d } = springOf(knobs.current.bounce);
      const now = performance.now();
      let busy = false;
      for (const c of cols.current) {
        /* targets that have waited their turn */
        while (c.due.length && c.due[0] <= now) {
          c.due.shift();
          c.target = c.next.shift()!;
        }
        if (c.due.length) busy = true;
        /* a column far from home jumps most of the way in whole
           turns first — it looks the same, and a flick does not
           leave the ones column spinning for a second */
        const gap = c.target - c.pos;
        if (Math.abs(gap) > 24) c.pos += Math.round((gap - Math.sign(gap) * 24) / 10) * 10;
        c.vel += (c.target - c.pos) * k * dt;
        c.vel *= Math.pow(d, dt);
        c.pos += c.vel * dt;
        if (Math.abs(c.target - c.pos) < 0.004 && Math.abs(c.vel) < 0.004) {
          c.pos = c.target;
          c.vel = 0;
        } else busy = true;
      }
      paint();
      raf.current = busy ? requestAnimationFrame(tick) : 0;
    };
    raf.current = requestAnimationFrame(tick);
  };

  useEffect(() => { paint(); }, [blur]);
  useEffect(() => () => { cancelAnimationFrame(raf.current); raf.current = 0; }, []);

  /* ── the one way the number changes ────────────────────── */
  const bump = (n: number) => {
    const v = clamp(val.current + n, min, max ?? MAX);
    if (v === val.current) return;
    val.current = v;
    setValue(v);
    onChange?.(v);
    const now = performance.now();
    cols.current.forEach((c, p) => {
      const to = Math.floor(v / 10 ** p);
      if (still) {
        c.pos = c.target = to;
        c.vel = 0;
        c.due = [];
        c.next = [];
        return;
      }
      c.due.push(now + p * knobs.current.stagger);
      c.next.push(to);
    });
    if (still) paint();
    else run();
  };

  /* ── holding a button ──────────────────────────────────── */
  const hold = useRef({ t: 0, since: 0 });
  const release = () => {
    clearTimeout(hold.current.t);
    hold.current.t = 0;
  };
  useEffect(() => release, []);
  const press = (dir: 1 | -1) => {
    release();
    bump(dir);
    hold.current.since = performance.now();
    const repeat = () => {
      const held = performance.now() - hold.current.since;
      /* ones, then tens after a second and a half */
      bump(dir * (held > 1500 ? 10 : 1));
      hold.current.t = window.setTimeout(repeat, held > 900 ? 55 : 90);
    };
    hold.current.t = window.setTimeout(repeat, 380);
  };

  /* ── taking the number itself ──────────────────────────── */
  const drag = useRef<{ y: number; acc: number; v: number; t: number } | null>(null);
  const fling = useRef(0);
  useEffect(() => () => cancelAnimationFrame(fling.current), []);
  const steps = (acc: number) => {
    const n = acc > 0 ? Math.floor(acc / PX) : Math.ceil(acc / PX);
    if (n) bump(n);
    return acc - n * PX;
  };

  const onDown = (e: React.PointerEvent) => {
    cancelAnimationFrame(fling.current);
    try { e.currentTarget.setPointerCapture(e.pointerId); } catch { /* a scripted pointer */ }
    drag.current = { y: e.clientY, acc: 0, v: 0, t: performance.now() };
  };
  const onMove = (e: React.PointerEvent) => {
    const g = drag.current;
    if (!g) return;
    const now = performance.now();
    /* up is more */
    const dy = g.y - e.clientY;
    g.y = e.clientY;
    const dt = Math.max(1, now - g.t);
    g.t = now;
    g.v = g.v * 0.6 + (dy / dt) * 0.4;
    g.acc = steps(g.acc + dy);
  };
  const onUp = (e: React.PointerEvent) => {
    const g = drag.current;
    drag.current = null;
    try { e.currentTarget.releasePointerCapture(e.pointerId); } catch { /* never captured */ }
    if (!g || still) return;
    /* a hand that stopped before letting go threw nothing */
    let v = performance.now() - g.t > 90 ? 0 : g.v * 16.67;
    if (Math.abs(v) < 2) return;
    let acc = g.acc;
    const coast = () => {
      acc = steps(acc + v);
      v *= 0.94;
      if (Math.abs(v) > 0.4) fling.current = requestAnimationFrame(coast);
    };
    fling.current = requestAnimationFrame(coast);
  };

  const shown = Math.max(1, String(value).length);
  const r = clamp(corner, 0, H / 2);
  const inner = Math.max(0, r - PAD);

  return (
    <div
      className="rct"
      style={{ "--rct-r": `${r}px`, "--rct-in": `${inner}px`, "--rct-cell": `${CELL}px` } as React.CSSProperties}
    >
      <button
        type="button"
        className="rct-btn"
        aria-label="Moins"
        onPointerDown={() => press(-1)}
        onPointerUp={release}
        onPointerLeave={release}
        onPointerCancel={release}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); bump(-1); } }}
      >
        <Minus size={16} strokeWidth={2.2} />
      </button>

      <div
        className="rct-num"
        role="spinbutton"
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={max ?? MAX}
        aria-label={`${label}. Glissez vers le haut ou le bas pour la changer.`}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "ArrowUp") { e.preventDefault(); bump(1); }
          if (e.key === "ArrowDown") { e.preventDefault(); bump(-1); }
        }}
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={onUp}
        onPointerCancel={onUp}
      >
        {Array.from({ length: PLACES }, (_, i) => {
          const p = PLACES - 1 - i;
          return (
            <span key={p} className="rct-pair">
              <span className="rct-col" data-on={p < shown || undefined}>
                <span className="rct-strip" ref={(el) => { strips.current[p] = el as HTMLDivElement | null; }}>
                  {[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0].map((d, j) => <span key={j}>{d}</span>)}
                </span>
              </span>
              {p === 3 && <span className="rct-sep" data-on={shown > 3 || undefined}>,</span>}
            </span>
          );
        })}
      </div>

      <button
        type="button"
        className="rct-btn"
        aria-label="Plus"
        onPointerDown={() => press(1)}
        onPointerUp={release}
        onPointerLeave={release}
        onPointerCancel={release}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); bump(1); } }}
      >
        <Plus size={16} strokeWidth={2.2} />
      </button>
    </div>
  );
}
