/* Interactive isometric figures for the landing, built with the iso-figure
   method (github.com/MrBongoC/ai-iso-skill, MIT): every part is a flat SVG
   shape placed on a 3D plane by one matrix(), objects are boxes drawn as
   their three visible faces in back-to-front paint order, interaction is one
   state object and class toggles, motion is CSS. Hairline monochrome, with
   Crenel's amber reserved for whatever is live. The figure does something
   real when pressed: each request answers, and three of them make a proof.
   Keyboard works once the figure has focus. */
import { useCallback, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { cn } from "../../lib/utils";

// ---------- Kernel (iso-figure, adapted to TSX) ----------
type B6 = readonly [number, number, number, number, number, number]; // x, y, z, w, d, h
const C = Math.cos(Math.PI / 6), S = Math.sin(Math.PI / 6);
const P = (x: number, y: number, z: number): [number, number] => [(x - y) * C, (x + y) * S - z];
const plane = (O: [number, number, number], U: [number, number, number], V: [number, number, number]) => {
  const o = P(...O), u = P(...U), v = P(...V);
  return `matrix(${u[0]} ${u[1]} ${v[0]} ${v[1]} ${o[0]} ${o[1]})`;
};
const TOP = (x: number, y: number, z: number) => plane([x, y, z], [1, 0, 0], [0, 1, 0]);
const FRONT = (x: number, y: number, z: number) => plane([x, y, z], [1, 0, 0], [0, 0, -1]);
const SIDE = (x: number, y: number, z: number) => plane([x, y, z], [0, -1, 0], [0, 0, -1]);

function Box({ b, r = 0, cls }: { b: B6; r?: number; cls?: string }) {
  const [x, y, z, w, d, h] = b;
  const rs = Math.min(r, h / 4);
  return (
    <>
      <g transform={SIDE(x + w, y + d, z + h)}><rect className={cn("face", cls)} width={d} height={h} rx={rs} /></g>
      <g transform={FRONT(x, y + d, z + h)}><rect className={cn("face", cls)} width={w} height={h} rx={rs} /></g>
      <g transform={TOP(x, y, z + h)}><rect className={cn("face top", cls)} width={w} height={d} rx={r} /></g>
    </>
  );
}

// viewBox from the scene's extreme corners, with a margin on every side.
function frame(boxes: B6[], margin = 0.1) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const [x, y, z, w, d, h] of boxes)
    for (const cx of [x, x + w]) for (const cy of [y, y + d]) for (const cz of [z, z + h]) {
      const [sx, sy] = P(cx, cy, cz);
      x0 = Math.min(x0, sx); y0 = Math.min(y0, sy); x1 = Math.max(x1, sx); y1 = Math.max(y1, sy);
    }
  const mx = (x1 - x0) * margin, my = (y1 - y0) * margin;
  return `${(x0 - mx).toFixed(1)} ${(y0 - my).toFixed(1)} ${(x1 - x0 + 2 * mx).toFixed(1)} ${(y1 - y0 + 2 * my).toFixed(1)}`;
}

// A part flashes "down" for a moment when pressed.
function useFlash() {
  const [down, setDown] = useState<string | null>(null);
  const t = useRef<ReturnType<typeof setTimeout>>();
  const flash = useCallback((k: string) => {
    setDown(k); clearTimeout(t.current); t.current = setTimeout(() => setDown(null), 120);
  }, []);
  return [down, flash] as const;
}

function Key({ b, r = 5, down, on, onPress, children, label }: {
  b: B6; r?: number; down?: boolean; on?: boolean; onPress: () => void; children?: ReactNode; label: string;
}) {
  return (
    <g className={cn("press", down && "down", on && "on")} role="button" aria-label={label}
      onPointerDown={(e) => { e.preventDefault(); onPress(); }}>
      <Box b={b} r={r} />
      {children}
    </g>
  );
}

function Plate({ fig, name, hint, readout, viewBox, label, onKey, children }: {
  fig: number; name: string; hint: string; readout: string; viewBox: string; label: string;
  onKey: (k: string) => boolean; children: ReactNode;
}) {
  function keydown(e: KeyboardEvent<SVGSVGElement>) {
    if (e.metaKey || e.ctrlKey || e.altKey || e.repeat) return;
    if (onKey(e.key.length === 1 ? e.key.toLowerCase() : e.key)) e.preventDefault();
  }
  return (
    <figure className="iso">
      <div className="iso-cap"><span className="hi">Fig {fig}</span><span>{name}</span></div>
      <svg viewBox={viewBox} tabIndex={0} role="img" aria-label={label} onKeyDown={keydown}>{children}</svg>
      <div className="iso-cap"><span>{hint}</span><span className="hi" aria-live="polite">{readout}</span></div>
    </figure>
  );
}

// ---------- Fig 1 · Proof bench: three requests make a proof ----------
const F1 = {
  slab: [0, 0, 0, 300, 200, 14] as B6,
  screen: [16, 12, 14, 268, 22, 112] as B6,
  keys: [
    { k: "b", b: [18, 120, 14, 78, 56, 12] as B6, glyph: "B", cap: "PROPRIO", line: "B lit proj_b_1 → 200" },
    { k: "a", b: [111, 120, 14, 78, 56, 12] as B6, glyph: "A", cap: "ATTAQUANT", line: "A lit proj_b_1 → 200" },
    { k: "0", b: [204, 120, 14, 78, 56, 12] as B6, glyph: "∅", cap: "ANONYME", line: "anon lit proj_b_1 → 401" },
  ],
};
const F1_VB = frame([F1.slab, F1.screen, ...F1.keys.map((k) => k.b)]);

export function ProofBenchFigure() {
  const [log, setLog] = useState<string[]>([]);
  const [st, setSt] = useState({ a: 0, b: false, n: false, done: false });
  const [down, flash] = useFlash();
  const proven = st.a >= 3 && st.b && st.n;
  const press = (k: string) => {
    const key = F1.keys.find((x) => x.k === k || (k === "n" && x.k === "0"));
    if (!key) return false;
    flash(key.k);
    const base = st.done ? { a: 0, b: false, n: false, done: false } : st;
    const next = { ...base, a: base.a + (key.k === "a" ? 1 : 0), b: base.b || key.k === "b", n: base.n || key.k === "0" };
    next.done = next.a >= 3 && next.b && next.n;
    setSt(next);
    const line = key.k === "a" ? `${key.line}  (×${next.a})` : key.line;
    setLog((l) => [...(st.done ? [] : l), line].slice(-4));
    return true;
  };
  const status = proven ? "PROUVÉ · test de régression prêt" : st.a > 0 ? (st.a < 3 ? "piste · rejouer A" : !st.b ? "piste · contrôle propriétaire ?" : "piste · contrôle anonyme ?") : "en attente · appuyez sur A, B, ∅";
  const reqs = st.a + (st.b ? 1 : 0) + (st.n ? 1 : 0);
  const readout = proven ? "prouvé · test prêt" : reqs === 0 ? "prêt" : `${reqs} requête${reqs > 1 ? "s" : ""} · piste`;
  return (
    <Plate fig={1} name="Banc de preuve" hint="Appuyez sur B, A ×3, ∅ · ça prouve" readout={readout} viewBox={F1_VB}
      label="Banc de preuve isométrique. Appuyez sur les touches B, A et vide, à la souris ou au clavier, pour envoyer les requêtes de la preuve." onKey={press}>
      <Box b={F1.slab} r={10} />
      <Box b={F1.screen} r={8} />
      <g transform={FRONT(16, 34, 126)}>
        <rect className="face glass" x="12" y="10" width="244" height="84" rx="6" />
        {log.map((l, i) => <text key={i} className="t dim" x="22" y={26 + i * 13} fontSize="8.5">{l}</text>)}
        <text className={cn("t", proven ? "live" : "dim2")} x="22" y="86" fontSize="9">{status}</text>
        <text className="t dim" x="12" y="106" fontSize="7">crenel · authz.matrix · /api/projects/:id</text>
      </g>
      {F1.keys.map((key) => (
        <Key key={key.k} b={key.b} r={6} down={down === key.k} on={proven} label={`${key.cap}`} onPress={() => press(key.k)}>
          <g transform={TOP(key.b[0], key.b[1], key.b[2] + key.b[5])}>
            <text className="t" x="12" y="30" fontSize="22">{key.glyph}</text>
            <text className="t dim" x="12" y="46" fontSize="7.5">{key.cap}</text>
            {key.k === "a" && st.a > 0 && <text className="t live" x="66" y="30" fontSize="10" textAnchor="end">×{st.a}</text>}
          </g>
        </Key>
      ))}
    </Plate>
  );
}
