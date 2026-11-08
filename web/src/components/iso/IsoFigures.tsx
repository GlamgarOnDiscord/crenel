/* Interactive isometric figures for the landing, built with the iso-figure
   method (github.com/MrBongoC/ai-iso-skill, MIT): every part is a flat SVG
   shape placed on a 3D plane by one matrix(), objects are boxes drawn as
   their three visible faces in back-to-front paint order, interaction is one
   state object and class toggles, motion is CSS. Hairline monochrome, with
   Crenel's amber reserved for whatever is live. Each figure does something
   real when pressed: requests answer, chunks get read, the gate decides, the
   build goes red or green. Keyboard works once the figure has focus. */
import { useCallback, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
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

// ---------- Fig 2 · Bundle: a laptop that reads the served chunks ----------
const CHUNKS: { name: string; lines: string[]; hit?: number; found?: string }[] = [
  { name: "index-1a9c.js", lines: ['import { h } from "preact";', 'const api = "/api/v1";', "export default App;"] },
  { name: "vendor-77de.js", lines: ["/* stripe-js */", 'const pk = "pk_live_51N…aQ";', "// clé publique : normal"] },
  { name: "index-4f2a.js", lines: ["const s = new Stripe(", '  "sk_live_51N…q8");', "// clé serveur côté client"], hit: 1, found: "clé serveur" },
  { name: "admin-0b3e.js.map", lines: ['"sources": [', '  "src/admin/billing.tsx"', "]"], hit: 1, found: "source map" },
];
const F2 = { base: [0, 0, 0, 250, 170, 10] as B6, lid: [0, 0, 10, 250, 8, 150] as B6, scan: [95, 114, 10, 60, 38, 7] as B6 };
const F2_VB = frame([F2.base, F2.lid, F2.scan]);

export function BundleFigure() {
  const [i, setI] = useState(-1);
  const [found, setFound] = useState<string[]>([]);
  const [down, flash] = useFlash();
  const press = (k: string) => {
    if (k !== " " && k !== "s" && k !== "Enter") return false;
    flash("scan");
    const n = (i + 1) % CHUNKS.length;
    const c = CHUNKS[n]!;
    setI(n);
    setFound((f) => (n === 0 ? [] : f).concat(c.found ? [c.found] : []));
    return true;
  };
  const c = i >= 0 ? CHUNKS[i] : null;
  const readout = !c ? "prêt" : `chunk ${i + 1}/${CHUNKS.length} · ${found.length ? found.join(", ") : "rien"}`;
  const grid = useMemo(() => {
    const out: ReactNode[] = [];
    for (let r = 0; r < 4; r++) for (let q = 0; q < 12; q++)
      out.push(<rect key={`${r}-${q}`} className="detail" x={18 + q * 18.3} y={26 + r * 17} width="15" height="13" rx="2.5" />);
    return out;
  }, []);
  return (
    <Plate fig={2} name="Bundle servi" hint="Appuyez sur SCAN · il lit le chunk suivant" readout={readout} viewBox={F2_VB}
      label="Ordinateur portable isométrique. Appuyez sur SCAN, à la souris ou avec Espace, pour lire le chunk JavaScript suivant du site." onKey={press}>
      <Box b={F2.base} r={10} />
      <Box b={F2.lid} r={8} />
      <g transform={FRONT(0, 8, 160)}>
        <rect className="face glass" x="12" y="12" width="226" height="118" rx="6" />
        <text className="t dim" x="22" y="28" fontSize="8">acme.app/assets/{c ? c.name : "…"}</text>
        <line className="detail" x1="12" y1="35" x2="238" y2="35" />
        {c ? c.lines.map((l, k) => (
          <g key={k}>
            {c.hit === k && <rect className="hl" x="18" y={44 + k * 16} width="214" height="14" rx="3" />}
            <text className={cn("t", c.hit === k ? "on-live" : "dim2")} x="22" y={54 + k * 16} fontSize="8.5">{l}</text>
          </g>
        )) : <text className="t dim" x="22" y="58" fontSize="8.5">appuyez sur SCAN</text>}
        {c?.found && <text className="t live" x="22" y="122" fontSize="8.5">trouvé : {c.found}</text>}
        <text className="t dim" x="112" y="143" fontSize="7">crenel</text>
      </g>
      <g transform={TOP(0, 0, 10)}>{grid}</g>
      <Key b={F2.scan} r={5} down={down === "scan"} label="SCAN" onPress={() => press(" ")}>
        <g transform={TOP(F2.scan[0], F2.scan[1], F2.scan[2] + F2.scan[5])}>
          <text className="t" x="30" y="23" fontSize="10" textAnchor="middle">SCAN</text>
        </g>
      </Key>
    </Plate>
  );
}

// ---------- Fig 3 · Authorization matrix: each cell is a real read ----------
const ROWS = ["A", "C", "anon"] as const;
const COLS = ["/projects", "/invoices", "/files"] as const;
// Objects belong to B. 200 for anyone but B is a flaw.
const RESULT: number[][] = [[200, 403, 200], [403, 403, 200], [401, 401, 401]];
const F3 = { base: [0, 0, 0, 300, 222, 12] as B6, screen: [14, 10, 12, 272, 18, 78] as B6 };
const cellBox = (r: number, q: number): B6 => [92 + q * 68, 72 + r * 44, 12, 58, 34, 8];
const F3_VB = frame([F3.base, F3.screen, cellBox(2, 2)]);

export function MatrixFigure() {
  const [tested, setTested] = useState<Set<number>>(new Set());
  const [last, setLast] = useState<number | null>(null);
  const [down, flash] = useFlash();
  const press = (k: string) => {
    const n = Number(k);
    if (!Number.isInteger(n) || n < 1 || n > 9) return false;
    const id = n - 1;
    flash(String(id));
    setLast(id);
    setTested((s) => new Set(s).add(id));
    return true;
  };
  const flaws = [...tested].filter((id) => RESULT[Math.floor(id / 3)]![id % 3] === 200).length;
  const lr = last === null ? null : { who: ROWS[Math.floor(last / 3)]!, path: COLS[last % 3]!, code: RESULT[Math.floor(last / 3)]![last % 3]! };
  const readout = tested.size === 0 ? "prêt" : `${tested.size}/9 testées · ${flaws} faille${flaws > 1 ? "s" : ""}`;
  return (
    <Plate fig={3} name="Matrice d'autorisation" hint="Appuyez sur une case · 1 à 9" readout={readout} viewBox={F3_VB}
      label="Matrice d'autorisation isométrique. Chaque case lit un objet du compte B en tant que A, C ou sans session. Appuyez sur une case ou sur les chiffres 1 à 9." onKey={press}>
      <Box b={F3.base} r={10} />
      <g transform={TOP(0, 0, 12)}>
        {COLS.map((c, q) => <text key={c} className="t dim" x={96 + q * 68} y="50" fontSize="8">{c}</text>)}
        {ROWS.map((r, i) => <text key={r} className="t" x="22" y={94 + i * 44} fontSize={r === "anon" ? 10 : 14}>{r}</text>)}
      </g>
      <Box b={F3.screen} r={6} />
      <g transform={FRONT(14, 28, 90)}>
        <rect className="face glass" x="10" y="10" width="252" height="48" rx="5" />
        {lr ? (
          <>
            <text className="t dim2" x="20" y="28" fontSize="8.5">{lr.who} lit {lr.path}/obj_b_1</text>
            <text className={cn("t", lr.code === 200 ? "live" : "dim2")} x="20" y="46" fontSize="9.5">
              → {lr.code} · {lr.code === 200 ? "FAILLE, l'objet de B est lisible" : "refusé, comme prévu"}
            </text>
          </>
        ) : <text className="t dim" x="20" y="38" fontSize="8.5">objets du compte B · lu par A, C, anon</text>}
        <text className="t dim" x="10" y="70" fontSize="7">crenel · authz.matrix</text>
      </g>
      {ROWS.map((_, r) => COLS.map((__, q) => {
        const id = r * 3 + q, b = cellBox(r, q), done = tested.has(id), bad = RESULT[r]![q] === 200;
        return (
          <Key key={id} b={b} r={5} down={down === String(id)} on={done && bad} label={`${ROWS[r]} ${COLS[q]}`} onPress={() => press(String(id + 1))}>
            <g transform={TOP(b[0], b[1], b[2] + b[5])}>
              <text className={cn("t", done ? (bad ? "live" : "dim2") : "dim")} x="29" y="21" fontSize={done ? 11 : 8} textAnchor="middle">
                {done ? RESULT[r]![q] : id + 1}
              </text>
            </g>
          </Key>
        );
      }))}
    </Plate>
  );
}

// ---------- Fig 4 · Permission gate: the mode decides what leaves ----------
const MODES = [{ id: "ask", cap: "DEMANDER" }, { id: "ro", cap: "LECTURE" }, { id: "bypass", cap: "BYPASS" }] as const;
type Mode = (typeof MODES)[number]["id"];
const F4 = { base: [0, 0, 0, 260, 190, 12] as B6, screen: [14, 10, 12, 232, 18, 72] as B6, probe: [80, 116, 12, 100, 46, 12] as B6 };
const modeBox = (i: number): B6 => [16 + i * 79, 62, 12, 70, 32, 8];
const F4_VB = frame([F4.base, F4.screen, F4.probe]);

export function GateFigure() {
  const [mode, setMode] = useState<Mode>("ask");
  const [pending, setPending] = useState(false);
  const [sent, setSent] = useState(0);
  const [msg, setMsg] = useState<{ t: string; live?: boolean } | null>(null);
  const [down, flash] = useFlash();
  const press = (k: string) => {
    const mi = ["1", "2", "3"].indexOf(k);
    if (mi >= 0) { flash(MODES[mi]!.id); setMode(MODES[mi]!.id); setPending(false); setMsg(null); return true; }
    if (k !== " " && k !== "Enter") return false;
    flash("probe");
    if (mode === "ro") setMsg({ t: "bloqué · lecture seule, aucune requête" });
    else if (mode === "ask" && !pending) { setPending(true); setMsg({ t: "GET staging.acme.app ? appuyez encore", live: true }); }
    else { setPending(false); setSent((n) => n + 1); setMsg({ t: mode === "ask" ? "autorisé une fois · GET → 200 · journalisé" : "envoyé · GET → 200 · journalisé", live: true }); }
    return true;
  };
  const cap = MODES.find((m) => m.id === mode)!.cap.toLowerCase();
  const readout = `${cap} · ${sent} envoyée${sent > 1 ? "s" : ""}${pending ? " · 1 en attente" : ""}`;
  return (
    <Plate fig={4} name="Porte des sondes" hint="Choisissez un mode · appuyez sur SONDE" readout={readout} viewBox={F4_VB}
      label="Porte des sondes isométrique. Choisissez un mode avec 1, 2 ou 3, puis appuyez sur SONDE ou Espace pour envoyer une requête." onKey={press}>
      <Box b={F4.base} r={10} />
      <Box b={F4.screen} r={6} />
      <g transform={FRONT(14, 28, 84)}>
        <rect className="face glass" x="10" y="10" width="212" height="44" rx="5" />
        <text className="t dim2" x="20" y="27" fontSize="8.5">mode : {cap} · hôtes déclarés</text>
        <text className={cn("t", msg?.live ? "live" : "dim")} x="20" y="44" fontSize="8.5">{msg ? msg.t : "aucune sonde envoyée"}</text>
        <text className="t dim" x="10" y="66" fontSize="7">crenel · net.gate</text>
      </g>
      {MODES.map((m, i) => {
        const b = modeBox(i);
        return (
          <Key key={m.id} b={b} r={5} down={down === m.id} on={mode === m.id} label={m.cap} onPress={() => press(String(i + 1))}>
            <g transform={TOP(b[0], b[1], b[2] + b[5])}>
              <text className={cn("t", mode === m.id ? "live" : "dim2")} x="35" y="20" fontSize="8" textAnchor="middle">{m.cap}</text>
            </g>
          </Key>
        );
      })}
      <Key b={F4.probe} r={6} down={down === "probe"} on={pending} label="SONDE" onPress={() => press(" ")}>
        <g transform={TOP(F4.probe[0], F4.probe[1], F4.probe[2] + F4.probe[5])}>
          <text className="t" x="50" y="28" fontSize="13" textAnchor="middle">SONDE</text>
        </g>
      </Key>
    </Plate>
  );
}

// ---------- Fig 5 · CI: the proof became a test, the build obeys it ----------
const F5 = { base: [0, 0, 0, 260, 190, 12] as B6, screen: [14, 10, 12, 232, 18, 84] as B6, fix: [16, 104, 12, 106, 52, 10] as B6, push: [138, 104, 12, 106, 52, 10] as B6 };
const F5_VB = frame([F5.base, F5.screen, F5.fix, F5.push]);

export function CiFigure() {
  const [fixed, setFixed] = useState(false);
  const [runs, setRuns] = useState(0);
  const [ranFixed, setRanFixed] = useState(false);
  const [down, flash] = useFlash();
  const press = (k: string) => {
    if (k === "f") { flash("fix"); setFixed((f) => !f); return true; }
    if (k === "p" || k === " " || k === "Enter") { flash("push"); setRuns((n) => n + 1); setRanFixed(fixed); return true; }
    return false;
  };
  const green = runs > 0 && ranFixed;
  const tests = [
    { t: "webhook Stripe signé", ok: true },
    { t: "clé serveur hors du bundle", ok: true },
    { t: "A ne lit pas proj_b_1", ok: ranFixed },
  ];
  const readout = runs === 0 ? (fixed ? "correctif prêt" : "prêt") : `push #${runs} · ${green ? "vert" : "bloqué · 1 rouge"}`;
  return (
    <Plate fig={5} name="Garde en CI" hint="CORRECTIF puis PUSH · la CI tranche" readout={readout} viewBox={F5_VB}
      label="Boîtier de CI isométrique. Appuyez sur PUSH (P) pour lancer la CI, et sur CORRECTIF (F) pour appliquer le correctif avant de pousser." onKey={press}>
      <Box b={F5.base} r={10} />
      <Box b={F5.screen} r={6} />
      <g transform={FRONT(14, 28, 96)}>
        <rect className="face glass" x="10" y="10" width="212" height="58" rx="5" />
        {runs === 0 ? <text className="t dim" x="20" y="42" fontSize="8.5">en attente d'un push</text> : tests.map((x, i) => (
          <text key={x.t} className={cn("t", x.ok ? "dim2" : "live")} x="20" y={26 + i * 14} fontSize="8.5">{x.ok ? "✓" : "✗"} {x.t}</text>
        ))}
        <text className={cn("t", green ? "live" : "dim")} x="10" y="80" fontSize="7.5">{runs === 0 ? "crenel test" : green ? `build #${runs} · vert` : `build #${runs} · bloqué`}</text>
      </g>
      <Key b={F5.fix} r={6} down={down === "fix"} on={fixed} label="CORRECTIF" onPress={() => press("f")}>
        <g transform={TOP(F5.fix[0], F5.fix[1], F5.fix[2] + F5.fix[5])}>
          <text className={cn("t", fixed ? "live" : "dim2")} x="53" y="30" fontSize="10" textAnchor="middle">CORRECTIF</text>
        </g>
      </Key>
      <Key b={F5.push} r={6} down={down === "push"} label="PUSH" onPress={() => press("p")}>
        <g transform={TOP(F5.push[0], F5.push[1], F5.push[2] + F5.push[5])}>
          <text className="t" x="53" y="30" fontSize="12" textAnchor="middle">PUSH</text>
        </g>
      </Key>
    </Plate>
  );
}
