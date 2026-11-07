import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  LayoutGrid, ShieldAlert, Radar, FolderClosed, KeyRound, LockKeyhole,
  FileCheck2, Plug, Settings, Plus, Sparkles, Search,
} from "lucide-react";

interface Cmd { label: string; hint: string; to: string; icon: typeof Search; }

const COMMANDS: Cmd[] = [
  { label: "Nouveau scan", hint: "lancer l'agent", to: "/app/scan/run", icon: Plus },
  { label: "Vue d'ensemble", hint: "aller à", to: "/app/overview", icon: LayoutGrid },
  { label: "Findings", hint: "aller à", to: "/app/findings", icon: ShieldAlert },
  { label: "Agent", hint: "console", to: "/app/scan/run", icon: Sparkles },
  { label: "Scans", hint: "historique", to: "/app/scans", icon: Radar },
  { label: "Cibles", hint: "dossiers", to: "/app/targets", icon: FolderClosed },
  { label: "Secrets", hint: "analyse", to: "/app/secrets", icon: KeyRound },
  { label: "Autorisation", hint: "matrice", to: "/app/authz", icon: LockKeyhole },
  { label: "Tests générés", hint: "régression", to: "/app/tests", icon: FileCheck2 },
  { label: "Intégrations", hint: "réglages", to: "/app/integrations", icon: Plug },
  { label: "Paramètres", hint: "réglages", to: "/app/settings", icon: Settings },
  { label: "Ajouter une cible", hint: "onboarding", to: "/app/onboarding", icon: Plus },
];

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState("");
  const [i, setI] = useState(0);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);

  const results = useMemo(
    () => COMMANDS.filter((c) => (c.label + " " + c.hint).toLowerCase().includes(q.toLowerCase())),
    [q],
  );

  useEffect(() => {
    if (open) { setQ(""); setI(0); setTimeout(() => inputRef.current?.focus(), 0); }
  }, [open]);
  useEffect(() => { setI(0); }, [q]);

  if (!open) return null;

  function go(c: Cmd) { navigate(c.to); onClose(); }

  return (
    <div className="cmdk-overlay" onMouseDown={onClose}>
      <div className="cmdk" role="dialog" aria-label="Palette de commandes" onMouseDown={(e) => e.stopPropagation()}>
        <div className="cmdk-input">
          <Search size={16} className="faint" />
          <input
            ref={inputRef}
            value={q}
            placeholder="Aller à une page, lancer une action…"
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setI((n) => Math.min(n + 1, results.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setI((n) => Math.max(n - 1, 0)); }
              else if (e.key === "Enter") { const c = results[i]; if (c) go(c); }
              else if (e.key === "Escape") onClose();
            }}
          />
          <span className="kbd">esc</span>
        </div>
        <div className="cmdk-list">
          {results.length === 0 && <div className="cmdk-empty">Aucun résultat</div>}
          {results.map((c, idx) => (
            <button key={c.label + c.to} className={`cmdk-item${idx === i ? " on" : ""}`} onMouseEnter={() => setI(idx)} onClick={() => go(c)}>
              <c.icon size={16} className="faint" />
              <span>{c.label}</span>
              <span className="cmdk-hint">{c.hint}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
