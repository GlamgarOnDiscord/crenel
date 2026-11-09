import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  House, ShieldAlert, ListTodo, FolderClosed, KeyRound, LockKeyhole,
  ShieldCheck, Plug, Settings, Plus, TerminalSquare, Search, SquarePen, Play, Download, OctagonX,
} from "lucide-react";
import { useData } from "../data/api.ts";
import { downloadSarif, killAll } from "../data/actions.ts";
import { useServerAction } from "./console-actions.tsx";

interface Cmd { label: string; hint: string; to: string; icon: typeof Search; state?: unknown; action?: "sarif" | "kill" }

// Real actions: the agent with a slash command, or a server call (needs crenel serve).
const ACTIONS: Cmd[] = [
  { label: "Lancer un scan", hint: "agent /scan", to: "/app/agent", state: { prompt: "/scan" }, icon: Play },
  { label: "Chercher des secrets", hint: "agent /secrets", to: "/app/agent", state: { prompt: "/secrets" }, icon: KeyRound },
  { label: "Exporter SARIF", hint: "téléchargement", to: "", action: "sarif", icon: Download },
  { label: "Arrêt d'urgence", hint: "arrêter toutes les tâches", to: "", action: "kill", icon: OctagonX },
];

const COMMANDS: Cmd[] = [
  { label: "Nouvelle tâche", hint: "composer", to: "/app/overview", icon: SquarePen },
  { label: "Agent", hint: "console", to: "/app/agent", icon: TerminalSquare },
  { label: "Accueil", hint: "aller à", to: "/app/overview", icon: House },
  { label: "Tâches", hint: "historique", to: "/app/scans", icon: ListTodo },
  { label: "Findings", hint: "aller à", to: "/app/findings", icon: ShieldAlert },
  { label: "Secrets", hint: "analyse", to: "/app/secrets", icon: KeyRound },
  { label: "Autorisation", hint: "matrice", to: "/app/authz", icon: LockKeyhole },
  { label: "Tests gardés", hint: "régression", to: "/app/tests", icon: ShieldCheck },
  { label: "Cibles", hint: "dossiers", to: "/app/targets", icon: FolderClosed },
  { label: "Intégrations", hint: "réglages", to: "/app/integrations", icon: Plug },
  { label: "Paramètres", hint: "réglages", to: "/app/settings", icon: Settings },
  { label: "Ajouter une cible", hint: "onboarding", to: "/app/onboarding", icon: Plus },
];

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState("");
  const [i, setI] = useState(0);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  const { project } = useData();
  const run = useServerAction();
  const results = useMemo(
    () => [...ACTIONS, ...COMMANDS].filter((c) => (c.label + " " + c.hint).toLowerCase().includes(q.toLowerCase())),
    [q],
  );

  useEffect(() => {
    if (open) {
      restoreRef.current = document.activeElement as HTMLElement | null;
      setQ(""); setI(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    } else {
      // Give focus back to whatever opened the palette.
      restoreRef.current?.focus?.();
    }
  }, [open]);
  useEffect(() => { setI(0); }, [q]);

  if (!open) return null;

  function go(c: Cmd) {
    onClose();
    if (c.action === "sarif") void run(() => downloadSarif(project), () => ({ title: "SARIF téléchargé" }), "SARIF non exporté");
    else if (c.action === "kill") void run(killAll, (r) => ({ title: r.stopped ? `${r.stopped} tâche${r.stopped > 1 ? "s" : ""} arrêtée${r.stopped > 1 ? "s" : ""}` : "Aucune tâche en cours" }), "Arrêt non effectué");
    else navigate(c.to, c.state ? { state: c.state } : undefined);
  }

  // Escape and a minimal focus trap at the dialog level, so they work no matter
  // which element inside holds focus.
  function onDialogKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") { e.preventDefault(); onClose(); return; }
    if (e.key === "Tab") {
      const focusable = dialogRef.current?.querySelectorAll<HTMLElement>('input, button, [href], [tabindex]:not([tabindex="-1"])');
      if (!focusable || focusable.length === 0) return;
      const first = focusable[0]!, last = focusable[focusable.length - 1]!;
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }

  return (
    <div className="cmdk-overlay" onMouseDown={onClose}>
      <div ref={dialogRef} className="cmdk" role="dialog" aria-modal="true" aria-label="Palette de commandes" onMouseDown={(e) => e.stopPropagation()} onKeyDown={onDialogKeyDown}>
        <div className="cmdk-input">
          <Search size={16} className="faint" aria-hidden="true" />
          <input
            ref={inputRef}
            value={q}
            aria-label="Rechercher une commande"
            placeholder="Aller à une page, lancer une action…"
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setI((n) => Math.min(n + 1, results.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setI((n) => Math.max(n - 1, 0)); }
              else if (e.key === "Enter") { const c = results[i]; if (c) go(c); }
            }}
          />
          <span className="kbd">esc</span>
        </div>
        <div className="cmdk-list">
          {results.length === 0 && <div className="cmdk-empty">Aucun résultat</div>}
          {results.map((c, idx) => (
            <button type="button" key={c.label + c.to} className={`cmdk-item${idx === i ? " on" : ""}`} onMouseEnter={() => setI(idx)} onClick={() => go(c)}>
              <c.icon size={16} className="faint" aria-hidden="true" />
              <span>{c.label}</span>
              <span className="cmdk-hint">{c.hint}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
