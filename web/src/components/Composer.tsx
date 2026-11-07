import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUp, Eye, FolderGit2, Globe, ListChecks, Paperclip, Radar, Square, X } from "lucide-react";
import { targets } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import { EFFORTS, MODELS, MODES, effortOf, modelLabel, useWorkspace, type ModeId } from "../lib/workspace.tsx";
import { EffortBars, Picker } from "./ui.tsx";

export const SLASH = [
  { cmd: "/scan", desc: "Scan complet de la cible" },
  { cmd: "/authz", desc: "Matrice d'autorisation entre comptes" },
  { cmd: "/secrets", desc: "Chercher des secrets exposés" },
  { cmd: "/explain", desc: "Expliquer une faille prouvée" },
  { cmd: "/fix", desc: "Préparer le correctif et son test" },
  { cmd: "/test", desc: "Générer les tests de régression" },
  { cmd: "/cible", desc: "Afficher la cible et son périmètre" },
  { cmd: "/clear", desc: "Effacer la conversation" },
];

const MODE_ICON: Record<ModeId, typeof Eye> = { readonly: Eye, plan: ListChecks, probes: Radar };

export function Composer({ value, onChange, onSubmit, placeholder, variant = "hero", busy, onStop, autoFocus }: {
  value: string; onChange: (v: string) => void; onSubmit: (text: string) => void; placeholder: string;
  variant?: "hero" | "dock"; busy?: boolean; onStop?: () => void; autoFocus?: boolean;
}) {
  const ws = useWorkspace();
  const id = useId();
  const taRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<string[]>([]);
  const [slashIdx, setSlashIdx] = useState(0);
  const [slashDismissed, setSlashDismissed] = useState(false);

  const slashQuery = /^\/\S*$/.test(value) ? value.toLowerCase() : null;
  const slashItems = slashQuery !== null ? SLASH.filter((s) => s.cmd.startsWith(slashQuery)) : [];
  const slashOpen = slashItems.length > 0 && !slashDismissed;

  useEffect(() => { setSlashIdx(0); setSlashDismissed(false); }, [slashQuery]);
  useEffect(() => { if (autoFocus) taRef.current?.focus(); }, [autoFocus]);
  // Auto-grow up to a cap.
  useEffect(() => {
    const ta = taRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = `${Math.min(ta.scrollHeight, 220)}px`;
  }, [value]);

  function submit(text = value) {
    const t = text.trim();
    if (!t) return;
    onSubmit(t);
    setFiles([]);
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.nativeEvent.isComposing) return;
    if (slashOpen) {
      if (e.key === "ArrowDown") { e.preventDefault(); setSlashIdx((i) => (i + 1) % slashItems.length); return; }
      if (e.key === "ArrowUp") { e.preventDefault(); setSlashIdx((i) => (i - 1 + slashItems.length) % slashItems.length); return; }
      if (e.key === "Tab") { e.preventDefault(); onChange(slashItems[slashIdx]!.cmd + " "); return; }
      if (e.key === "Enter") { e.preventDefault(); submit(slashItems[slashIdx]!.cmd); return; }
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); setSlashDismissed(true); return; }
    }
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
  }

  const effort = effortOf(ws.effort);
  const ModeIcon = MODE_ICON[ws.mode];
  const TargetIcon = ws.target.kind === "repo" ? FolderGit2 : Globe;

  return (
    <div className={cn("composer", `is-${variant}`)}>
      {slashOpen && (
        <div className="slashmenu" role="listbox" id={`${id}-slash`} aria-label="Commandes">
          {slashItems.map((s, i) => (
            <div key={s.cmd} id={`${id}-slash-${i}`} role="option" aria-selected={i === slashIdx}
              className={cn("slash-opt", i === slashIdx && "on")}
              onMouseEnter={() => setSlashIdx(i)}
              onMouseDown={(e) => { e.preventDefault(); submit(s.cmd); }}>
              <span className="mono">{s.cmd}</span><span className="slash-d">{s.desc}</span>
            </div>
          ))}
        </div>
      )}
      {files.length > 0 && (
        <div className="attach">
          {files.map((f) => (
            <span key={f} className="attach-chip">
              <Paperclip size={12} aria-hidden="true" />{f}
              <button type="button" aria-label={`Retirer ${f}`} onClick={() => setFiles((l) => l.filter((x) => x !== f))}><X size={12} /></button>
            </span>
          ))}
        </div>
      )}
      <label className="sr-only" htmlFor={`${id}-ta`}>Message à Crenel</label>
      <textarea
        ref={taRef} id={`${id}-ta`} rows={variant === "hero" ? 3 : 1} value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)} onKeyDown={onKeyDown}
        role="combobox" aria-expanded={slashOpen} aria-autocomplete="list"
        aria-controls={slashOpen ? `${id}-slash` : undefined}
        aria-activedescendant={slashOpen ? `${id}-slash-${slashIdx}` : undefined}
      />
      <div className="ctools">
        <input ref={fileRef} type="file" multiple hidden onChange={(e) => {
          const names = Array.from(e.target.files ?? []).map((f) => f.name);
          setFiles((l) => [...l, ...names.filter((n) => !l.includes(n))]);
          e.target.value = "";
        }} />
        <button type="button" className="tbtn icon" aria-label="Joindre un fichier" title="Joindre un fichier" onClick={() => fileRef.current?.click()}>
          <Paperclip size={15} />
        </button>
        <Picker
          label="Cible" value={ws.target.id} onChange={ws.setTargetId} placement={variant === "dock" ? "up" : "down"}
          buttonClassName="tbtn"
          options={targets.map((t) => ({
            value: t.id, label: t.name, desc: t.url,
            icon: t.kind === "repo" ? <FolderGit2 size={15} /> : <Globe size={15} />,
          }))}
          footer={<Link to="/app/onboarding" className="pop-link">+ Ajouter une cible</Link>}
        >
          <TargetIcon size={14} aria-hidden="true" /><span className="tlabel">{ws.target.name}</span>
        </Picker>
        <Picker
          label="Mode" value={ws.mode} onChange={ws.setMode} placement={variant === "dock" ? "up" : "down"}
          buttonClassName={cn("tbtn", ws.mode === "probes" && "warn")}
          options={MODES.map((m) => { const I = MODE_ICON[m.id]; return { value: m.id, label: m.label, desc: m.desc, icon: <I size={15} /> }; })}
        >
          <ModeIcon size={14} aria-hidden="true" /><span className="tlabel">{MODES.find((m) => m.id === ws.mode)!.label}</span>
        </Picker>
        <span className="sp" />
        <Picker
          label="Modèle" value={ws.model} onChange={ws.setModel} align="right" placement={variant === "dock" ? "up" : "down"}
          buttonClassName="tbtn"
          options={MODELS.map((m) => ({ value: m.id, label: m.label, desc: m.desc, icon: <span className="mglyph" /> }))}
        >
          <span className="mglyph" aria-hidden="true" /><span>{modelLabel(ws.model)}</span>
        </Picker>
        <Picker
          label="Effort" value={ws.effort} onChange={ws.setEffort} align="right" placement={variant === "dock" ? "up" : "down"}
          buttonClassName="tbtn"
          options={EFFORTS.map((e) => ({ value: e.id, label: e.label, desc: e.desc, icon: <EffortBars level={e.level} /> }))}
        >
          <EffortBars level={effort.level} /><span className="tlabel">{effort.label}</span>
        </Picker>
        {busy && onStop ? (
          <button type="button" className="sendbtn stop" aria-label="Interrompre (Échap)" title="Interrompre (Échap)" onClick={onStop}><Square size={13} fill="currentColor" /></button>
        ) : (
          <button type="button" className="sendbtn" aria-label="Envoyer (Entrée)" title="Envoyer (Entrée)" disabled={!value.trim()} onClick={() => submit()}><ArrowUp size={17} strokeWidth={2.5} /></button>
        )}
      </div>
    </div>
  );
}
