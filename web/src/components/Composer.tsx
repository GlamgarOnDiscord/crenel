import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUp, ChevronDown, ChevronLeft, ChevronRight, Eye, FolderGit2, Globe, Hand, Mic, Paperclip, Plus, Radar, Square, X } from "lucide-react";
import { ModelLogo } from "../brand/ModelLogo.tsx";
import { targets } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";
import { EFFORTS, MODELS, MODES, effortOf, modelOf, useWorkspace, type ModeId } from "../lib/workspace.tsx";
import { Picker } from "./ui.tsx";

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

const MODE_ICON: Record<ModeId, typeof Eye> = { ask: Hand, readonly: Eye, probes: Radar };

/* Model + effort in one compact trigger (after the Codex composer): an effort
   slider "Plus rapide / Plus fin" on top, then a model row with a sub-list. */
function ModelMenu({ placement }: { placement: "up" | "down" }) {
  const ws = useWorkspace();
  const id = useId();
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<"main" | "models">("main");
  const [active, setActive] = useState(0);
  const wrapRef = useRef<HTMLDivElement>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const sliderRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const model = modelOf(ws.model);
  const effort = effortOf(ws.effort);

  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) { if (!wrapRef.current?.contains(e.target as Node)) setOpen(false); }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);
  useEffect(() => {
    if (!open) { setView("main"); return; }
    if (view === "main") sliderRef.current?.focus({ preventScroll: true });
    else { setActive(Math.max(0, MODELS.findIndex((m) => m.id === ws.model))); listRef.current?.focus({ preventScroll: true }); }
  }, [open, view]);

  function close() { setOpen(false); btnRef.current?.focus(); }
  function setLevel(l: number) { const e = EFFORTS[Math.min(3, Math.max(0, l - 1))]!; ws.setEffort(e.id); }

  function onPopKey(e: React.KeyboardEvent) {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); if (view === "models") setView("main"); else close(); }
  }
  function onSliderKey(e: React.KeyboardEvent) {
    if (e.key === "ArrowRight" || e.key === "ArrowUp") { e.preventDefault(); setLevel(effort.level + 1); }
    else if (e.key === "ArrowLeft" || e.key === "ArrowDown") { e.preventDefault(); setLevel(effort.level - 1); }
    else if (e.key === "Home") { e.preventDefault(); setLevel(1); }
    else if (e.key === "End") { e.preventDefault(); setLevel(4); }
  }
  function onListKey(e: React.KeyboardEvent) {
    const n = MODELS.length;
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => (a + 1) % n); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => (a - 1 + n) % n); }
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); ws.setModel(MODELS[active]!.id); setView("main"); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); setView("main"); }
  }

  return (
    <div className="picker" ref={wrapRef}>
      <button ref={btnRef} type="button" className="tbtn modelbtn" aria-haspopup="dialog" aria-expanded={open}
        aria-label={`Modèle ${model.label}, effort ${effort.label}`} onClick={() => setOpen((o) => !o)}>
        <ModelLogo provider={model.provider} size={14} />
        <span className="tlabel">{model.label}</span>
        <span className="faint tlabel">{effort.label}</span>
        <ChevronDown size={13} className="faint" aria-hidden="true" />
      </button>
      {open && (
        <div className={cn("pop right mm", placement === "up" && "up")} role="dialog" aria-label="Modèle et effort" onKeyDown={onPopKey}>
          {view === "main" ? (
            <>
              <div className="mm-effort">
                <div className="mm-ends"><span>Plus rapide</span><span>Plus fin</span></div>
                <div ref={sliderRef} className="mm-track" role="slider" tabIndex={0} aria-label="Effort"
                  aria-valuemin={1} aria-valuemax={4} aria-valuenow={effort.level} aria-valuetext={effort.label} onKeyDown={onSliderKey}>
                  <span className="mm-fill" style={{ width: `calc((100% - 22px) * ${(effort.level - 1) / 3} + 22px)` }} />
                  {EFFORTS.map((e) => (
                    <button key={e.id} type="button" tabIndex={-1} className={cn("mm-notch", e.level <= effort.level && "on")}
                      style={{ left: `calc(11px + (100% - 22px) * ${(e.level - 1) / 3})` }} aria-label={e.label} onClick={() => setLevel(e.level)} />
                  ))}
                </div>
                <div className="mm-cur">Effort <b>{effort.label}</b></div>
              </div>
              <button type="button" className="mm-row" onClick={() => setView("models")} aria-haspopup="listbox">
                <ModelLogo provider={model.provider} size={15} /><span className="mm-row-l">{model.label}</span>
                <span className="faint mm-row-v">{model.vendor}</span><ChevronRight size={14} className="faint" aria-hidden="true" />
              </button>
            </>
          ) : (
            <>
              <button type="button" className="mm-back" onClick={() => setView("main")}><ChevronLeft size={14} aria-hidden="true" /> Modèle</button>
              <div ref={listRef} role="listbox" tabIndex={-1} aria-label="Modèle" className="pop-list" onKeyDown={onListKey}
                aria-activedescendant={`${id}-m-${active}`}>
                {MODELS.map((m, i) => (
                  <div key={m.id} id={`${id}-m-${i}`} role="option" aria-selected={m.id === ws.model}
                    className={cn("pop-opt", i === active && "on")} onMouseEnter={() => setActive(i)}
                    onClick={() => { ws.setModel(m.id); setView("main"); }}>
                    <span className="pop-ic"><ModelLogo provider={m.provider} size={15} title /></span>
                    <span className="pop-tx"><span className="pop-l">{m.label}</span><span className="pop-d">{m.vendor} · {m.desc}</span></span>
                    <span className="pop-check" aria-hidden="true">✓</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// Minimal Web Speech dictation when the browser offers it; otherwise the
// button is disabled and says why.
type SR = { lang: string; interimResults: boolean; start: () => void; stop: () => void; onresult: ((e: { results: ArrayLike<ArrayLike<{ transcript: string }>> }) => void) | null; onend: (() => void) | null };
function MicButton({ onText }: { onText: (t: string) => void }) {
  const [on, setOn] = useState(false);
  const recRef = useRef<SR | null>(null);
  const Ctor = typeof window !== "undefined"
    ? ((window as unknown as { SpeechRecognition?: new () => SR; webkitSpeechRecognition?: new () => SR }).SpeechRecognition
      ?? (window as unknown as { webkitSpeechRecognition?: new () => SR }).webkitSpeechRecognition)
    : undefined;
  function toggle() {
    if (!Ctor) return;
    if (on) { recRef.current?.stop(); return; }
    const r = new Ctor(); r.lang = "fr-FR"; r.interimResults = false;
    r.onresult = (e) => { const t = e.results[0]?.[0]?.transcript; if (t) onText(t); };
    r.onend = () => setOn(false);
    recRef.current = r; r.start(); setOn(true);
  }
  const label = !Ctor ? "Dictée indisponible dans ce navigateur" : on ? "Arrêter la dictée" : "Dicter";
  return (
    <button type="button" className={cn("tbtn icon", on && "rec")} aria-label={label} title={label} aria-pressed={on} disabled={!Ctor} onClick={toggle}>
      <Mic size={15} />
    </button>
  );
}

export function Composer({ value, onChange, onSubmit, placeholder, variant = "hero", busy, onStop, autoFocus, extra }: {
  value: string; onChange: (v: string) => void; onSubmit: (text: string) => void; placeholder: string;
  variant?: "hero" | "dock"; busy?: boolean; onStop?: () => void; autoFocus?: boolean; extra?: React.ReactNode;
}) {
  const ws = useWorkspace();
  const id = useId();
  const taRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<string[]>([]);
  const [slashIdx, setSlashIdx] = useState(0);
  const [slashDismissed, setSlashDismissed] = useState(false);
  const placement = variant === "dock" ? "up" : "down";

  const slashQuery = /^\/\S*$/.test(value) ? value.toLowerCase() : null;
  const slashItems = slashQuery !== null ? SLASH.filter((s) => s.cmd.startsWith(slashQuery)) : [];
  const slashOpen = slashItems.length > 0 && !slashDismissed;

  useEffect(() => { setSlashIdx(0); setSlashDismissed(false); }, [slashQuery]);
  useEffect(() => { if (autoFocus) taRef.current?.focus(); }, [autoFocus]);
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

  const ModeIcon = MODE_ICON[ws.mode];
  const TargetIcon = ws.target.kind === "repo" ? FolderGit2 : Globe;

  return (
    <div className={cn("composer-wrap", `is-${variant}`)}>
      <div className="composer">
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
          ref={taRef} id={`${id}-ta`} rows={variant === "hero" ? 2 : 1} value={value}
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
            <Plus size={16} />
          </button>
          <Picker
            label="Permissions" value={ws.mode} onChange={ws.setMode} placement={placement}
            buttonClassName={cn("tbtn", ws.mode === "probes" && "warn")}
            options={MODES.map((m) => { const I = MODE_ICON[m.id]; return { value: m.id, label: m.label, desc: m.desc, icon: <I size={15} /> }; })}
          >
            <ModeIcon size={14} aria-hidden="true" /><span className="tlabel">{MODES.find((m) => m.id === ws.mode)!.label}</span>
            <ChevronDown size={13} className="faint" aria-hidden="true" />
          </Picker>
          <span className="sp" />
          {extra}
          <ModelMenu placement={placement} />
          <MicButton onText={(t) => onChange((value ? value + " " : "") + t)} />
          {busy && onStop ? (
            <button type="button" className="sendbtn stop" aria-label="Interrompre (Échap)" title="Interrompre (Échap)" onClick={onStop}><Square size={12} fill="currentColor" /></button>
          ) : (
            <button type="button" className="sendbtn" aria-label="Envoyer (Entrée)" title="Envoyer (Entrée)" disabled={!value.trim()} onClick={() => submit()}><ArrowUp size={16} strokeWidth={2.5} /></button>
          )}
        </div>
      </div>
      {variant === "hero" && (
        <div className="cband">
          <TargetIcon size={14} aria-hidden="true" />
          <span className="cband-l">Cible</span>
          <Picker
            label="Cible" value={ws.target.id} onChange={ws.setTargetId} placement="down" buttonClassName="cband-btn"
            options={targets.map((t) => ({
              value: t.id, label: t.name, desc: t.url,
              icon: t.kind === "repo" ? <FolderGit2 size={15} /> : <Globe size={15} />,
            }))}
            footer={<Link to="/app/onboarding" className="pop-link">+ Ajouter une cible</Link>}
          >
            <span>{ws.target.name}</span><span className="mono faint">{ws.target.url}</span><ChevronDown size={13} className="faint" aria-hidden="true" />
          </Picker>
        </div>
      )}
    </div>
  );
}
