import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUp, Check, ChevronDown, Eye, FolderGit2, Globe, Goal, Hand, Mic, Paperclip, Plus, Radar, Square, X } from "lucide-react";
import { ModelLogo } from "../brand/ModelLogo.tsx";
import { useData } from "../data/api.ts";
import { cn } from "../lib/cn.ts";
import { GOALS, MODELS, MODES, effortOf, goalOf, modelOf, useWorkspace, type ModeId } from "../lib/workspace.tsx";
import { ModelSelector, ModelSelectorCommand, ModelSelectorContent, ModelSelectorEmpty, ModelSelectorGroup, ModelSelectorInput, ModelSelectorItem, ModelSelectorList, ModelSelectorLogo, ModelSelectorName, ModelSelectorTrigger } from "./ai/model-selector.tsx";
import { EffortControl, EffortGauge } from "./EffortControl.tsx";
import { Tooltip } from "./arc/tooltip/tooltip.tsx";
import { Picker } from "./ui.tsx";

export const SLASH = [
  { cmd: "/scan", desc: "Scan complet de la cible" },
  { cmd: "/authz", desc: "Matrice d'autorisation entre comptes" },
  { cmd: "/secrets", desc: "Chercher des secrets exposés" },
  { cmd: "/explain", desc: "Expliquer une faille prouvée" },
  { cmd: "/fix", desc: "Préparer le correctif et son test" },
  { cmd: "/test", desc: "Générer les tests de régression" },
  { cmd: "/goal", desc: "Fixer un objectif: l'agent continue jusqu'à l'atteindre" },
  { cmd: "/cible", desc: "Afficher la cible et son périmètre" },
  { cmd: "/clear", desc: "Effacer la conversation" },
];

const MODE_ICON: Record<ModeId, typeof Eye> = { ask: Hand, readonly: Eye, bypass: Radar };

/* Model + effort in one compact trigger, as in the Codex composer: the AI
   Elements ModelSelector (cmdk in a popover, grouped by vendor, logos) with
   the EffortControl on top. */
const VENDORS = ["Anthropic", "OpenAI", "Google", "Mistral AI"] as const;
function ModelMenu({ placement }: { placement: "up" | "down" }) {
  const ws = useWorkspace();
  const [open, setOpen] = useState(false);
  const model = modelOf(ws.model);
  const effort = effortOf(ws.effort);
  return (
    <ModelSelector open={open} onOpenChange={setOpen}>
      <ModelSelectorTrigger asChild>
        <button type="button" className="tbtn modelbtn" aria-label={`Modèle ${model.label}, effort ${effort.label}`}>
          <ModelLogo provider={model.provider} size={14} />
          <span className="tlabel mb-name">{model.label}</span>
          <span className="mb-sep" aria-hidden="true" />
          <EffortGauge level={effort.level} size={15} tone="muted" />
          <span className="tlabel mb-eff">{effort.label}</span>
          <ChevronDown size={13} className="mb-chev" aria-hidden="true" />
        </button>
      </ModelSelectorTrigger>
      <ModelSelectorContent side={placement === "up" ? "top" : "bottom"} align="end">
        <EffortControl value={ws.effort} onChange={ws.setEffort} />
        <ModelSelectorCommand value={ws.model} label="Modèle">
          <ModelSelectorInput placeholder="Rechercher un modèle" />
          <ModelSelectorList>
            <ModelSelectorEmpty>Aucun modèle</ModelSelectorEmpty>
            {VENDORS.map((v) => (
              <ModelSelectorGroup key={v} heading={v}>
                {MODELS.filter((m) => m.vendor === v).map((m) => (
                  <ModelSelectorItem key={m.id} value={m.id} keywords={[m.label, m.vendor]} onSelect={() => { ws.setModel(m.id); setOpen(false); }} data-checked={m.id === ws.model || undefined}>
                    <ModelSelectorLogo provider={m.provider} />
                    <ModelSelectorName desc={m.desc}>{m.label}</ModelSelectorName>
                    <Check size={14} className="msel-check" aria-hidden="true" />
                  </ModelSelectorItem>
                ))}
              </ModelSelectorGroup>
            ))}
          </ModelSelectorList>
        </ModelSelectorCommand>
        <div className="msel-foot"><kbd>↑</kbd><kbd>↓</kbd> naviguer <kbd>⏎</kbd> choisir <kbd>Échap</kbd> fermer</div>
      </ModelSelectorContent>
    </ModelSelector>
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
    <Tooltip content={label}>
      <button type="button" className={cn("tbtn icon", on && "rec")} aria-label={label} aria-pressed={on} aria-disabled={!Ctor} onClick={toggle}>
        <Mic size={15} />
      </button>
    </Tooltip>
  );
}

export function Composer({ value, onChange, onSubmit, placeholder, variant = "hero", busy, onStop, autoFocus, extra }: {
  value: string; onChange: (v: string) => void; onSubmit: (text: string) => void; placeholder: string;
  variant?: "hero" | "dock"; busy?: boolean; onStop?: () => void; autoFocus?: boolean; extra?: React.ReactNode;
}) {
  const ws = useWorkspace();
  const { targets } = useData();
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
          <Tooltip content="Joindre un fichier">
            <button type="button" className="tbtn icon" aria-label="Joindre un fichier" onClick={() => fileRef.current?.click()}>
              <Plus size={16} />
            </button>
          </Tooltip>
          <Picker
            label="Permissions" value={ws.mode} onChange={ws.setMode} placement={placement}
            buttonClassName={cn("tbtn", ws.mode === "bypass" && "warn")}
            options={MODES.map((m) => { const I = MODE_ICON[m.id]; return { value: m.id, label: m.label, desc: m.desc, icon: <I size={15} /> }; })}
          >
            <ModeIcon size={14} aria-hidden="true" /><span className="tlabel">{ws.mode === "bypass" ? "Bypass" : MODES.find((m) => m.id === ws.mode)!.label}</span>
            <ChevronDown size={13} className="faint" aria-hidden="true" />
          </Picker>
          <Picker
            label="Objectif" value={ws.goal} onChange={ws.setGoal} placement={placement}
            buttonClassName={cn("tbtn", ws.goal !== "none" && "on")}
            options={GOALS.map((g) => ({ value: g.id, label: g.label, desc: g.desc, icon: <Goal size={15} /> }))}
          >
            <Goal size={14} aria-hidden="true" /><span className="tlabel">{goalOf(ws.goal).short}</span>
          </Picker>
          <span className="sp" />
          {extra}
          <ModelMenu placement={placement} />
          <MicButton onText={(t) => onChange((value ? value + " " : "") + t)} />
          {busy && onStop ? (
            <Tooltip content="Interrompre · Échap"><button type="button" className="sendbtn stop" aria-label="Interrompre (Échap)" onClick={onStop}><Square size={12} fill="currentColor" /></button></Tooltip>
          ) : (
            <Tooltip content="Envoyer · ⏎"><button type="button" className="sendbtn" aria-label="Envoyer (Entrée)" aria-disabled={!value.trim()} data-empty={!value.trim() || undefined} onClick={() => submit()}><ArrowUp size={16} strokeWidth={2.5} /></button></Tooltip>
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
