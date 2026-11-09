import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, ArrowUp, Check, ChevronDown, Compass, Eye, FolderGit2, Globe, Goal, Hand, KeyRound, Mic, Paperclip, Plus, Radar, Square, Trash2, X } from "lucide-react";
import { ModelLogo } from "../brand/ModelLogo.tsx";
import { useData } from "../data/api.ts";
import { cn } from "../lib/cn.ts";
import { CONNECTORS, EXPLORES, GOALS, MODELS, MODEL_KEY_ENVS, MODES, activeModelView, connectorOf, connectorToDraft, customSource, customSpec, draftNotes, draftToModel, effortOf, emptyDraft, goalOf, providerOf, useWorkspace, validateDraft, type Connector, type GoalId, type ModeId, type ModelDraft } from "../lib/workspace.tsx";
import { ModelSelector, ModelSelectorCommand, ModelSelectorContent, ModelSelectorEmpty, ModelSelectorGroup, ModelSelectorInput, ModelSelectorItem, ModelSelectorList, ModelSelectorLogo, ModelSelectorName, ModelSelectorTrigger } from "./ai/model-selector.tsx";
import { EffortControl, EffortGauge } from "./EffortControl.tsx";
import { Tooltip } from "./arc/tooltip/tooltip.tsx";
import { Picker } from "./ui.tsx";

export const SLASH = [
  { cmd: "/scan", desc: "Scan complet de la cible" },
  { cmd: "/authz", desc: "Matrice d'autorisation entre comptes" },
  { cmd: "/secrets", desc: "Chercher des secrets exposés" },
  { cmd: "/explore", desc: "Exploration libre par le modèle, chaque affirmation rejouée" },
  { cmd: "/explain", desc: "Expliquer une faille prouvée" },
  { cmd: "/fix", desc: "Préparer le correctif et son test" },
  { cmd: "/test", desc: "Générer les tests de régression" },
  { cmd: "/goal", desc: "Fixer un objectif: l'agent continue jusqu'à l'atteindre" },
  { cmd: "/cible", desc: "Afficher la cible et son périmètre" },
  { cmd: "/clear", desc: "Effacer la conversation" },
];

const MODE_ICON: Record<ModeId, typeof Eye> = { ask: Hand, readonly: Eye, bypass: Radar };

/* Free exploration (off / assist / full). Without a model it stays off: the
   server would refuse it anyway, so the menu says why instead. */
function ExploreMenu({ placement }: { placement: "up" | "down" }) {
  const ws = useWorkspace();
  const data = useData();
  const value = data.llm ? (ws.explore ?? data.explore) : "off";
  const cur = EXPLORES.find((e) => e.id === value)!;
  return (
    <Picker
      label="Exploration" value={value} placement={placement}
      onChange={(v) => ws.setExplore(v as typeof value)}
      buttonClassName={cn("tbtn", value !== "off" && "explore-on")}
      options={EXPLORES.map((e) => ({ value: e.id, label: e.label, desc: !data.llm && e.id !== "off" ? "Demande un modèle (crenel serve --llm)." : e.desc, icon: <Compass size={15} /> }))}
    >
      <Compass size={14} aria-hidden="true" /><span className="tlabel">{cur.short}</span>
      <ChevronDown size={13} className="faint" aria-hidden="true" />
    </Picker>
  );
}

/* The card that adds a custom model. Pick a connector (cloud or local): it
   pre-fills the endpoint and the conventional NAME of the key's env var, then
   only the model name is left to type. Everything is editable; the checks are
   the server's (https or localhost, no credentials in the URL, a model-key
   variable name). Nothing here is a secret: the key never leaves the
   environment of the machine running Crenel. */
function CustomModelForm({ initial, onSave, onCancel }: { initial?: ModelDraft; onSave: (d: ModelDraft) => void; onCancel: () => void }) {
  const [draft, setDraft] = useState<ModelDraft>(() => initial ?? emptyDraft());
  const [touched, setTouched] = useState(false);
  const errors = validateDraft(draft);
  const notes = draftNotes(draft);
  const prov = providerOf(draft.provider);
  const conn = connectorOf(draft.connector) ?? connectorOf("custom")!;
  const set = (patch: Partial<ModelDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const pick = (c: Connector) => setDraft((d) => connectorToDraft(c, d.name));
  const submit = () => { setTouched(true); if (Object.keys(errors).length === 0) onSave(draft); };
  const spec = `${prov.prefix}:${draft.name.trim() || "…"}`;
  const show = (k: keyof ModelDraft) => (touched || (k !== "name" && draft[k] !== "")) && errors[k];
  const group = (local: boolean) => CONNECTORS.filter((c) => !!c.local === local && c.id !== "custom");
  const tile = (c: Connector) => (
    <button key={c.id} type="button" role="radio" aria-checked={c.id === conn.id} title={c.baseUrl ?? "Point d'accès compatible OpenAI à renseigner"}
      className={cn("cmf-conn", c.id === conn.id && "on")} onClick={() => pick(c)}>
      <ModelLogo provider={c.logo} size={14} /><span className="cmf-conn-l">{c.label}</span>
    </button>
  );
  return (
    <div className="cmf" role="group" aria-label="Ajouter un modèle custom" onKeyDown={(e) => { if (e.key === "Enter" && (e.target as HTMLElement).tagName === "INPUT") { e.preventDefault(); submit(); } }}>
      <div className="cmf-head">
        <button type="button" className="tbtn icon" aria-label="Retour à la liste" onClick={onCancel}><ArrowLeft size={15} /></button>
        <span className="cmf-title">Ajouter un modèle</span>
        <span className="cmf-spec mono" title={`Spécification envoyée au moteur : ${spec}`}>{spec}</span>
      </div>

      <div className="cmf-sec">
        <span className="cmf-sec-l">Cloud</span>
        <div className="cmf-conns" role="radiogroup" aria-label="Connecteurs cloud">{group(false).map(tile)}</div>
        <span className="cmf-sec-l">Sur votre machine</span>
        <div className="cmf-conns" role="radiogroup" aria-label="Connecteurs locaux">{[...group(true), connectorOf("custom")!].map(tile)}</div>
      </div>

      <div className="cmf-picked">
        <ModelLogo provider={conn.logo} size={16} />
        <div className="cmf-picked-t">
          <b>{conn.id === "custom" ? "Point d'accès compatible OpenAI" : conn.label}</b>
          <span className="mono">{draft.baseUrl || "à renseigner ci-dessous"}{draft.apiKeyEnv ? ` · ${draft.apiKeyEnv}` : conn.local ? " · sans clé" : ""}</span>
        </div>
      </div>

      <label className="cmf-field">
        <span className="cmf-lbl">Nom du modèle</span>
        <input className="cmf-in mono" value={draft.name} placeholder={conn.example ?? "nom du modèle"} spellCheck={false} autoCorrect="off"
          onChange={(e) => set({ name: e.target.value })} aria-invalid={!!show("name")} autoFocus />
        {show("name") && <span className="cmf-err">{errors.name}</span>}
      </label>
      <label className="cmf-field">
        <span className="cmf-lbl">Point d'accès {conn.id !== "custom" && <span className="cmf-opt">pré-rempli</span>}</span>
        <input className="cmf-in mono" value={draft.baseUrl} placeholder={prov.basePlaceholder} spellCheck={false} autoCorrect="off"
          onChange={(e) => set({ baseUrl: e.target.value })} aria-invalid={!!show("baseUrl")} />
        {show("baseUrl") ? <span className="cmf-err">{errors.baseUrl}</span> : <span className="cmf-hint">https, ou http://localhost pour un modèle local.</span>}
      </label>
      <div className="cmf-row">
        <label className="cmf-field grow">
          <span className="cmf-lbl">Variable de la clé {!prov.needsKey && <span className="cmf-opt">optionnel</span>}</span>
          <input className="cmf-in mono" value={draft.apiKeyEnv} placeholder={conn.local ? "aucune" : "OPENAI_API_KEY"} list="cmf-key-envs"
            onChange={(e) => set({ apiKeyEnv: e.target.value.toUpperCase() })} aria-invalid={!!show("apiKeyEnv")}
            autoCapitalize="characters" autoCorrect="off" spellCheck={false} />
          <datalist id="cmf-key-envs">{MODEL_KEY_ENVS.map((n) => <option key={n} value={n} />)}<option value="CRENEL_LLM_API_KEY" /></datalist>
        </label>
        <label className="cmf-field temp">
          <span className="cmf-lbl">Température</span>
          <input className="cmf-in mono" value={draft.temperature} placeholder="défaut" inputMode="decimal"
            onChange={(e) => set({ temperature: e.target.value })} aria-invalid={!!show("temperature")} />
        </label>
      </div>
      {show("apiKeyEnv") ? <span className="cmf-err">{errors.apiKeyEnv}</span>
        : notes.apiKeyEnv ? <span className="cmf-warn">{notes.apiKeyEnv}</span>
        : <span className="cmf-hint"><KeyRound size={11} aria-hidden="true" /> Le nom de la variable, jamais la clé : le moteur lit sa valeur dans son environnement.</span>}
      {show("temperature") && <span className="cmf-err">{errors.temperature}</span>}

      <div className="cmf-actions">
        <button type="button" className="btn quiet sm" onClick={onCancel}>Annuler</button>
        <button type="button" className="btn sm" onClick={submit}>Ajouter le modèle</button>
      </div>
    </div>
  );
}

/* Model + effort in one compact trigger, as in the Codex composer: the AI
   Elements ModelSelector (cmdk in a popover, grouped by vendor, logos) with
   the EffortControl on top, plus a "Modèles custom" group and its config card. */
const VENDORS = ["Anthropic", "OpenAI", "Google", "Mistral AI"] as const;
function ModelMenu({ placement }: { placement: "up" | "down" }) {
  const ws = useWorkspace();
  const [open, setOpen] = useState(false);
  const [adding, setAdding] = useState(false);
  const view = activeModelView(ws.model, ws.customModels);
  const effort = effortOf(ws.effort);
  const closeMenu = () => { setOpen(false); setAdding(false); };
  return (
    <ModelSelector open={open} onOpenChange={(o) => { setOpen(o); if (!o) setAdding(false); }}>
      <ModelSelectorTrigger asChild>
        <button type="button" className="tbtn modelbtn" aria-label={`Modèle ${view.label}, effort ${effort.label}`}>
          <ModelLogo provider={view.provider} size={14} />
          <span className="tlabel mb-name">{view.label}</span>
          <span className="mb-sep" aria-hidden="true" />
          <EffortGauge level={effort.level} size={15} tone="muted" />
          <span className="tlabel mb-eff">{effort.label}</span>
          <ChevronDown size={13} className="mb-chev" aria-hidden="true" />
        </button>
      </ModelSelectorTrigger>
      <ModelSelectorContent side={placement === "up" ? "top" : "bottom"} align="end">
        {adding ? (
          <CustomModelForm
            onCancel={() => setAdding(false)}
            onSave={(d) => { const m = draftToModel(d); ws.addCustomModel(m); ws.setModel(m.id); closeMenu(); }}
          />
        ) : (
          <>
            <EffortControl value={ws.effort} onChange={ws.setEffort} />
            <ModelSelectorCommand value={ws.model} label="Modèle">
              <ModelSelectorInput placeholder="Rechercher un modèle" />
              <ModelSelectorList>
                <ModelSelectorEmpty>Aucun modèle</ModelSelectorEmpty>
                {VENDORS.map((v) => (
                  <ModelSelectorGroup key={v} heading={v}>
                    {MODELS.filter((m) => m.vendor === v).map((m) => (
                      <ModelSelectorItem key={m.id} value={m.id} keywords={[m.label, m.vendor]} onSelect={() => { ws.setModel(m.id); closeMenu(); }} data-checked={m.id === ws.model || undefined}>
                        <ModelSelectorLogo provider={m.provider} />
                        <ModelSelectorName desc={m.desc} recommended={"recommended" in m && m.recommended}>{m.label}</ModelSelectorName>
                        <Check size={14} className="msel-check" aria-hidden="true" />
                      </ModelSelectorItem>
                    ))}
                  </ModelSelectorGroup>
                ))}
                <ModelSelectorGroup heading="Modèles custom">
                  {ws.customModels.map((m) => (
                    <ModelSelectorItem key={m.id} value={m.id} keywords={[m.name, customSource(m).label, customSpec(m)]} onSelect={() => { ws.setModel(m.id); closeMenu(); }} data-checked={m.id === ws.model || undefined}>
                      <ModelSelectorLogo provider={customSource(m).logo} />
                      <ModelSelectorName desc={`${customSource(m).label} · ${customSpec(m)}`}>{m.name}</ModelSelectorName>
                      <button type="button" className="msel-del" aria-label={`Supprimer ${m.name}`}
                        onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); ws.removeCustomModel(m.id); }}>
                        <Trash2 size={13} aria-hidden="true" />
                      </button>
                      <Check size={14} className="msel-check" aria-hidden="true" />
                    </ModelSelectorItem>
                  ))}
                  <ModelSelectorItem value="__add-custom" keywords={["ajouter", "custom", "openai", "ollama", "anthropic", "local"]} className="msel-add" onSelect={() => setAdding(true)}>
                    <span className="msel-logo msel-logo-add" aria-hidden="true"><Plus size={16} /></span>
                    <ModelSelectorName desc="OpenRouter, Groq, Mistral, Ollama, LM Studio…">Ajouter un modèle…</ModelSelectorName>
                  </ModelSelectorItem>
                </ModelSelectorGroup>
              </ModelSelectorList>
            </ModelSelectorCommand>
            <div className="msel-foot"><kbd>↑</kbd><kbd>↓</kbd> naviguer <kbd>⏎</kbd> choisir <kbd>Échap</kbd> fermer</div>
          </>
        )}
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
  // "/goal" opens a second list with the goals instead of sending the command.
  const [goalStage, setGoalStage] = useState(false);
  const placement = variant === "dock" ? "up" : "down";

  const slashQuery = /^\/\S*$/.test(value) ? value.toLowerCase() : null;
  const goalItems = GOALS.filter((g) => g.id !== "none").map((g) => ({ cmd: g.id, label: g.label, desc: g.desc }));
  const slashItems = goalStage ? goalItems : slashQuery !== null ? SLASH.filter((s) => s.cmd.startsWith(slashQuery)).map((s) => ({ ...s, label: s.cmd })) : [];
  const slashOpen = slashItems.length > 0 && !slashDismissed;

  useEffect(() => { setSlashIdx(0); setSlashDismissed(false); if (!/^\/goal$/i.test(value)) setGoalStage(false); }, [slashQuery]);

  function pickSlash(i: number) {
    const item = slashItems[i];
    if (!item) return;
    if (goalStage) { ws.setGoal(item.cmd as GoalId); setGoalStage(false); onChange(""); return; }
    if (item.cmd === "/goal") { onChange("/goal"); setGoalStage(true); setSlashIdx(0); return; }
    submit(item.cmd);
  }
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
      if (e.key === "Tab" && !goalStage) { e.preventDefault(); onChange(slashItems[slashIdx]!.cmd + " "); return; }
      if (e.key === "Enter" || e.key === "Tab") { e.preventDefault(); pickSlash(slashIdx); return; }
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); if (goalStage) setGoalStage(false); else setSlashDismissed(true); return; }
    }
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
  }

  const ModeIcon = MODE_ICON[ws.mode];
  const TargetIcon = ws.target.kind === "repo" ? FolderGit2 : Globe;

  return (
    <div className={cn("composer-wrap", `is-${variant}`)}>
      <div className="composer">
        {slashOpen && (
          <div className="slashmenu" role="listbox" id={`${id}-slash`} aria-label={goalStage ? "Objectifs" : "Commandes"}>
            {goalStage && <div className="slash-head"><Goal size={13} aria-hidden="true" />Objectif: l'agent continue jusqu'à l'atteindre</div>}
            {slashItems.map((s, i) => (
              <div key={s.cmd} id={`${id}-slash-${i}`} role="option" aria-selected={i === slashIdx}
                className={cn("slash-opt", goalStage && "goal", i === slashIdx && "on")}
                onMouseEnter={() => setSlashIdx(i)}
                onMouseDown={(e) => { e.preventDefault(); pickSlash(i); }}>
                <span className={goalStage ? "slash-g" : "mono"}>{s.label}</span><span className="slash-d">{s.desc}</span>
                {goalStage && ws.goal === s.cmd && <Check size={14} className="slash-ck" aria-hidden="true" />}
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
          <Picker
            label="Ajouter" value={ws.goal as string} placement={placement} buttonClassName="tbtn icon"
            onChange={(v) => { if (v === "__file") fileRef.current?.click(); else ws.setGoal(v as GoalId); }}
            options={[
              { value: "__file", label: "Joindre un fichier", icon: <Paperclip size={15} /> },
              ...GOALS.filter((g) => g.id !== "none").map((g) => ({ value: g.id as string, label: g.label, desc: g.desc, icon: <Goal size={15} /> })),
              ...(ws.goal !== "none" ? [{ value: "none", label: "Retirer l'objectif", icon: <X size={15} /> }] : []),
            ]}
          >
            <Plus size={16} aria-hidden="true" />
          </Picker>
          <Picker
            label="Permissions" value={ws.mode} onChange={ws.setMode} placement={placement}
            buttonClassName={cn("tbtn", ws.mode === "bypass" && "warn")}
            options={MODES.map((m) => { const I = MODE_ICON[m.id]; return { value: m.id, label: m.label, desc: m.desc, icon: <I size={15} /> }; })}
          >
            <ModeIcon size={14} aria-hidden="true" /><span className="tlabel">{ws.mode === "bypass" ? "Bypass" : MODES.find((m) => m.id === ws.mode)!.label}</span>
            <ChevronDown size={13} className="faint" aria-hidden="true" />
          </Picker>
          <ExploreMenu placement={placement} />
          {ws.goal !== "none" && (
            <Tooltip content={`Objectif: ${goalOf(ws.goal).label} · cliquer pour le retirer`}>
              <button type="button" className="tbtn icon goal-on" aria-label={`Retirer l'objectif: ${goalOf(ws.goal).label}`} onClick={() => ws.setGoal("none")}>
                <Goal size={15} aria-hidden="true" />
              </button>
            </Tooltip>
          )}
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
