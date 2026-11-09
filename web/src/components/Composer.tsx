import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, ArrowUp, Check, ChevronDown, Compass, Eye, FolderGit2, Gauge, Globe, Goal, Hand, KeyRound, Mic, Paperclip, Plus, Radar, Search, Square, Trash2, TriangleAlert, X } from "lucide-react";
import { ModelLogo } from "../brand/ModelLogo.tsx";
import { ProviderIcon, hasProviderIcon } from "../brand/ProviderIcon.tsx";
import { useData } from "../data/api.ts";
import { cn } from "../lib/cn.ts";
import { CONNECTORS, EXPLORES, GOALS, MODELS, MODEL_KEY_ENVS, MODES, activeModelView, modelCaps, connectorOf, connectorToDraft, customSource, customSpec, draftNotes, draftToModel, effortOf, emptyDraft, goalOf, providerOf, useWorkspace, validateDraft, type Connector, type CustomModel, type GoalId, type ModeId, type ModelDraft } from "../lib/workspace.tsx";
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

/* A connector's mark: the provider's logo (brand/ProviderIcon), or a tinted
   "{}" tile for a generic OpenAI-compatible endpoint. */
export function ConnectorMark({ c, size = 22 }: { c: Connector | undefined; size?: number }) {
  if (c && hasProviderIcon(c.id)) return <span className="cmark logo" style={{ width: size, height: size }}><ProviderIcon id={c.id} size={Math.round(size * 0.64)} /></span>;
  const tint = c?.tint ?? "#A1A1AA";
  return (
    <span className="cmark mono" style={{ width: size, height: size, fontSize: Math.round(size * 0.42), color: tint, background: `color-mix(in srgb, ${tint} 16%, transparent)`, boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${tint} 30%, transparent)` }}>
      {c?.mono ?? "?"}
    </span>
  );
}

/* Adding a custom model, in two steps.
   1. Pick a connector: cloud providers, or a server on this machine.
   2. Type the model name. The connector pre-fills the endpoint and the NAME of
      the key's env var; whether that variable is set on the server shows right
      there (names only, never a value). Endpoint, key variable and temperature
      sit under "Réglages avancés", opened for "Autre point d'accès" or when one
      of them needs fixing. The checks are the server's. */
function CustomModelForm({ initial, onSave, onCancel }: { initial?: ModelDraft; onSave: (d: ModelDraft) => void; onCancel: () => void }) {
  const data = useData();
  const [draft, setDraft] = useState<ModelDraft>(() => initial ?? emptyDraft());
  const [step, setStep] = useState<"pick" | "details">(initial ? "details" : "pick");
  const [touched, setTouched] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [query, setQuery] = useState("");
  const errors = validateDraft(draft);
  const notes = draftNotes(draft);
  const prov = providerOf(draft.provider);
  const conn = connectorOf(draft.connector) ?? connectorOf("custom")!;
  const set = (patch: Partial<ModelDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const pick = (c: Connector) => { setDraft((d) => connectorToDraft(c, d.name)); setAdvanced(c.id === "custom"); setTouched(false); setStep("details"); };
  const valid = Object.keys(errors).length === 0;
  const submit = () => { setTouched(true); if (valid) onSave(draft); else if (errors.baseUrl || errors.apiKeyEnv || errors.temperature) setAdvanced(true); };
  const show = (k: keyof ModelDraft) => (touched || (k !== "name" && draft[k] !== "")) && errors[k];
  const advOpen = advanced || !!show("baseUrl") || !!show("apiKeyEnv") || !!show("temperature");
  const spec = `${prov.prefix}:${draft.name.trim() || "…"}`;
  const key = draft.apiKeyEnv.trim();
  const keySet = key && data.modelKeys ? data.modelKeys.includes(key) : null;

  if (step === "pick") {
    const q = query.trim().toLowerCase();
    const match = (c: Connector) => !q || c.label.toLowerCase().includes(q) || c.id.includes(q) || (c.baseUrl ?? "").includes(q);
    const ready = (c: Connector) => !!c.apiKeyEnv && !!data.modelKeys?.includes(c.apiKeyEnv);
    const tile = (c: Connector) => (
      <button key={c.id} type="button" className={cn("cmf-conn", c.id === "custom" && "wide")} onClick={() => pick(c)}
        title={c.baseUrl ?? "Un point d'accès compatible OpenAI à renseigner"}>
        <ConnectorMark c={c} size={24} />
        <span className="cmf-conn-l">{c.label}</span>
        {c.id === "custom" && <span className="cmf-conn-d">compatible OpenAI</span>}
        {ready(c) && <span className="cmf-ready" title={`${c.apiKeyEnv} est définie : prêt à l'emploi`} aria-label="clé définie" />}
      </button>
    );
    const cloud = CONNECTORS.filter((c) => !c.local && c.id !== "custom" && match(c));
    const local = [...CONNECTORS.filter((c) => c.local), connectorOf("custom")!].filter(match);
    const readyCount = CONNECTORS.filter(ready).length;
    return (
      <div className="cmf" role="group" aria-label="Choisir un connecteur">
        <div className="cmf-head">
          <button type="button" className="tbtn icon" aria-label="Retour à la liste" onClick={onCancel}><ArrowLeft size={15} /></button>
          <div className="cmf-head-t">
            <span className="cmf-title">Ajouter un modèle</span>
            <span className="cmf-sub">{readyCount > 0 ? `${readyCount} fournisseur${readyCount > 1 ? "s" : ""} avec une clé déjà définie` : "Choisissez où il tourne."}</span>
          </div>
        </div>
        <label className="cmf-search">
          <Search size={14} aria-hidden="true" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Rechercher un fournisseur" autoFocus spellCheck={false}
            onKeyDown={(e) => { if (e.key === "Enter") { const first = [...cloud, ...local][0]; if (first) { e.preventDefault(); pick(first); } } }} />
        </label>
        {cloud.length > 0 && <><span className="cmf-sec-l">Cloud</span><div className="cmf-conns">{cloud.map(tile)}</div></>}
        {local.length > 0 && <><span className="cmf-sec-l">Sur votre machine <em>sans clé</em></span><div className="cmf-conns">{local.map(tile)}</div></>}
        {cloud.length + local.length === 0 && <div className="cmf-empty">Aucun fournisseur ne correspond. <button type="button" onClick={() => pick(connectorOf("custom")!)}>Saisir un point d'accès</button></div>}
      </div>
    );
  }

  return (
    <div className="cmf" role="group" aria-label={`Nouveau modèle ${conn.label}`}
      onKeyDown={(e) => { if (e.key === "Enter" && (e.target as HTMLElement).tagName === "INPUT") { e.preventDefault(); submit(); } }}>
      <div className="cmf-head">
        <button type="button" className="tbtn icon" aria-label="Changer de connecteur" onClick={() => setStep("pick")}><ArrowLeft size={15} /></button>
        <div className="cmf-head-t"><span className="cmf-title">Nouveau modèle</span><span className="cmf-sub mono" title={`Envoyé au moteur : ${spec}`}>{spec}</span></div>
      </div>

      <div className="cmf-picked">
        <ConnectorMark c={conn} size={32} />
        <div className="cmf-picked-t">
          <b>{conn.label}</b>
          <span className="mono">{draft.baseUrl ? displayUrl(draft.baseUrl) : "point d'accès à renseigner"}</span>
        </div>
        <button type="button" className="cmf-change" onClick={() => setStep("pick")}>Changer</button>
      </div>

      <label className="cmf-field">
        <span className="cmf-lbl">Nom du modèle</span>
        <input className="cmf-in big mono" value={draft.name} placeholder={conn.example ?? "nom du modèle"} spellCheck={false} autoCorrect="off" autoCapitalize="off"
          onChange={(e) => set({ name: e.target.value })} aria-invalid={!!show("name")} autoFocus />
        {show("name") ? <span className="cmf-err">{errors.name}</span> : <span className="cmf-hint">Tel que {conn.local ? "le serveur local" : "le fournisseur"} le nomme{conn.example && !/fournisseur|nom du|…/.test(conn.example) ? `, par ex. ${conn.example}` : ""}.</span>}
      </label>

      <div className={cn("cmf-key", notes.apiKeyEnv ? "bad" : key ? (keySet === true ? "ok" : keySet === false ? "miss" : "info") : "info")}>
        <KeyRound size={14} aria-hidden="true" />
        {!key ? <span>{conn.local ? "Modèle local : aucune clé n'est envoyée." : "Aucune clé : seulement si le point d'accès n'en demande pas."}</span>
          : notes.apiKeyEnv ? <span><b className="mono">{key}</b> n'est pas une variable de clé de modèle : le serveur refusera de l'envoyer. Utilisez un nom <b className="mono">CRENEL_LLM_*</b> ou celui du fournisseur.</span>
          : keySet === true ? <span><b className="mono">{key}</b> est définie sur la machine qui lance Crenel.</span>
          : keySet === false ? <span><b className="mono">{key}</b> n'est pas définie : <code className="mono">export {key}=…</code> avant <code className="mono">crenel serve</code>.</span>
          : <span>La clé sera lue dans <b className="mono">{key}</b>, sur la machine qui lance Crenel.</span>}
      </div>

      <div className={cn("cmf-adv", advOpen && "open")}>
        <button type="button" className="cmf-adv-t" aria-expanded={advOpen} onClick={() => setAdvanced((o) => !o)}>
          <ChevronDown size={14} className="cmf-adv-chev" aria-hidden="true" />
          <span>Réglages avancés</span>
          {!advOpen && <span className="cmf-adv-sum mono">{[key || "sans clé", draft.temperature.trim() ? `t=${draft.temperature.trim()}` : null].filter(Boolean).join(" · ")}</span>}
        </button>
        {advOpen && (
          <div className="cmf-adv-b">
            <label className="cmf-field">
              <span className="cmf-lbl">Point d'accès</span>
              <input className="cmf-in mono" value={draft.baseUrl} placeholder={prov.basePlaceholder} spellCheck={false} autoCorrect="off" autoCapitalize="off"
                onChange={(e) => set({ baseUrl: e.target.value })} aria-invalid={!!show("baseUrl")} />
              {show("baseUrl") ? <span className="cmf-err">{errors.baseUrl}</span> : <span className="cmf-hint">https, ou http://localhost pour un modèle local.</span>}
            </label>
            <div className="cmf-row">
              <label className="cmf-field">
                <span className="cmf-lbl">Variable de la clé</span>
                <input className="cmf-in mono" value={draft.apiKeyEnv} placeholder={conn.local ? "aucune" : "OPENAI_API_KEY"} list="cmf-key-envs"
                  onChange={(e) => set({ apiKeyEnv: e.target.value.toUpperCase() })} aria-invalid={!!show("apiKeyEnv")}
                  autoCapitalize="characters" autoCorrect="off" spellCheck={false} />
                <datalist id="cmf-key-envs">{MODEL_KEY_ENVS.map((n) => <option key={n} value={n} />)}<option value="CRENEL_LLM_API_KEY" /></datalist>
              </label>
              <label className="cmf-field">
                <span className="cmf-lbl">Température</span>
                <input className="cmf-in mono" value={draft.temperature} placeholder="défaut" inputMode="decimal"
                  onChange={(e) => set({ temperature: e.target.value })} aria-invalid={!!show("temperature")} />
              </label>
            </div>
            {show("apiKeyEnv") && <span className="cmf-err">{errors.apiKeyEnv}</span>}
            {show("temperature") && <span className="cmf-err">{errors.temperature}</span>}
            <span className="cmf-hint">Le nom de la variable, jamais la clé : sa valeur ne quitte pas la machine qui lance Crenel, sauf vers ce point d'accès.</span>
          </div>
        )}
      </div>

      <div className="cmf-actions">
        <button type="button" className="btn quiet sm" onClick={onCancel}>Annuler</button>
        <button type="button" className="btn sm" onClick={submit} disabled={!draft.name.trim()}>Ajouter {draft.name.trim() ? "ce modèle" : "le modèle"}</button>
      </div>
    </div>
  );
}

// The connector a saved model shows: its preset, or one matching its provider.
const connectorFor = (m: CustomModel) => connectorOf(m.connector) ?? connectorOf(m.provider === "ollama" ? "ollama" : m.provider === "anthropic-api" ? "anthropic" : "custom");

// An endpoint as shown in the card: no scheme noise, no trailing slash.
const displayUrl = (u: string) => u.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");

/* Model + effort in one compact trigger, as in the Codex composer: the AI
   Elements ModelSelector (cmdk in a popover, grouped by vendor, logos) with
   the EffortControl on top, plus a "Modèles custom" group and its config card. */
function ModelMenu({ placement }: { placement: "up" | "down" }) {
  const ws = useWorkspace();
  const data = useData();
  const [open, setOpen] = useState(false);
  const [adding, setAdding] = useState(false);
  const view = activeModelView(ws.model, ws.customModels);
  const activeCustom = ws.customModels.find((m) => m.id === ws.model);
  const caps = modelCaps(ws.model, ws.customModels, data);
  const effort = effortOf(ws.effort);
  const closeMenu = () => { setOpen(false); setAdding(false); };
  const builtinCaps = modelCaps(MODELS[0]!.id, [], data);
  // A custom model's key, as the server sees it (names only): missing is worth a word.
  const keyMissing = (m: CustomModel) => !!m.apiKeyEnv && !!data.modelKeys && !data.modelKeys.includes(m.apiKeyEnv);
  return (
    <ModelSelector open={open} onOpenChange={(o) => { setOpen(o); if (!o) setAdding(false); }}>
      <ModelSelectorTrigger asChild>
        <button type="button" className={cn("tbtn modelbtn", !caps.available && "warn")} aria-label={`Modèle ${view.label}${caps.effort ? `, effort ${effort.label}` : ""}${caps.available ? "" : ", indisponible"}`}>
          {activeCustom ? <ConnectorMark c={connectorFor(activeCustom)} size={16} /> : <ModelLogo provider={view.provider} size={14} />}
          <span className="tlabel mb-name">{view.label}</span>
          {caps.effort && <>
            <span className="mb-sep" aria-hidden="true" />
            <EffortGauge level={effort.level} size={15} tone="muted" />
            <span className="tlabel mb-eff">{effort.label}</span>
          </>}
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
            {!caps.available && (
              <div className="msel-alert" role="status"><TriangleAlert size={14} aria-hidden="true" /><span><b>{view.label} ne peut pas tourner ici.</b> {caps.why} Installez Claude Code ou choisissez un de vos modèles.</span></div>
            )}
            {caps.effort ? <EffortControl value={ws.effort} onChange={ws.setEffort} /> : (
              <div className="msel-noeffort"><Gauge size={14} aria-hidden="true" /><span>{caps.why ?? "Pas de réglage d'effort pour ce modèle."}</span></div>
            )}
            <ModelSelectorCommand value={ws.model} label="Modèle">
              <ModelSelectorInput placeholder="Rechercher un modèle ou un fournisseur" />
              <ModelSelectorList>
                <ModelSelectorEmpty>Aucun modèle. <button type="button" className="msel-empty-add" onClick={() => setAdding(true)}>Ajouter un modèle</button></ModelSelectorEmpty>
                <ModelSelectorGroup heading={builtinCaps.available ? "Claude · via claude -p" : "Claude · indisponible, CLI claude introuvable"}>
                  {MODELS.map((m) => (
                    <ModelSelectorItem key={m.id} value={m.id} keywords={[m.label, m.vendor, "claude"]} disabled={!builtinCaps.available}
                      onSelect={() => { ws.setModel(m.id); closeMenu(); }} data-checked={m.id === ws.model || undefined}>
                      <ModelSelectorLogo provider={m.provider} />
                      <ModelSelectorName desc={m.desc} recommended={builtinCaps.available && "recommended" in m && m.recommended}>{m.label}</ModelSelectorName>
                      <Check size={14} className="msel-check" aria-hidden="true" />
                    </ModelSelectorItem>
                  ))}
                </ModelSelectorGroup>
                {ws.customModels.length > 0 && (
                  <ModelSelectorGroup heading="Vos modèles">
                    {ws.customModels.map((m) => (
                      <ModelSelectorItem key={m.id} value={m.id} keywords={[m.name, customSource(m).label, customSpec(m)]} onSelect={() => { ws.setModel(m.id); closeMenu(); }} data-checked={m.id === ws.model || undefined}>
                        <span className="msel-logo"><ConnectorMark c={connectorFor(m)} size={24} /></span>
                        <span className="msel-name">
                          <span className="msel-n">{m.name}</span>
                          <span className="msel-d">{customSource(m).label}{keyMissing(m) ? <> · <span className="msel-warn" title={`${m.apiKeyEnv} n'est pas définie sur la machine qui lance Crenel`}>clé absente</span></> : modelCaps(m.id, [m], data).effort ? " · effort réglable" : ""}</span>
                        </span>
                        <button type="button" className="msel-del" aria-label={`Supprimer ${m.name}`}
                          onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
                          onClick={(e) => { e.preventDefault(); e.stopPropagation(); ws.removeCustomModel(m.id); }}>
                          <Trash2 size={13} aria-hidden="true" />
                        </button>
                        <Check size={14} className="msel-check" aria-hidden="true" />
                      </ModelSelectorItem>
                    ))}
                  </ModelSelectorGroup>
                )}
                <ModelSelectorGroup heading="Autres fournisseurs">
                  <ModelSelectorItem value="__add-custom" className="msel-add" onSelect={() => setAdding(true)}
                    keywords={["ajouter", "custom", "local", ...CONNECTORS.flatMap((c) => [c.id, c.label]), "gpt", "chatgpt", "grok", "llama"]}>
                    <span className="msel-logo msel-logo-add" aria-hidden="true"><Plus size={16} /></span>
                    <span className="msel-name">
                      <span className="msel-n">Ajouter un modèle</span>
                      <span className="msel-stack" aria-hidden="true">
                        {["openai", "gemini", "mistral", "openrouter", "groq", "ollama"].map((id) => <ConnectorMark key={id} c={connectorOf(id)} size={18} />)}
                        <em>+{CONNECTORS.length - 6}</em>
                      </span>
                    </span>
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
