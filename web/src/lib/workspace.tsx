import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { useData } from "../data/api.ts";
import { targets } from "../data/mock.ts";
import type { Provider } from "../brand/ModelLogo.tsx";
import type { Target } from "./types.ts";

// Shared choices of the composer (target, model, effort, mode). They live in a
// small context mounted by the Shell, so Home and Agent stay in sync.

export const MODELS = [
  { id: "opus", label: "Opus 5.5", provider: "claude", vendor: "Anthropic", desc: "Le plus capable, pour les audits profonds." },
  { id: "sonnet", label: "Sonnet 5.5", provider: "claude", vendor: "Anthropic", desc: "Rapide et précis, le bon défaut." },
  { id: "haiku", label: "Haiku 5.5", provider: "claude", vendor: "Anthropic", desc: "Le plus rapide, pour les vérifications simples." },
  { id: "gpt", label: "GPT-5.5", provider: "openai", vendor: "OpenAI", desc: "Modèle généraliste d'OpenAI." },
  { id: "gemini", label: "Gemini 3.5", provider: "gemini", vendor: "Google", desc: "Grande fenêtre de contexte, pour les gros dépôts." },
  { id: "mistral", label: "Mistral Large", provider: "mistral", vendor: "Mistral AI", desc: "Hébergé en Europe." },
] as const;
export type ModelId = (typeof MODELS)[number]["id"];

/* ---------------- custom / local models ----------------
   The composer can point a run at a model the engine reaches over HTTP (see
   src/agent/llm.ts): an OpenAI-compatible endpoint, a native Ollama, or the
   Anthropic Messages API. The console never holds a key: it keeps only the NAME
   of the environment variable that holds it; the engine reads the value at call
   time. Custom models are stored per-browser in localStorage. */
export type CustomProvider = "openai-compatible" | "ollama" | "anthropic-api";

export interface CustomModel {
  /** Stable local id, "cm-…". Used as ws.model when this model is active. */
  id: string;
  provider: CustomProvider;
  /** Model name sent to the provider, e.g. "llama3.1" or "gpt-4o-mini". */
  name: string;
  /** Optional endpoint; the engine's default is used when empty. */
  baseUrl?: string;
  /** Optional NAME of the env var holding the API key (never the key itself). */
  apiKeyEnv?: string;
  /** Optional sampling temperature (0..2). */
  temperature?: number;
}

export const PROVIDERS: { id: CustomProvider; label: string; logo: Provider; prefix: string; basePlaceholder: string; needsKey: boolean }[] = [
  { id: "openai-compatible", label: "OpenAI compatible", logo: "openai", prefix: "openai", basePlaceholder: "https://api.openai.com (ou http://127.0.0.1:1234/v1)", needsKey: true },
  { id: "ollama", label: "Ollama", logo: "custom", prefix: "ollama", basePlaceholder: "http://127.0.0.1:11434", needsKey: false },
  { id: "anthropic-api", label: "Anthropic API", logo: "claude", prefix: "anthropic-api", basePlaceholder: "https://api.anthropic.com", needsKey: true },
] as const;

export const providerOf = (id: CustomProvider) => PROVIDERS.find((p) => p.id === id)!;
/** The engine spec for a custom model: "openai:<name>", "ollama:<name>", "anthropic-api:<name>". */
export const customSpec = (m: CustomModel) => `${providerOf(m.provider).prefix}:${m.name}`;

const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/;

export interface ModelDraft { provider: CustomProvider; name: string; baseUrl: string; apiKeyEnv: string; temperature: string }
export const emptyDraft = (): ModelDraft => ({ provider: "openai-compatible", name: "", baseUrl: "", apiKeyEnv: "", temperature: "" });

/** Soft validation of the config card. Returns a field->message map (empty = ok). */
export function validateDraft(d: ModelDraft): Partial<Record<keyof ModelDraft, string>> {
  const e: Partial<Record<keyof ModelDraft, string>> = {};
  if (!d.name.trim()) e.name = "Nom du modèle requis.";
  if (d.apiKeyEnv.trim() && !ENV_NAME.test(d.apiKeyEnv.trim())) e.apiKeyEnv = "MAJUSCULES et underscore, ex. CRENEL_LLM_API_KEY.";
  if (d.baseUrl.trim() && /\s/.test(d.baseUrl.trim())) e.baseUrl = "URL invalide.";
  if (d.temperature.trim()) { const t = Number(d.temperature); if (!Number.isFinite(t) || t < 0 || t > 2) e.temperature = "Entre 0 et 2."; }
  return e;
}

/** Build a CustomModel from a valid draft (caller checks validateDraft first). */
export function draftToModel(d: ModelDraft, id = `cm-${Math.random().toString(36).slice(2, 9)}`): CustomModel {
  const t = d.temperature.trim() ? Number(d.temperature) : undefined;
  return {
    id, provider: d.provider, name: d.name.trim(),
    baseUrl: d.baseUrl.trim() || undefined, apiKeyEnv: d.apiKeyEnv.trim() || undefined,
    temperature: t !== undefined && Number.isFinite(t) ? t : undefined,
  };
}

const CUSTOM_KEY = "crenel.customModels";
const MODEL_KEY = "crenel.model";

/** Parse and sanitise the custom models stored in localStorage. Never throws. */
export function parseCustomModels(raw: string | null): CustomModel[] {
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.filter((m): m is CustomModel =>
      !!m && typeof m.id === "string" && typeof m.name === "string" && PROVIDERS.some((p) => p.id === m.provider),
    ).map((m) => ({
      id: m.id, provider: m.provider, name: m.name,
      ...(typeof m.baseUrl === "string" ? { baseUrl: m.baseUrl } : {}),
      ...(typeof m.apiKeyEnv === "string" ? { apiKeyEnv: m.apiKeyEnv } : {}),
      ...(typeof m.temperature === "number" ? { temperature: m.temperature } : {}),
    }));
  } catch { return []; }
}

const canStore = () => typeof window !== "undefined" && !!window.localStorage;
function loadCustomModels(): CustomModel[] {
  if (!canStore()) return [];
  try { return parseCustomModels(window.localStorage.getItem(CUSTOM_KEY)); } catch { return []; }
}
function saveCustomModels(list: CustomModel[]): void {
  if (!canStore()) return;
  try { window.localStorage.setItem(CUSTOM_KEY, JSON.stringify(list)); } catch { /* storage full or blocked */ }
}
function loadModelId(fallback: string): string {
  if (!canStore()) return fallback;
  try { return window.localStorage.getItem(MODEL_KEY) || fallback; } catch { return fallback; }
}
function saveModelId(id: string): void {
  if (!canStore()) return;
  try { window.localStorage.setItem(MODEL_KEY, id); } catch { /* ignore */ }
}

/** Display info for the active model, whether a built-in id or a custom one. */
export function activeModelView(model: string, custom: CustomModel[]): { label: string; provider: Provider; custom: boolean } {
  const m = MODELS.find((x) => x.id === model);
  if (m) return { label: m.label, provider: m.provider, custom: false };
  const c = custom.find((x) => x.id === model);
  if (c) return { label: c.name, provider: providerOf(c.provider).logo, custom: true };
  const d = MODELS[0]!;
  return { label: d.label, provider: d.provider, custom: false };
}

/** What `start(...)` sends: a built-in id passes through; a custom id becomes its spec + connection (never a key value). */
export function modelSend(model: string, custom: CustomModel[]): { model: string; modelBaseUrl?: string; modelApiKeyEnv?: string } {
  const c = custom.find((x) => x.id === model);
  if (!c) return { model };
  return { model: customSpec(c), modelBaseUrl: c.baseUrl || undefined, modelApiKeyEnv: c.apiKeyEnv || undefined };
}

export const EFFORTS = [
  { id: "low", label: "Bas", level: 1 },
  { id: "med", label: "Moyen", level: 2 },
  { id: "high", label: "Élevé", level: 3 },
  { id: "max", label: "Max", level: 4 },
] as const;
export type EffortId = (typeof EFFORTS)[number]["id"];

export const MODES = [
  { id: "ask", label: "Demander avant chaque sonde", short: "Demander", desc: "Analyse librement, demande avant toute requête vers un hôte." },
  { id: "readonly", label: "Lecture seule", short: "Lecture seule", desc: "N'envoie aucune requête: bundle, dépôt et dépendances seulement." },
  { id: "bypass", label: "Bypass all permissions", short: "Bypass", desc: "N'interrompt jamais pour demander: envoie toutes les sondes que le périmètre autorise. Chaque sonde est inscrite à l'audit." },
] as const;
export type ModeId = (typeof MODES)[number]["id"];

// Free exploration on top of the fixed plan: the model picks its own requests
// and reads within the perimeter; only a validator's replay proves anything.
export const EXPLORES = [
  { id: "off", label: "Exploration coupée", short: "Coupée", desc: "Seulement le plan fixe de Crenel." },
  { id: "assist", label: "Exploration assistée", short: "Assistée", desc: "Le modèle explore en lecture (HTTP GET, code, JS servi), petit budget. Chaque affirmation est rejouée." },
  { id: "full", label: "Exploration complète", short: "Complète", desc: "Ajoute la boîte à outils avec arguments libres et les écritures, toujours via la porte et allowActiveTesting." },
] as const;
export type ExploreId = (typeof EXPLORES)[number]["id"];

// Goals, like /goal: the agent keeps going until the objective is met (checked
// by code), a budget runs out, or you stop it. Free text: type /goal <texte>.
export const GOALS = [
  { id: "none", label: "Aucun objectif", short: "Définir un objectif", desc: "Une seule passe, puis l'agent s'arrête.", text: "" },
  { id: "crit", label: "Aucun critique prouvé", short: "Aucun critique prouvé", desc: "Vérifié par le code sur les findings.", text: "aucun finding critique prouvé" },
  { id: "authz", label: "Isolation entre comptes prouvée", short: "Isolation prouvée", desc: "Toutes les ressources déclarées, vérifié par le code.", text: "prouver l'isolation entre comptes sur toutes les ressources" },
  { id: "tests", label: "Chaque faille prouvée a son test", short: "Failles testées", desc: "Un test de régression généré par faille prouvée.", text: "100 % des failles prouvées gardées en CI" },
] as const;
export type GoalId = (typeof GOALS)[number]["id"];

export const CONTEXT_WINDOW: Record<string, number> = {
  opus: 200_000, sonnet: 200_000, haiku: 200_000, gpt: 400_000, gemini: 1_000_000, mistral: 128_000,
};
/** Context window for any model id (built-in or custom); a safe default otherwise. */
export const contextWindowOf = (model: string) => CONTEXT_WINDOW[model] ?? 128_000;

interface Workspace {
  target: Target;
  setTargetId: (id: string) => void;
  model: string;
  setModel: (m: string) => void;
  customModels: CustomModel[];
  addCustomModel: (m: CustomModel) => void;
  removeCustomModel: (id: string) => void;
  effort: EffortId;
  setEffort: (e: EffortId) => void;
  mode: ModeId;
  setMode: (m: ModeId) => void;
  goal: GoalId;
  setGoal: (g: GoalId) => void;
  /** null: the config's choice (data.explore). */
  explore: ExploreId | null;
  setExplore: (e: ExploreId) => void;
}

const noop = () => {};
const WorkspaceContext = createContext<Workspace>({
  target: targets[0]!, setTargetId: noop,
  model: "opus", setModel: noop,
  customModels: [], addCustomModel: noop, removeCustomModel: noop,
  effort: "med", setEffort: noop,
  mode: "ask", setMode: noop,
  goal: "none", setGoal: noop,
  explore: null, setExplore: noop,
});

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [targetId, setTargetId] = useState(targets[0]!.id);
  const [customModels, setCustomModels] = useState<CustomModel[]>(() => loadCustomModels());
  const [model, setModelState] = useState<string>(() => loadModelId("opus"));
  const [effort, setEffort] = useState<EffortId>("med");
  const [mode, setMode] = useState<ModeId>("ask");
  const [goal, setGoal] = useState<GoalId>("none");
  const [explore, setExplore] = useState<ExploreId | null>(null);
  const data = useData();
  const value = useMemo<Workspace>(() => {
    const setModel = (m: string) => { setModelState(m); saveModelId(m); };
    const addCustomModel = (m: CustomModel) => setCustomModels((l) => { const next = [...l.filter((x) => x.id !== m.id), m]; saveCustomModels(next); return next; });
    const removeCustomModel = (id: string) => setCustomModels((l) => { const next = l.filter((x) => x.id !== id); saveCustomModels(next); if (model === id) setModel("opus"); return next; });
    return {
      target: data.targets.find((t) => t.id === targetId) ?? data.targets[0]!,
      setTargetId, model, setModel, customModels, addCustomModel, removeCustomModel,
      effort, setEffort, mode, setMode, goal, setGoal, explore, setExplore,
    };
  }, [targetId, model, customModels, effort, mode, goal, explore, data.targets]);
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace() {
  return useContext(WorkspaceContext);
}

export const modelOf = (id: ModelId) => MODELS.find((m) => m.id === id)!;
export const modelLabel = (id: ModelId) => modelOf(id).label;
export const effortOf = (id: EffortId) => EFFORTS.find((e) => e.id === id)!;
export const modeOf = (id: ModeId) => MODES.find((m) => m.id === id)!;
export const modeLabel = (id: ModeId) => modeOf(id).short;
export const goalOf = (id: GoalId) => GOALS.find((g) => g.id === id)!;
