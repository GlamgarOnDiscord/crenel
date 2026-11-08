import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { useData } from "../data/api.ts";
import { targets } from "../data/mock.ts";
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

export const CONTEXT_WINDOW: Record<ModelId, number> = {
  opus: 200_000, sonnet: 200_000, haiku: 200_000, gpt: 400_000, gemini: 1_000_000, mistral: 128_000,
};

interface Workspace {
  target: Target;
  setTargetId: (id: string) => void;
  model: ModelId;
  setModel: (m: ModelId) => void;
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
  effort: "med", setEffort: noop,
  mode: "ask", setMode: noop,
  goal: "none", setGoal: noop,
  explore: null, setExplore: noop,
});

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [targetId, setTargetId] = useState(targets[0]!.id);
  const [model, setModel] = useState<ModelId>("opus");
  const [effort, setEffort] = useState<EffortId>("med");
  const [mode, setMode] = useState<ModeId>("ask");
  const [goal, setGoal] = useState<GoalId>("none");
  const [explore, setExplore] = useState<ExploreId | null>(null);
  const data = useData();
  const value = useMemo<Workspace>(() => ({
    target: data.targets.find((t) => t.id === targetId) ?? data.targets[0]!,
    setTargetId, model, setModel, effort, setEffort, mode, setMode, goal, setGoal, explore, setExplore,
  }), [targetId, model, effort, mode, goal, explore, data.targets]);
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
