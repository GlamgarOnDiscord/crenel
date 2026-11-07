import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
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
  { id: "probes", label: "Sondes autorisées", short: "Sondes autorisées", desc: "Envoie des requêtes aux hôtes déclarés sans redemander." },
] as const;
export type ModeId = (typeof MODES)[number]["id"];

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
}

const noop = () => {};
const WorkspaceContext = createContext<Workspace>({
  target: targets[0]!, setTargetId: noop,
  model: "opus", setModel: noop,
  effort: "med", setEffort: noop,
  mode: "ask", setMode: noop,
});

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [targetId, setTargetId] = useState(targets[0]!.id);
  const [model, setModel] = useState<ModelId>("opus");
  const [effort, setEffort] = useState<EffortId>("med");
  const [mode, setMode] = useState<ModeId>("ask");
  const value = useMemo<Workspace>(() => ({
    target: targets.find((t) => t.id === targetId) ?? targets[0]!,
    setTargetId, model, setModel, effort, setEffort, mode, setMode,
  }), [targetId, model, effort, mode]);
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
