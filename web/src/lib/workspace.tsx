import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { targets } from "../data/mock.ts";
import type { Target } from "./types.ts";

// Shared choices of the composer (target, model, effort, mode). They live in a
// small context mounted by the Shell, so Home and Agent stay in sync.

export const MODELS = [
  { id: "opus", label: "Opus 5.5", desc: "Le plus capable, pour les audits profonds." },
  { id: "sonnet", label: "Sonnet 5.5", desc: "Équilibré: rapide et précis." },
  { id: "haiku", label: "Haiku 5.5", desc: "Le plus rapide, pour les vérifications simples." },
] as const;
export type ModelId = (typeof MODELS)[number]["id"];

export const EFFORTS = [
  { id: "low", label: "Bas", level: 1, desc: "Survol rapide, peu de tokens." },
  { id: "med", label: "Moyen", level: 2, desc: "Le bon réglage par défaut." },
  { id: "high", label: "Élevé", level: 3, desc: "Creuse chaque piste avant de conclure." },
  { id: "max", label: "Max", level: 4, desc: "Tout explorer, quel que soit le coût." },
] as const;
export type EffortId = (typeof EFFORTS)[number]["id"];

export const MODES = [
  { id: "readonly", label: "Lecture seule", desc: "Analyse, et demande avant toute requête vers un hôte." },
  { id: "plan", label: "Plan", desc: "Prépare le plan d'attaque sans rien exécuter." },
  { id: "probes", label: "Sondes autorisées", desc: "Envoie des requêtes aux hôtes déclarés sans redemander." },
] as const;
export type ModeId = (typeof MODES)[number]["id"];

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
  mode: "readonly", setMode: noop,
});

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [targetId, setTargetId] = useState(targets[0]!.id);
  const [model, setModel] = useState<ModelId>("opus");
  const [effort, setEffort] = useState<EffortId>("med");
  const [mode, setMode] = useState<ModeId>("readonly");
  const value = useMemo<Workspace>(() => ({
    target: targets.find((t) => t.id === targetId) ?? targets[0]!,
    setTargetId, model, setModel, effort, setEffort, mode, setMode,
  }), [targetId, model, effort, mode]);
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace() {
  return useContext(WorkspaceContext);
}

export const modelLabel = (id: ModelId) => MODELS.find((m) => m.id === id)!.label;
export const effortOf = (id: EffortId) => EFFORTS.find((e) => e.id === id)!;
export const modeLabel = (id: ModeId) => MODES.find((m) => m.id === id)!.label;
