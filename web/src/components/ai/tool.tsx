/* Adapted from Vercel AI Elements `tool.tsx` (Apache-2.0, see NOTICE.txt): Tool,
   ToolHeader with a status badge, ToolContent, ToolInput, ToolOutput. States and
   colours mapped to Crenel (running amber, proven red, done grey). */
import * as Collapsible from "@radix-ui/react-collapsible";
import { ChevronDown, CircleCheck, CircleDashed, Clock, ShieldAlert, Wrench, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "../../lib/utils";
import { Badge } from "../arc/badge/badge";
import { Shimmer } from "./shimmer";

export type ToolState = "input-streaming" | "input-available" | "approval-requested" | "approval-responded" | "output-available" | "output-denied" | "output-error" | "output-proven";

const LABEL: Record<ToolState, string> = {
  "input-streaming": "En attente", "input-available": "En cours", "approval-requested": "Votre accord",
  "approval-responded": "Répondu", "output-available": "Terminé", "output-denied": "Refusé",
  "output-error": "Erreur", "output-proven": "Faille prouvée",
};
const TONE: Record<ToolState, "neutral" | "success" | "warning" | "danger" | "info"> = {
  "input-streaming": "neutral", "input-available": "warning", "approval-requested": "warning",
  "approval-responded": "neutral", "output-available": "neutral", "output-denied": "neutral",
  "output-error": "danger", "output-proven": "danger",
};
const ICON: Record<ToolState, ReactNode> = {
  "input-streaming": <CircleDashed className="size-3" />, "input-available": <Clock className="size-3" />,
  "approval-requested": <Clock className="size-3" />, "approval-responded": <CircleCheck className="size-3" />,
  "output-available": <CircleCheck className="size-3" />, "output-denied": <XCircle className="size-3" />,
  "output-error": <XCircle className="size-3" />, "output-proven": <ShieldAlert className="size-3" />,
};

export const getStatusBadge = (s: ToolState) => <Badge size="sm" tone={TONE[s]} icon={ICON[s]}>{LABEL[s]}</Badge>;

export function Tool({ className, children, defaultOpen }: { className?: string; children: ReactNode; defaultOpen?: boolean }) {
  return <Collapsible.Root defaultOpen={defaultOpen} className={cn("tool group", className)}>{children}</Collapsible.Root>;
}

export function ToolHeader({ title, args, state, duration, className }: { title: string; args?: string; state: ToolState; duration?: string; className?: string }) {
  const running = state === "input-available";
  return (
    <Collapsible.Trigger className={cn("tool-hd", className)}>
      <Wrench className="size-3.5 shrink-0 text-fg-faint" aria-hidden="true" />
      <span className="tool-n">{running ? <Shimmer duration={1.2}>{title}</Shimmer> : title}</span>
      {args && <span className="tool-a">{args}</span>}
      <span className="sp" />
      {getStatusBadge(state)}
      {duration && !running && <span className="tool-d">{duration}</span>}
      <ChevronDown className="chev size-3.5 transition-transform duration-200 group-data-[state=open]:rotate-180" aria-hidden="true" />
    </Collapsible.Trigger>
  );
}

export function ToolContent({ children, className }: { children: ReactNode; className?: string }) {
  return <Collapsible.Content className={cn("t-collapse", className)}><div className="tool-b">{children}</div></Collapsible.Content>;
}

export function ToolInput({ input }: { input: string }) {
  return (
    <div className="tool-sec">
      <h4 className="tool-lab">Paramètres</h4>
      <pre>{input}</pre>
    </div>
  );
}

export function ToolOutput({ output, errorText }: { output?: ReactNode; errorText?: string }) {
  if (!output && !errorText) return null;
  return (
    <div className="tool-sec">
      <h4 className="tool-lab">{errorText ? "Erreur" : "Résultat"}</h4>
      <pre className={cn(errorText && "text-danger-ink")}>{errorText ?? output}</pre>
    </div>
  );
}
