/* Adapted from Vercel AI Elements `plan.tsx` and `task.tsx` (Apache-2.0, see
   NOTICE.txt): a collapsible Plan card (title shimmers while streaming) whose
   content lists TaskItems. Progress uses the Arc UI Progress bar. */
import * as Collapsible from "@radix-ui/react-collapsible";
import { ChevronsUpDown } from "lucide-react";
import { createContext, useContext, useMemo, type ReactNode } from "react";
import { cn } from "../../lib/utils";
import { Shimmer } from "./shimmer";

const PlanContext = createContext<{ isStreaming: boolean }>({ isStreaming: false });

export function Plan({ isStreaming = false, defaultOpen = true, className, children }: { isStreaming?: boolean; defaultOpen?: boolean; className?: string; children: ReactNode }) {
  const v = useMemo(() => ({ isStreaming }), [isStreaming]);
  return (
    <PlanContext.Provider value={v}>
      <Collapsible.Root defaultOpen={defaultOpen} className={cn("plan", className)}>{children}</Collapsible.Root>
    </PlanContext.Provider>
  );
}
export function PlanHeader({ children }: { children: ReactNode }) {
  return <div className="flex items-center gap-3 px-4 pb-1 pt-3">{children}</div>;
}
export function PlanTitle({ children }: { children: string }) {
  const { isStreaming } = useContext(PlanContext);
  return <h3 className="font-sans text-[14px] font-medium text-fg">{isStreaming ? <Shimmer>{children}</Shimmer> : children}</h3>;
}
export function PlanAction({ children }: { children: ReactNode }) {
  return <div className="ml-auto flex items-center gap-3">{children}</div>;
}
export function PlanTrigger() {
  return (
    <Collapsible.Trigger className="iconbtn sm" aria-label="Replier ou déplier le plan">
      <ChevronsUpDown className="size-3.5" />
    </Collapsible.Trigger>
  );
}
export function PlanContent({ children }: { children: ReactNode }) {
  return <Collapsible.Content className="t-collapse"><div className="px-4 pb-3 pt-1">{children}</div></Collapsible.Content>;
}
export function TaskItem({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("text-[13px] text-fg-faint", className)}>{children}</div>;
}
export function TaskItemFile({ children }: { children: ReactNode }) {
  return <span className="inline-flex items-center gap-1 rounded-md border border-line bg-raised px-1.5 py-0.5 font-mono text-[11.5px] text-fg">{children}</span>;
}
