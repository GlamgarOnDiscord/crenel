/* Adapted from Vercel AI Elements `reasoning.tsx` (Apache-2.0, see NOTICE.txt):
   same compound API (Reasoning, ReasoningTrigger, ReasoningContent), auto-open
   while streaming, auto-close one second after, duration measured. */
import * as Collapsible from "@radix-ui/react-collapsible";
import { useControllableState } from "@radix-ui/react-use-controllable-state";
import { Brain, ChevronDown } from "lucide-react";
import { createContext, memo, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { cn } from "../../lib/utils";
import { Shimmer } from "./shimmer";

interface Ctx { isStreaming: boolean; isOpen: boolean; setIsOpen: (o: boolean) => void; duration: number | undefined }
const ReasoningContext = createContext<Ctx | null>(null);
const useReasoning = () => {
  const c = useContext(ReasoningContext);
  if (!c) throw new Error("Reasoning components must be used within Reasoning");
  return c;
};

const AUTO_CLOSE_DELAY = 1000;

export const Reasoning = memo(function Reasoning({ className, isStreaming = false, defaultOpen, duration: durationProp, children }: {
  className?: string; isStreaming?: boolean; defaultOpen?: boolean; duration?: number; children: ReactNode;
}) {
  const [isOpen, setIsOpen] = useControllableState<boolean>({ defaultProp: defaultOpen ?? isStreaming });
  const [duration, setDuration] = useState<number | undefined>(durationProp);
  const ever = useRef(isStreaming);
  const start = useRef<number | null>(null);
  const [autoClosed, setAutoClosed] = useState(false);

  useEffect(() => {
    if (isStreaming) { ever.current = true; if (start.current === null) start.current = Date.now(); }
    else if (start.current !== null) { setDuration(Math.max(1, Math.ceil((Date.now() - start.current) / 1000))); start.current = null; }
  }, [isStreaming]);
  useEffect(() => { if (isStreaming && !isOpen && defaultOpen !== false) setIsOpen(true); }, [isStreaming, isOpen, setIsOpen, defaultOpen]);
  useEffect(() => {
    if (ever.current && !isStreaming && isOpen && !autoClosed) {
      const t = setTimeout(() => { setIsOpen(false); setAutoClosed(true); }, AUTO_CLOSE_DELAY);
      return () => clearTimeout(t);
    }
  }, [isStreaming, isOpen, setIsOpen, autoClosed]);

  const value = useMemo(() => ({ duration: durationProp ?? duration, isOpen: !!isOpen, isStreaming, setIsOpen }), [durationProp, duration, isOpen, isStreaming, setIsOpen]);
  return (
    <ReasoningContext.Provider value={value}>
      <Collapsible.Root className={cn("reasoning", className)} open={!!isOpen} onOpenChange={setIsOpen}>{children}</Collapsible.Root>
    </ReasoningContext.Provider>
  );
});

export function ReasoningTrigger({ className }: { className?: string }) {
  const { isStreaming, isOpen, duration } = useReasoning();
  return (
    <Collapsible.Trigger className={cn("flex w-fit items-center gap-2 text-[13px] text-fg-faint transition-colors hover:text-fg-muted", className)}>
      <Brain className="size-3.5" aria-hidden="true" />
      {isStreaming || duration === 0 ? <Shimmer duration={1.4}>Réflexion…</Shimmer>
        : <span>Réflexion · {duration === undefined ? "quelques secondes" : `${duration} s`}</span>}
      <ChevronDown className={cn("size-3.5 transition-transform duration-200", isOpen ? "rotate-180" : "rotate-0")} aria-hidden="true" />
    </Collapsible.Trigger>
  );
}

export function ReasoningContent({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <Collapsible.Content className={cn("t-collapse", className)}>
      <div className="ml-[7px] mt-2 border-l-2 border-line-strong pl-4 text-[13px] leading-relaxed text-fg-faint">{children}</div>
    </Collapsible.Content>
  );
}
