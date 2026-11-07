/* Adapted from Vercel AI Elements `context.tsx` (Apache-2.0, see NOTICE.txt):
   a hover card with context usage, the ring icon, per-kind token rows and the
   window. tokenlens removed; the bar is the Arc UI Progress. */
import * as HoverCard from "@radix-ui/react-hover-card";
import { createContext, useContext, useMemo, type ReactNode } from "react";
import { Progress } from "../arc/progress/progress";

interface Ctx { usedTokens: number; maxTokens: number; usage?: { input: number; output: number; reasoning: number } }
const ContextContext = createContext<Ctx | null>(null);
const useCtx = () => { const c = useContext(ContextContext); if (!c) throw new Error("Context components must be used within Context"); return c; };
const pct = new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 1, style: "percent" });
const compact = new Intl.NumberFormat("fr-FR", { notation: "compact" });

export function Context({ children, ...v }: Ctx & { children: ReactNode }) {
  const value = useMemo(() => v, [v.usedTokens, v.maxTokens, v.usage]); // eslint-disable-line
  return <ContextContext.Provider value={value}><HoverCard.Root openDelay={80} closeDelay={60}>{children}</HoverCard.Root></ContextContext.Provider>;
}
function ContextIcon() {
  const { usedTokens, maxTokens } = useCtx();
  const r = 10, c = 2 * Math.PI * r, p = usedTokens / maxTokens;
  return (
    <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r={r} fill="none" stroke="currentColor" strokeWidth="2.5" opacity=".25" />
      <circle cx="12" cy="12" r={r} fill="none" stroke="currentColor" strokeWidth="2.5" opacity=".8" strokeLinecap="round"
        strokeDasharray={`${c} ${c}`} strokeDashoffset={c * (1 - p)} style={{ transform: "rotate(-90deg)", transformOrigin: "center", transition: "stroke-dashoffset .4s var(--ease-standard)" }} />
    </svg>
  );
}
export function ContextTrigger() {
  const { usedTokens, maxTokens } = useCtx();
  return (
    <HoverCard.Trigger asChild>
      <button type="button" className="tbtn ctxbtn" aria-label={`Contexte utilisé: ${pct.format(usedTokens / maxTokens)}`}>
        <span className="font-mono text-[11.5px] text-fg-faint">{pct.format(usedTokens / maxTokens)}</span>
        <ContextIcon />
      </button>
    </HoverCard.Trigger>
  );
}
export function ContextContent() {
  const { usedTokens, maxTokens, usage } = useCtx();
  return (
    <HoverCard.Portal>
      <HoverCard.Content side="top" align="end" sideOffset={8} className="ctx-card t-pop">
        <div className="p-3">
          <div className="mb-2 flex items-center justify-between text-[12px]">
            <span className="text-fg-muted">Contexte</span>
            <span className="font-mono text-fg">{compact.format(usedTokens)} / {compact.format(maxTokens)}</span>
          </div>
          <Progress value={usedTokens} max={maxTokens} label="Contexte utilisé" />
        </div>
        {usage && (
          <div className="border-t border-line p-3 text-[12px]">
            {([["Entrée", usage.input], ["Sortie", usage.output], ["Réflexion", usage.reasoning]] as const).map(([l, n]) => (
              <div key={l} className="flex items-center justify-between py-0.5"><span className="text-fg-faint">{l}</span><span className="font-mono text-fg-muted">{compact.format(n)}</span></div>
            ))}
          </div>
        )}
      </HoverCard.Content>
    </HoverCard.Portal>
  );
}
