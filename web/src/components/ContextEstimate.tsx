/* The agent's context gauge. The console does not receive token counts from the
   run (the journal has none until run.end, and the server's own count is itself
   an estimate), so this is an estimate from the conversation's length, and the
   gauge says so ("≈"). Same look as components/ai/context.tsx. */
import * as HoverCard from "@radix-ui/react-hover-card";
import { Progress } from "./arc/progress/progress";

const pct = new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 1, style: "percent" });
const compact = new Intl.NumberFormat("fr-FR", { notation: "compact" });

export function ContextEstimate({ usedTokens, maxTokens }: { usedTokens: number; maxTokens: number }) {
  const p = Math.min(1, usedTokens / maxTokens);
  const r = 10, c = 2 * Math.PI * r;
  return (
    <HoverCard.Root openDelay={80} closeDelay={60}>
      <HoverCard.Trigger asChild>
        <button type="button" className="tbtn ctxbtn" aria-label={`Contexte utilisé, estimation: environ ${pct.format(p)}`}>
          <span className="font-mono text-[11.5px] text-fg-faint">≈ {pct.format(p)}</span>
          <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r={r} fill="none" stroke="currentColor" strokeWidth="2.5" opacity=".25" />
            <circle cx="12" cy="12" r={r} fill="none" stroke="currentColor" strokeWidth="2.5" opacity=".8" strokeLinecap="round"
              strokeDasharray={`${c} ${c}`} strokeDashoffset={c * (1 - p)} style={{ transform: "rotate(-90deg)", transformOrigin: "center", transition: "stroke-dashoffset .4s var(--ease-standard)" }} />
          </svg>
        </button>
      </HoverCard.Trigger>
      <HoverCard.Portal>
        <HoverCard.Content side="top" align="end" sideOffset={8} className="ctx-card t-pop">
          <div className="p-3">
            <div className="mb-2 flex items-center justify-between text-[12px]">
              <span className="text-fg-muted">Contexte (estimation)</span>
              <span className="font-mono text-fg">≈ {compact.format(usedTokens)} / {compact.format(maxTokens)}</span>
            </div>
            <Progress value={Math.min(usedTokens, maxTokens)} max={maxTokens} label="Contexte utilisé, estimation" />
          </div>
          <p className="ctx-note">Calculé par la console d'après la longueur de la conversation, pas un décompte du modèle.</p>
        </HoverCard.Content>
      </HoverCard.Portal>
    </HoverCard.Root>
  );
}
