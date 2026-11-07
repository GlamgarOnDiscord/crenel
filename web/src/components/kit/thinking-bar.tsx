/* Adapted from prompt-kit `thinking-bar.tsx` by Julien Thibeaut (ibelick),
   https://github.com/ibelick/prompt-kit, MIT License (also on 21st.dev). */
import { ChevronRight } from "lucide-react";
import { cn } from "../../lib/utils";
import { Shimmer } from "../ai/shimmer";

export function ThinkingBar({ className, text = "Réflexion", onStop, stopLabel = "Répondre maintenant", onClick }: {
  className?: string; text?: string; onStop?: () => void; stopLabel?: string; onClick?: () => void;
}) {
  return (
    <div className={cn("flex w-full items-center justify-between text-[13px]", className)}>
      {onClick ? (
        <button type="button" onClick={onClick} className="flex items-center gap-1 transition-opacity hover:opacity-80">
          <Shimmer className="font-medium">{text}</Shimmer><ChevronRight className="size-3.5 text-fg-faint" />
        </button>
      ) : <Shimmer className="cursor-default font-medium">{text}</Shimmer>}
      {onStop && (
        <button type="button" onClick={onStop} className="border-b border-dotted border-fg-ghost text-fg-faint transition-colors hover:border-fg hover:text-fg">{stopLabel}</button>
      )}
    </div>
  );
}
