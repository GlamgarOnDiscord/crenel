/* Adapted from prompt-kit `loader.tsx` by Julien Thibeaut (ibelick),
   https://github.com/ibelick/prompt-kit, MIT License: the "bars", "dots" and
   "terminal" variants, keyframes in transitions.css. */
import { cn } from "../../lib/utils";

export function Loader({ variant = "bars", className, label = "Chargement" }: { variant?: "bars" | "dots" | "terminal"; className?: string; label?: string }) {
  if (variant === "terminal") {
    return (
      <span className={cn("inline-flex items-center gap-1 font-mono text-[12px] text-fg-faint", className)} role="status">
        <span>{">"}</span><span className="pk-cursor h-3.5 w-[7px] bg-brand" /><span className="sr-only">{label}</span>
      </span>
    );
  }
  if (variant === "dots") {
    return (
      <span className={cn("inline-flex h-4 items-center gap-1", className)} role="status">
        {[0, 1, 2].map((i) => <span key={i} className="pk-bounce size-1.5 rounded-full bg-brand" style={{ animationDelay: `${i * 160}ms` }} />)}
        <span className="sr-only">{label}</span>
      </span>
    );
  }
  return (
    <span className={cn("inline-flex h-3.5 items-end gap-[3px]", className)} role="status">
      {[0, 1, 2].map((i) => <span key={i} className="pk-wave h-full w-[3px] rounded-[1px] bg-brand" style={{ animationDelay: `${i * 0.2}s` }} />)}
      <span className="sr-only">{label}</span>
    </span>
  );
}
