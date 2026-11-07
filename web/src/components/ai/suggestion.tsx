/* Adapted from Vercel AI Elements `suggestion.tsx` (Apache-2.0, see NOTICE.txt). */
import type { ComponentProps } from "react";
import { cn } from "../../lib/utils";

export function Suggestions({ className, ...props }: ComponentProps<"div">) {
  return (
    <div className="w-full overflow-x-auto [scrollbar-width:none]">
      <div className={cn("flex w-max flex-nowrap items-center gap-2", className)} {...props} />
    </div>
  );
}
export function Suggestion({ suggestion, onClick, className, children }: { suggestion: string; onClick?: (s: string) => void; className?: string; children?: React.ReactNode }) {
  return (
    <button type="button" onClick={() => onClick?.(suggestion)}
      className={cn("sugg-b rounded-full", className)}>
      {children ?? suggestion}
    </button>
  );
}
