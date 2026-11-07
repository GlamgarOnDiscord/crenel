/* Adapted from prompt-kit `steps.tsx` by Julien Thibeaut (ibelick),
   https://github.com/ibelick/prompt-kit, MIT License (also on 21st.dev). */
import * as Collapsible from "@radix-ui/react-collapsible";
import { ChevronDown } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "../../lib/utils";

export function Steps({ defaultOpen = true, className, children }: { defaultOpen?: boolean; className?: string; children: ReactNode }) {
  return <Collapsible.Root defaultOpen={defaultOpen} className={cn(className)}>{children}</Collapsible.Root>;
}
export function StepsTrigger({ children, leftIcon, className }: { children: ReactNode; leftIcon?: ReactNode; className?: string }) {
  return (
    <Collapsible.Trigger className={cn("group flex w-fit items-center gap-2 text-[13px] text-fg-faint transition-colors hover:text-fg-muted", className)}>
      {leftIcon && (
        <span className="relative inline-flex size-4 items-center justify-center">
          <span className="transition-opacity group-hover:opacity-0">{leftIcon}</span>
          <ChevronDown className="absolute size-3.5 opacity-0 transition-all group-hover:opacity-100 group-data-[state=open]:rotate-180" />
        </span>
      )}
      <span>{children}</span>
      {!leftIcon && <ChevronDown className="size-3.5 transition-transform group-data-[state=open]:rotate-180" />}
    </Collapsible.Trigger>
  );
}
export function StepsContent({ children }: { children: ReactNode }) {
  return (
    <Collapsible.Content className="t-collapse">
      <div className="mt-2.5 grid min-w-0 grid-cols-[min-content_minmax(0,1fr)] items-start gap-x-3">
        <div className="h-full w-[2px] self-stretch rounded-full bg-line-strong" aria-hidden="true" />
        <div className="min-w-0 space-y-1.5">{children}</div>
      </div>
    </Collapsible.Content>
  );
}
export function StepsItem({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("text-[13px] text-fg-faint", className)}>{children}</div>;
}
