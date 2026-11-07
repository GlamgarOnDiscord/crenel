/* Adapted from Vercel AI Elements `sources.tsx` (Apache-2.0, see NOTICE.txt). */
import * as Collapsible from "@radix-ui/react-collapsible";
import { BookOpen, ChevronDown } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "../../lib/utils";

export function Sources({ className, children }: { className?: string; children: ReactNode }) {
  return <Collapsible.Root className={cn("group/src text-[12px]", className)}>{children}</Collapsible.Root>;
}
export function SourcesTrigger({ count }: { count: number }) {
  return (
    <Collapsible.Trigger className="flex items-center gap-1.5 text-fg-faint transition-colors hover:text-fg-muted">
      <span className="font-medium">{count} sources utilisées</span>
      <ChevronDown className="size-3.5 transition-transform duration-200 group-data-[state=open]/src:rotate-180" aria-hidden="true" />
    </Collapsible.Trigger>
  );
}
export function SourcesContent({ children }: { children: ReactNode }) {
  return <Collapsible.Content className="t-collapse"><div className="mt-2.5 flex w-fit flex-col gap-1.5">{children}</div></Collapsible.Content>;
}
export function Source({ href, title, kind }: { href: string; title: string; kind?: string }) {
  return (
    <a className="flex items-center gap-2 rounded-lg px-2 py-1 text-fg transition-colors hover:bg-raised" href={href} rel="noreferrer" target="_blank">
      <BookOpen className="size-3.5 text-fg-faint" aria-hidden="true" />
      {kind && <span className="text-fg-faint">{kind}</span>}
      <span className="font-medium">{title}</span>
    </a>
  );
}
