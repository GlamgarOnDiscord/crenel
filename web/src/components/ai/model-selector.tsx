/* Adapted from Vercel AI Elements `model-selector.tsx` (Apache-2.0, see
   NOTICE.txt): the same compound API (ModelSelector, Trigger, Content, Input,
   List, Empty, Group, Item, Logo, Name) on cmdk, rendered in a Radix popover
   anchored to the composer (as in the Codex composer) rather than a dialog. */
import * as Popover from "@radix-ui/react-popover";
import { Command } from "cmdk";
import { Search } from "lucide-react";
import type { ComponentProps, ReactNode } from "react";
import { cn } from "../../lib/utils";
import { ModelLogo, type Provider } from "../../brand/ModelLogo";

export const ModelSelector = Popover.Root;
export const ModelSelectorTrigger = Popover.Trigger;

export function ModelSelectorContent({ className, children, title = "Modèle et effort", ...props }: ComponentProps<typeof Popover.Content> & { title?: string }) {
  return (
    <Popover.Portal>
      <Popover.Content sideOffset={8} collisionPadding={12} aria-label={title} className={cn("msel t-pop", className)} {...props}>
        {children}
      </Popover.Content>
    </Popover.Portal>
  );
}
export function ModelSelectorCommand({ children, ...props }: ComponentProps<typeof Command>) {
  return <Command className="msel-cmd" loop {...props}>{children}</Command>;
}
export function ModelSelectorInput(props: ComponentProps<typeof Command.Input>) {
  return (
    <div className="msel-search">
      <Search className="size-3.5 text-fg-faint" aria-hidden="true" />
      <Command.Input {...props} />
    </div>
  );
}
export const ModelSelectorList = ({ className, ...props }: ComponentProps<typeof Command.List>) => <Command.List className={cn("msel-list", className)} {...props} />;
export const ModelSelectorEmpty = (props: ComponentProps<typeof Command.Empty>) => <Command.Empty className="msel-empty" {...props} />;
export const ModelSelectorGroup = (props: ComponentProps<typeof Command.Group>) => <Command.Group className="msel-group" {...props} />;
export const ModelSelectorItem = ({ className, ...props }: ComponentProps<typeof Command.Item>) => <Command.Item className={cn("msel-item", className)} {...props} />;
export function ModelSelectorLogo({ provider, size = 16 }: { provider: Provider; size?: number }) {
  return <span className="msel-logo"><ModelLogo provider={provider} size={size} title /></span>;
}
export function ModelSelectorName({ children, desc }: { children: ReactNode; desc?: string }) {
  return <span className="msel-name"><span className="msel-n">{children}</span>{desc && <span className="msel-d">{desc}</span>}</span>;
}
