/* Adapted from Vercel AI Elements `conversation.tsx` (Apache-2.0, see NOTICE.txt):
   StickToBottom container, content, empty state and the scroll-to-bottom button. */
import { ArrowDown } from "lucide-react";
import type { ComponentProps, ReactNode } from "react";
import { StickToBottom, useStickToBottomContext } from "use-stick-to-bottom";
import { cn } from "../../lib/utils";

export function Conversation({ className, ...props }: ComponentProps<typeof StickToBottom>) {
  return <StickToBottom className={cn("relative min-h-0 flex-1 overflow-y-hidden", className)} initial="smooth" resize="smooth" role="log" {...props} />;
}
export function ConversationContent({ className, ...props }: ComponentProps<typeof StickToBottom.Content>) {
  return <StickToBottom.Content className={cn("transcript", className)} {...props} />;
}
export function ConversationEmptyState({ icon, title, description }: { icon?: ReactNode; title: string; description?: string }) {
  return (
    <div className="t-reveal flex flex-col items-center justify-center gap-3 p-14 text-center">
      {icon}
      <h3 className="font-sans text-[14px] font-medium">{title}</h3>
      {description && <p className="text-[13px] text-fg-faint">{description}</p>}
    </div>
  );
}
export function ConversationScrollButton() {
  const { isAtBottom, scrollToBottom } = useStickToBottomContext();
  if (isAtBottom) return null;
  return (
    <button type="button" className="tobottom t-pop" onClick={() => scrollToBottom()}>
      <ArrowDown className="size-3.5" aria-hidden="true" /> Revenir en bas
    </button>
  );
}
