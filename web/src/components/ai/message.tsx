/* Adapted from Vercel AI Elements `message.tsx` (Apache-2.0, see NOTICE.txt):
   Message (from user or assistant), MessageContent, MessageActions with
   MessageAction buttons wrapped in the Arc UI Tooltip. */
import type { ComponentProps, ReactNode } from "react";
import { cn } from "../../lib/utils";
import { Tooltip } from "../arc/tooltip/tooltip";

export function Message({ from, className, ...props }: ComponentProps<"div"> & { from: "user" | "assistant" }) {
  return <div className={cn("group/msg flex w-full gap-3", from === "user" ? "is-user justify-end" : "is-assistant", className)} {...props} />;
}
export function MessageContent({ className, ...props }: ComponentProps<"div">) {
  return (
    <div className={cn(
      "flex min-w-0 flex-col gap-2 text-[14.5px] leading-[1.65]",
      "group-[.is-user]/msg:max-w-[80%] group-[.is-user]/msg:rounded-[18px_18px_6px_18px] group-[.is-user]/msg:bg-raised group-[.is-user]/msg:px-3.5 group-[.is-user]/msg:py-2.5",
      className)} {...props} />
  );
}
export function MessageActions({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("flex items-center gap-0.5 opacity-70 transition-opacity group-hover/msg:opacity-100", className)} {...props} />;
}
export function MessageAction({ tooltip, label, children, ...props }: ComponentProps<"button"> & { tooltip: string; label?: string; children: ReactNode }) {
  return (
    <Tooltip content={tooltip}>
      <button type="button" className="iconbtn sm" aria-label={label ?? tooltip} {...props}>{children}</button>
    </Tooltip>
  );
}
