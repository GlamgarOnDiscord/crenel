/* Adapted from prompt-kit `feedback-bar.tsx` by Julien Thibeaut (ibelick),
   https://github.com/ibelick/prompt-kit, MIT License (listed on 21st.dev as
   "Feedback Bar"). */
import { ThumbsDown, ThumbsUp, X } from "lucide-react";
import { cn } from "../../lib/utils";

export function FeedbackBar({ className, title, icon, onHelpful, onNotHelpful, onClose }: {
  className?: string; title?: string; icon?: React.ReactNode; onHelpful?: () => void; onNotHelpful?: () => void; onClose?: () => void;
}) {
  return (
    <div className={cn("inline-flex rounded-[12px] border border-line bg-panel text-[13px]", className)}>
      <div className="flex w-full items-center justify-between">
        <div className="flex flex-1 items-center gap-3 py-2.5 pl-3.5">{icon}<span className="font-medium text-fg">{title}</span></div>
        <div className="flex items-center gap-0.5 px-2">
          <button type="button" className="iconbtn sm" aria-label="Utile" onClick={onHelpful}><ThumbsUp className="size-3.5" /></button>
          <button type="button" className="iconbtn sm" aria-label="Pas utile" onClick={onNotHelpful}><ThumbsDown className="size-3.5" /></button>
        </div>
        <div className="flex items-center border-l border-line">
          <button type="button" onClick={onClose} className="iconbtn sm m-1" aria-label="Fermer"><X className="size-4" /></button>
        </div>
      </div>
    </div>
  );
}
