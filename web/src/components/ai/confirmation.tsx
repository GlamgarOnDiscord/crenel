/* Adapted from Vercel AI Elements `confirmation.tsx` (Apache-2.0, see NOTICE.txt):
   Confirmation with Request / Accepted / Rejected slots and Actions, driven by
   the tool approval state. */
import { createContext, forwardRef, useContext, useMemo, type ComponentProps, type ReactNode } from "react";
import { cn } from "../../lib/utils";

export type ApprovalState = "approval-requested" | "approval-responded";
interface Ctx { state: ApprovalState; approved?: boolean }
const ConfirmationContext = createContext<Ctx | null>(null);
const useConfirmation = () => {
  const c = useContext(ConfirmationContext);
  if (!c) throw new Error("Confirmation components must be used within Confirmation");
  return c;
};

export function Confirmation({ state, approved, className, children, ...props }: ComponentProps<"div"> & Ctx) {
  const v = useMemo(() => ({ state, approved }), [state, approved]);
  return (
    <ConfirmationContext.Provider value={v}>
      <div role="group" className={cn("confirm-card", state === "approval-requested" && "pending", className)} {...props}>{children}</div>
    </ConfirmationContext.Provider>
  );
}
export function ConfirmationTitle({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("flex items-center gap-3 font-medium", className)} {...props} />;
}
export function ConfirmationRequest({ children }: { children?: ReactNode }) {
  return useConfirmation().state === "approval-requested" ? <>{children}</> : null;
}
export function ConfirmationAccepted({ children }: { children?: ReactNode }) {
  const { state, approved } = useConfirmation();
  return state === "approval-responded" && approved ? <>{children}</> : null;
}
export function ConfirmationRejected({ children }: { children?: ReactNode }) {
  const { state, approved } = useConfirmation();
  return state === "approval-responded" && approved === false ? <>{children}</> : null;
}
export function ConfirmationActions({ className, ...props }: ComponentProps<"div">) {
  return useConfirmation().state === "approval-requested" ? <div className={cn("flex flex-wrap items-center gap-2", className)} {...props} /> : null;
}
export const ConfirmationAction = forwardRef<HTMLButtonElement, ComponentProps<"button"> & { variant?: "primary" | "ghost" }>(
  function ConfirmationAction({ className, variant = "ghost", ...props }, ref) {
    return <button ref={ref} type="button" className={cn("perm-b", variant === "primary" && "primary", className)} {...props} />;
  });
