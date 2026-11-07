// App-wide toasts: the Arc UI ToastStack (MIT), wrapped so pages can call
// useToast()(...) without knowing the stack API.
import type { ReactNode } from "react";
import { ToastStack, ToastStackProvider, useToastStack, type ToastOptions } from "./arc/toast-stack/toast-stack";

export function ToastProvider({ children }: { children: ReactNode }) {
  return (
    <ToastStackProvider duration={3200}>
      {children}
      <ToastStack label="Notifications" position="bottom-right" visibleToasts={3} />
    </ToastStackProvider>
  );
}

export function useToast() {
  const { toast } = useToastStack();
  return (o: ToastOptions) => toast(o);
}
