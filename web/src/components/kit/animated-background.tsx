/* Adapted from motion-primitives `animated-background.tsx` by Julien Thibeaut
   (ibelick), https://github.com/ibelick/motion-primitives, MIT License. */
import { AnimatePresence, motion, type Transition } from "motion/react";
import { Children, cloneElement, useEffect, useId, useState, type ReactElement } from "react";
import { cn } from "../../lib/utils";

type Child = ReactElement<{ "data-id": string; className?: string; children?: React.ReactNode }>;

export function AnimatedBackground({ children, defaultValue, className, transition, enableHover = false }: {
  children: Child | Child[]; defaultValue?: string; className?: string; transition?: Transition; enableHover?: boolean;
}) {
  const [active, setActive] = useState<string | null>(null);
  const uid = useId();
  useEffect(() => { if (defaultValue !== undefined) setActive(defaultValue); }, [defaultValue]);
  return <>{Children.map(children, (child: Child, i) => {
    const id = child.props["data-id"];
    const interaction = enableHover
      ? { onMouseEnter: () => setActive(id), onMouseLeave: () => setActive(defaultValue ?? null), onFocus: () => setActive(id), onBlur: () => setActive(defaultValue ?? null) }
      : { onClick: () => setActive(id) };
    return cloneElement(child, {
      key: i, className: cn("relative", child.props.className), "data-checked": active === id ? "true" : "false", ...interaction,
    } as Record<string, unknown>, <>
      <AnimatePresence initial={false}>
        {active === id && (
          <motion.span layoutId={`bg-${uid}`} className={cn("absolute inset-0", className)} transition={transition}
            initial={{ opacity: defaultValue ? 1 : 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} />
        )}
      </AnimatePresence>
      <span className="relative z-10 flex w-full items-center gap-[inherit]">{child.props.children}</span>
    </>);
  })}</>;
}
