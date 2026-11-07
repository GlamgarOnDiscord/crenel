/* Adapted from motion-primitives `text-morph.tsx` by Julien Thibeaut (ibelick),
   https://github.com/ibelick/motion-primitives, MIT License (also on 21st.dev). */
import { AnimatePresence, motion, type Transition, type Variants } from "motion/react";
import { useId, useMemo } from "react";
import { cn } from "../../lib/utils";

export function TextMorph({ children, as: Component = "span", className, variants, transition }: {
  children: string; as?: React.ElementType; className?: string; variants?: Variants; transition?: Transition;
}) {
  const uid = useId();
  const chars = useMemo(() => {
    const n: Record<string, number> = {};
    return children.split("").map((ch) => {
      const k = ch.toLowerCase(); n[k] = (n[k] || 0) + 1;
      return { id: `${uid}-${k}${n[k]}`, label: ch === " " ? " " : ch };
    });
  }, [children, uid]);
  return (
    <Component className={cn(className)} aria-label={children}>
      <AnimatePresence mode="popLayout" initial={false}>
        {chars.map((c) => (
          <motion.span key={c.id} layoutId={c.id} className="inline-block" aria-hidden="true"
            initial="initial" animate="animate" exit="exit"
            variants={variants ?? { initial: { opacity: 0 }, animate: { opacity: 1 }, exit: { opacity: 0 } }}
            transition={transition ?? { type: "spring", stiffness: 280, damping: 18, mass: 0.3 }}>
            {c.label}
          </motion.span>
        ))}
      </AnimatePresence>
    </Component>
  );
}
