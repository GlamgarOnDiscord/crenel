/* Adapted from motion-primitives `border-trail.tsx` by Julien Thibeaut (ibelick),
   https://github.com/ibelick/motion-primitives, MIT License (also on 21st.dev). */
import { motion, type Transition } from "motion/react";
import { cn } from "../../lib/utils";

export function BorderTrail({ className, size = 60, transition, style }: { className?: string; size?: number; transition?: Transition; style?: React.CSSProperties }) {
  return (
    <div className="pointer-events-none absolute inset-0 rounded-[inherit] border border-transparent [mask-clip:padding-box,border-box] [mask-composite:intersect] [mask-image:linear-gradient(transparent,transparent),linear-gradient(var(--fg),var(--fg))]">
      <motion.div
        className={cn("absolute aspect-square bg-brand", className)}
        style={{ width: size, offsetPath: `rect(0 auto auto 0 round ${size}px)`, ...style }}
        animate={{ offsetDistance: ["0%", "100%"] }}
        transition={transition ?? { repeat: Infinity, duration: 5, ease: "linear" }}
      />
    </div>
  );
}
