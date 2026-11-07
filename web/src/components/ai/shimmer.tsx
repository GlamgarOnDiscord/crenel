/* Adapted from Vercel AI Elements `shimmer.tsx` (Apache-2.0, see NOTICE.txt). */
import { motion, type MotionProps } from "motion/react";
import type { CSSProperties, ElementType } from "react";
import { memo, useMemo } from "react";
import { cn } from "../../lib/utils";

type MotionHTMLProps = MotionProps & Record<string, unknown>;
const cache = new Map<string, React.ComponentType<MotionHTMLProps>>();
const getMotion = (el: string) => {
  let c = cache.get(el);
  if (!c) { c = motion.create(el as "span") as unknown as React.ComponentType<MotionHTMLProps>; cache.set(el, c); }
  return c;
};

export interface TextShimmerProps { children: string; as?: ElementType; className?: string; duration?: number; spread?: number }

function ShimmerComponent({ children, as = "span", className, duration = 2, spread = 2 }: TextShimmerProps) {
  const M = getMotion(as as string);
  const s = useMemo(() => (children?.length ?? 0) * spread, [children, spread]);
  return (
    <M
      animate={{ backgroundPosition: "0% center" }}
      initial={{ backgroundPosition: "100% center" }}
      transition={{ duration, ease: "linear", repeat: Number.POSITIVE_INFINITY }}
      className={cn(
        "relative inline-block bg-[length:250%_100%,auto] bg-clip-text text-transparent",
        "[--bg:linear-gradient(90deg,transparent_calc(50%-var(--spread)),var(--color-foreground),transparent_calc(50%+var(--spread)))] [background-repeat:no-repeat,padding-box]",
        className,
      )}
      style={{ "--spread": `${s}px`, backgroundImage: "var(--bg), linear-gradient(var(--color-muted-foreground), var(--color-muted-foreground))" } as CSSProperties}
    >
      {children}
    </M>
  );
}
export const Shimmer = memo(ShimmerComponent);
