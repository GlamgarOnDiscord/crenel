/* Adapted from motion-primitives `sliding-number.tsx` by Julien Thibeaut (ibelick),
   https://github.com/ibelick/motion-primitives, MIT License (also on 21st.dev). */
import { motion, motionValue, useSpring, useTransform, type MotionValue } from "motion/react";
import { useEffect, useId } from "react";
import useMeasure from "react-use-measure";

const TRANSITION = { type: "spring" as const, stiffness: 280, damping: 18, mass: 0.3 };

function Digit({ value, place }: { value: number; place: number }) {
  const v = Math.floor(value / place) % 10;
  const mv = useSpring(motionValue(v), TRANSITION);
  useEffect(() => { mv.set(v); }, [mv, v]);
  return (
    <span className="relative inline-block w-[1ch] overflow-x-visible overflow-y-clip leading-none tabular-nums">
      <span className="invisible">0</span>
      {Array.from({ length: 10 }, (_, i) => <Num key={i} mv={mv} number={i} />)}
    </span>
  );
}

function Num({ mv, number }: { mv: MotionValue<number>; number: number }) {
  const uid = useId();
  const [ref, bounds] = useMeasure();
  const y = useTransform(mv, (latest) => {
    if (!bounds.height) return 0;
    const off = (10 + number - (latest % 10)) % 10;
    let m = off * bounds.height;
    if (off > 5) m -= 10 * bounds.height;
    return m;
  });
  if (!bounds.height) return <span ref={ref} className="invisible absolute">{number}</span>;
  return <motion.span ref={ref} style={{ y }} layoutId={`${uid}-${number}`} className="absolute inset-0 flex items-center justify-center" transition={TRANSITION}>{number}</motion.span>;
}

export function SlidingNumber({ value, padStart = false, decimalSeparator = "," }: { value: number; padStart?: boolean; decimalSeparator?: string }) {
  const [intPart, decPart] = Math.abs(value).toString().split(".");
  const intVal = parseInt(intPart!, 10);
  const padded = padStart && intVal < 10 ? `0${intPart}` : intPart!;
  const digits = padded.split("");
  return (
    <span className="inline-flex items-center" aria-label={String(value).replace(".", decimalSeparator)}>
      <span aria-hidden="true" className="inline-flex items-center">
        {value < 0 && "−"}
        {digits.map((_, i) => <Digit key={`p-${10 ** (digits.length - i - 1)}`} value={intVal} place={10 ** (digits.length - i - 1)} />)}
        {decPart && <><span>{decimalSeparator}</span>{decPart.split("").map((_, i) => <Digit key={`d-${i}`} value={parseInt(decPart, 10)} place={10 ** (decPart.length - i - 1)} />)}</>}
      </span>
    </span>
  );
}
