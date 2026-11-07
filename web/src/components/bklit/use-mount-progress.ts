"use client";
/* Ported from bklit-ui (https://github.com/bklit/bklit-ui, packages/ui), MIT License, Copyright (c) 2026 uixmat.
   Adapted for Crenel (import paths, React 18, Crenel tokens). */

import { animate, type Transition, useMotionValue } from "motion/react";
import { useEffect, useRef } from "react";
import { DEFAULT_CHART_ENTER_TRANSITION } from "./animation";

/** Drives 0→1 enter progress using the studio motion transition (spring or tween). */
export function useMountProgress(
  enterTransition: Transition | undefined,
  delaySeconds: number,
  replayKey: number | string
) {
  const progress = useMotionValue(0);
  const transitionRef = useRef(enterTransition);
  // Latest transition without restarting the enter tween on every new object
  // identity. Declared before the tween effect so it runs first.
  useEffect(() => {
    transitionRef.current = enterTransition;
  });

  // replayKey intentionally retriggers enter when motion settings change
  // biome-ignore lint/correctness/useExhaustiveDependencies: replayKey
  useEffect(() => {
    progress.set(0);
    const controls = animate(progress, 1, {
      ...(transitionRef.current ?? DEFAULT_CHART_ENTER_TRANSITION),
      delay: delaySeconds,
    });
    return () => controls.stop();
  }, [delaySeconds, replayKey, progress]);

  return progress;
}
