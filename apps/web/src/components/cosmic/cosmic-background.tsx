"use client";

import { motion, useReducedMotion } from "framer-motion";

export function CosmicBackground() {
  const reduceMotion = useReducedMotion();

  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden" aria-hidden="true">
      <div className="absolute inset-0 star-field opacity-[0.55]" />
      <div className="absolute inset-0 cosmic-grid" />
      <motion.div
        className="absolute -left-32 top-16 size-[32rem] rounded-full bg-violet-600/[0.15] blur-[110px]"
        animate={reduceMotion ? undefined : { x: [0, 42, 0], y: [0, 24, 0], scale: [1, 1.08, 1] }}
        transition={{ duration: 16, ease: "easeInOut", repeat: Infinity }}
      />
      <motion.div
        className="absolute -right-40 top-1/3 size-[34rem] rounded-full bg-sky-500/[0.12] blur-[120px]"
        animate={reduceMotion ? undefined : { x: [0, -36, 0], y: [0, -22, 0], scale: [1.04, 0.96, 1.04] }}
        transition={{ duration: 18, ease: "easeInOut", repeat: Infinity }}
      />
      <div className="absolute inset-0 noise-overlay" />
    </div>
  );
}
