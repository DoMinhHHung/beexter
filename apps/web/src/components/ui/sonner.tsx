"use client";

import { Toaster as Sonner } from "sonner";

export function Toaster() {
  return (
    <Sonner
      theme="dark"
      position="top-right"
      toastOptions={{
        classNames: {
          toast: "border-white/10 bg-slate-950/90 text-slate-50 backdrop-blur-xl",
          description: "text-slate-400",
          actionButton: "bg-indigo-500 text-white",
          cancelButton: "bg-white/10 text-slate-200"
        }
      }}
    />
  );
}
