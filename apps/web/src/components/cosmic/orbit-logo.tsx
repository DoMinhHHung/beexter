import { Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";

interface OrbitLogoProps {
  compact?: boolean;
  className?: string;
}

export function OrbitLogo({ compact = false, className }: OrbitLogoProps) {
  return (
    <div className={cn("inline-flex items-center gap-3", className)}>
      <div className="relative flex size-10 items-center justify-center rounded-2xl border border-white/[0.15] bg-gradient-to-br from-violet-500/30 to-sky-400/[0.15] shadow-glow">
        <div className="absolute inset-[7px] rounded-full border border-cyan-300/[0.45]" />
        <div className="absolute h-px w-8 rotate-[32deg] bg-gradient-to-r from-transparent via-violet-200/70 to-transparent" />
        <Sparkles className="relative size-4 text-white" strokeWidth={1.8} />
      </div>
      {!compact && (
        <div>
          <div className="text-base font-bold tracking-[-0.03em] text-white">Beexster</div>
          <div className="text-[10px] font-medium uppercase tracking-[0.24em] text-slate-500">Talent orbit</div>
        </div>
      )}
    </div>
  );
}
