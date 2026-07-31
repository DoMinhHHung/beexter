import { OrbitLogo } from "@/components/cosmic/orbit-logo";

export default function Loading() {
  return (
    <main className="flex min-h-dvh items-center justify-center px-6" aria-live="polite" aria-busy="true">
      <div className="flex flex-col items-center gap-5">
        <div className="relative">
          <div className="absolute inset-0 animate-ping rounded-2xl bg-violet-500/20" />
          <OrbitLogo compact />
        </div>
        <p className="text-sm text-muted-foreground">Đang đồng bộ quỹ đạo...</p>
      </div>
    </main>
  );
}
