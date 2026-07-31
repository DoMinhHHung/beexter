import type { ReactNode } from "react";
import { OrbitLogo } from "@/components/cosmic/orbit-logo";

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <main id="main-content" className="min-h-dvh px-4 py-5 sm:px-6 sm:py-8 lg:px-10">
      <div className="mx-auto flex min-h-[calc(100dvh-2.5rem)] max-w-7xl flex-col rounded-[2rem] border border-white/10 bg-slate-950/[0.35] shadow-panel backdrop-blur-lg sm:min-h-[calc(100dvh-4rem)] lg:grid lg:grid-cols-[1.05fr_0.95fr]">
        <section className="relative hidden overflow-hidden rounded-l-[2rem] border-r border-white/10 p-10 lg:flex lg:flex-col lg:justify-between">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(124,58,237,0.24),transparent_36%),radial-gradient(circle_at_70%_70%,rgba(14,165,233,0.16),transparent_34%)]" />
          <div className="relative">
            <OrbitLogo />
          </div>
          <div className="relative max-w-xl pb-8">
            <div className="mb-8 flex items-center gap-3 text-xs font-semibold uppercase tracking-[0.24em] text-violet-300">
              <span className="h-px w-10 bg-violet-300/60" /> Career constellation
            </div>
            <h1 className="font-[family-name:var(--font-heading)] text-5xl font-bold leading-[1.05] tracking-[-0.055em] xl:text-6xl">
              Nơi năng lực của bạn tìm thấy đúng <span className="text-gradient">quỹ đạo.</span>
            </h1>
            <p className="mt-6 max-w-lg text-base leading-8 text-slate-300/80">
              Xây hồ sơ có chiều sâu, kể câu chuyện nghề nghiệp rõ ràng và kết nối với những đội ngũ đang tạo ra tương lai.
            </p>
          </div>
          <div className="relative flex items-center gap-4 text-xs text-slate-500">
            <span>Profile-first matching</span>
            <span className="size-1 rounded-full bg-slate-700" />
            <span>Privacy by design</span>
          </div>
        </section>
        <section className="flex min-h-full items-center justify-center p-5 sm:p-10 lg:p-14">
          <div className="w-full max-w-md">
            <div className="mb-10 lg:hidden">
              <OrbitLogo />
            </div>
            {children}
          </div>
        </section>
      </div>
    </main>
  );
}
