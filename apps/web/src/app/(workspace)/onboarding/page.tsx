import type { Metadata } from "next";
import { Suspense } from "react";
import { AnimatedPage } from "@/components/shared/animated-page";
import { OnboardingWizard } from "@/components/onboarding/onboarding-wizard";

export const metadata: Metadata = { title: "Thiết lập hồ sơ" };

export default function OnboardingPage() {
  return (
    <AnimatedPage>
      <div className="mb-7 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-violet-300">Onboarding constellation</p>
          <h1 className="mt-2 font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.045em] sm:text-4xl">Xây hồ sơ có lực hút</h1>
          <p className="mt-3 max-w-2xl text-sm leading-7 text-muted-foreground sm:text-base">Mỗi bước là một tín hiệu giúp cơ hội phù hợp tìm thấy bạn nhanh hơn.</p>
        </div>
      </div>
      <Suspense fallback={<div className="h-[42rem] animate-pulse rounded-[2rem] bg-white/[0.025]" />}>
        <OnboardingWizard />
      </Suspense>
    </AnimatedPage>
  );
}
