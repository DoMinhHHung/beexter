"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { ArrowLeft, ArrowRight, Check, LoaderCircle, RotateCcw, Rocket } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { onboardingSteps } from "@/lib/constants";
import { saveProfileDraft } from "@/lib/api/profile-client";
import { personalProfileSchema } from "@/lib/validation/onboarding";
import { cn } from "@/lib/utils";
import { useOnboardingDraft } from "@/hooks/use-onboarding-draft";
import { ExperienceStep } from "./experience-step";
import { PersonalStep } from "./personal-step";
import { PortfolioStep } from "./portfolio-step";
import { ReviewStep } from "./review-step";
import { SkillsStep } from "./skills-step";

export function OnboardingWizard() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const reduceMotion = useReducedMotion();
  const requestedStep = Number(searchParams.get("step") || 0);
  const [currentStep, setCurrentStep] = useState(Number.isInteger(requestedStep) && requestedStep >= 0 && requestedStep < onboardingSteps.length ? requestedStep : 0);
  const [submitSignal, setSubmitSignal] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [direction, setDirection] = useState(1);
  const {
    draft,
    hydrated,
    score,
    updatePersonal,
    updateSkills,
    updateExperiences,
    updatePortfolio,
    complete,
    reset
  } = useOnboardingDraft();

  const progress = ((currentStep + 1) / onboardingSteps.length) * 100;

  const validation = useMemo(() => {
    const personal = personalProfileSchema.safeParse(draft.personal).success;
    const skills = draft.skills.length >= 3;
    const experience = draft.experienceSkipped || (draft.experiences.length > 0 && draft.experiences.every((item) => item.role.trim() && item.company.trim() && item.startDate));
    const portfolio = (draft.projects.length > 0 || Object.values(draft.links).some((value) => value.trim())) && draft.projects.every((project) => project.title.trim() && project.description.trim());
    return [personal, skills, experience, portfolio, personal && skills && experience && portfolio];
  }, [draft]);

  const goTo = (step: number) => {
    setDirection(step > currentStep ? 1 : -1);
    setCurrentStep(step);
    window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" });
  };

  const next = () => {
    setSubmitSignal((value) => value + 1);
    if (!validation[currentStep]) {
      toast.error("Hoàn thiện các thông tin cần thiết trước khi tiếp tục");
      return;
    }
    goTo(Math.min(currentStep + 1, onboardingSteps.length - 1));
  };

  const finish = async () => {
    if (!validation[4]) {
      toast.error("Hồ sơ còn thiếu tín hiệu quan trọng");
      return;
    }

    setSubmitting(true);
    try {
      const payload = {
        ...draft,
        experiences: draft.experienceSkipped ? [] : draft.experiences,
        completedAt: new Date().toISOString()
      };
      const result = await saveProfileDraft(payload);
      complete();
      toast.success(result.mode === "api" ? "Hồ sơ đã đồng bộ với Profile Service" : "Hồ sơ đã lưu trong chế độ local");
      router.push("/dashboard");
      router.refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Không thể hoàn tất hồ sơ");
    } finally {
      setSubmitting(false);
    }
  };

  const resetDraft = () => {
    reset();
    goTo(0);
    toast.success("Đã tạo một bản nháp mới");
  };

  if (!hydrated) {
    return <div className="h-[38rem] animate-pulse rounded-[2rem] border border-white/[0.08] bg-white/[0.025]" aria-label="Đang tải bản nháp hồ sơ" />;
  }

  const variants = {
    enter: (value: number) => ({ opacity: 0, x: reduceMotion ? 0 : value * 28 }),
    center: { opacity: 1, x: 0 },
    exit: (value: number) => ({ opacity: 0, x: reduceMotion ? 0 : value * -18 })
  };

  return (
    <div className="grid gap-6 xl:grid-cols-[16rem_minmax(0,1fr)]">
      <aside className="xl:sticky xl:top-28 xl:h-fit">
        <Card className="overflow-hidden bg-slate-950/[0.55]">
          <CardContent className="p-4 sm:p-5">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-violet-300">Launch sequence</p>
                <p className="mt-1 text-sm font-medium text-white">Bước {currentStep + 1} / {onboardingSteps.length}</p>
              </div>
              <span className="text-xs font-semibold text-cyan-300">{Math.round(progress)}%</span>
            </div>
            <Progress value={progress} />

            <div className="mt-5 grid grid-cols-5 gap-1.5 xl:block xl:space-y-1.5">
              {onboardingSteps.map((step, index) => {
                const completed = index < currentStep || validation[index];
                const active = index === currentStep;
                return (
                  <button
                    key={step.id}
                    type="button"
                    onClick={() => index <= currentStep && goTo(index)}
                    disabled={index > currentStep}
                    className={cn(
                      "group flex min-h-12 items-center justify-center gap-3 rounded-xl px-2 text-left transition-colors focus-visible:ring-2 focus-visible:ring-ring xl:w-full xl:justify-start xl:px-3",
                      active ? "bg-violet-500/[0.15] text-white" : index < currentStep ? "text-slate-300 hover:bg-white/[0.04]" : "cursor-not-allowed text-slate-600"
                    )}
                    aria-current={active ? "step" : undefined}
                  >
                    <span className={cn("flex size-8 shrink-0 items-center justify-center rounded-lg border text-xs font-semibold", active ? "border-violet-400/30 bg-violet-400/10 text-violet-200" : completed ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300" : "border-white/[0.08] bg-white/[0.025]")}>{completed && index < currentStep ? <Check className="size-4" /> : index + 1}</span>
                    <span className="hidden min-w-0 xl:block">
                      <span className="block truncate text-sm font-medium">{step.label}</span>
                      <span className="mt-0.5 block truncate text-[10px] text-muted-foreground">{step.description}</span>
                    </span>
                  </button>
                );
              })}
            </div>

            <Button type="button" variant="ghost" size="sm" onClick={resetDraft} className="mt-5 hidden w-full justify-start text-slate-500 xl:flex">
              <RotateCcw /> Bắt đầu lại
            </Button>
          </CardContent>
        </Card>
      </aside>

      <section className="min-w-0">
        <Card className="overflow-hidden bg-slate-950/[0.55]">
          <CardContent className="p-5 sm:p-8 lg:p-10">
            <AnimatePresence mode="wait" custom={direction}>
              <motion.div
                key={currentStep}
                custom={direction}
                variants={variants}
                initial="enter"
                animate="center"
                exit="exit"
                transition={{ duration: reduceMotion ? 0 : 0.24, ease: [0.16, 1, 0.3, 1] }}
              >
                {currentStep === 0 && <PersonalStep value={draft.personal} onChange={updatePersonal} submitSignal={submitSignal} />}
                {currentStep === 1 && <SkillsStep value={draft.skills} onChange={updateSkills} submitSignal={submitSignal} />}
                {currentStep === 2 && (
                  <ExperienceStep
                    value={draft.experiences}
                    onChange={(experiences) => updateExperiences(experiences, draft.experienceSkipped)}
                    skipped={draft.experienceSkipped}
                    onSkippedChange={(skipped) => updateExperiences(draft.experiences, skipped)}
                    submitSignal={submitSignal}
                  />
                )}
                {currentStep === 3 && <PortfolioStep projects={draft.projects} links={draft.links} onChange={updatePortfolio} submitSignal={submitSignal} />}
                {currentStep === 4 && <ReviewStep draft={draft} score={score} />}
              </motion.div>
            </AnimatePresence>

            <div className="mt-10 flex flex-col-reverse gap-3 border-t border-white/[0.08] pt-6 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex gap-3">
                {currentStep > 0 ? (
                  <Button type="button" variant="ghost" onClick={() => goTo(currentStep - 1)}><ArrowLeft /> Quay lại</Button>
                ) : (
                  <Button asChild variant="ghost"><Link href="/dashboard">Để sau</Link></Button>
                )}
              </div>
              {currentStep < onboardingSteps.length - 1 ? (
                <motion.div whileHover={{ y: -2 }} whileTap={{ scale: 0.985 }}>
                  <Button type="button" variant="cosmic" onClick={next} className="w-full sm:w-auto">Tiếp tục <ArrowRight /></Button>
                </motion.div>
              ) : (
                <motion.div whileHover={{ y: -2 }} whileTap={{ scale: 0.985 }}>
                  <Button type="button" variant="cosmic" size="lg" onClick={finish} disabled={submitting} className="w-full sm:w-auto">
                    {submitting ? <LoaderCircle className="animate-spin" /> : <Rocket />}
                    {submitting ? "Đang đồng bộ..." : "Hoàn tất và cất cánh"}
                  </Button>
                </motion.div>
              )}
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
