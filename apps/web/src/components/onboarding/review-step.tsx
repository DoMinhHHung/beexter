import type { ComponentType, ReactNode } from "react";
import { BadgeCheck, BriefcaseBusiness, FolderKanban, MapPin, Orbit, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { skillLevelLabels } from "@/lib/constants";
import type { ProfileDraft } from "@/types/profile";
import { StepHeader } from "./step-header";

export function ReviewStep({ draft, score }: { draft: ProfileDraft; score: number }) {
  return (
    <div>
      <StepHeader
        eyebrow="05 · Launch check"
        title="Hồ sơ của bạn đã sẵn sàng cất cánh"
        description="Kiểm tra nhanh các tín hiệu quan trọng. Bạn luôn có thể quay lại chỉnh sửa sau khi hoàn tất."
      />

      <div className="mb-6 rounded-3xl border border-violet-400/[0.15] bg-gradient-to-br from-violet-500/[0.12] to-sky-400/[0.05] p-5 sm:p-6">
        <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="mb-2 flex items-center gap-2 text-sm font-medium text-violet-200"><Sparkles className="size-4" /> Profile signal</div>
            <p className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.04em] text-white">{score}% hoàn thiện</p>
            <p className="mt-2 text-sm text-muted-foreground">Tín hiệu từ 70% đã đủ để bắt đầu nhận đề xuất công việc.</p>
          </div>
          <div className="w-full sm:max-w-xs"><Progress value={score} /></div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <ReviewCard icon={Orbit} title={`${draft.personal.firstName} ${draft.personal.lastName}`} subtitle={draft.personal.headline || "Chưa có headline"}>
          <div className="mt-4 flex items-center gap-2 text-sm text-muted-foreground"><MapPin className="size-4" /> {draft.personal.location || "Chưa có địa điểm"}</div>
          <p className="mt-4 line-clamp-4 text-sm leading-6 text-slate-300/80">{draft.personal.about || "Chưa có giới thiệu"}</p>
        </ReviewCard>

        <ReviewCard icon={BadgeCheck} title={`${draft.skills.length} kỹ năng`} subtitle="Năng lực nổi bật">
          <div className="mt-4 flex flex-wrap gap-2">
            {draft.skills.map((skill) => <Badge key={skill.id} variant="outline">{skill.name} · {skillLevelLabels[skill.level]}</Badge>)}
          </div>
        </ReviewCard>

        <ReviewCard icon={BriefcaseBusiness} title={`${draft.experiences.length} chặng đường`} subtitle="Kinh nghiệm nghề nghiệp">
          <div className="mt-4 space-y-3">
            {draft.experiences.slice(0, 3).map((experience) => (
              <div key={experience.id} className="rounded-xl bg-white/[0.035] p-3">
                <p className="text-sm font-medium text-slate-200">{experience.role}</p>
                <p className="mt-1 text-xs text-muted-foreground">{experience.company}</p>
              </div>
            ))}
            {draft.experiences.length === 0 && <p className="text-sm text-muted-foreground">Hồ sơ đang tập trung vào kỹ năng và portfolio.</p>}
          </div>
        </ReviewCard>

        <ReviewCard icon={FolderKanban} title={`${draft.projects.length} dự án`} subtitle="Proof of work">
          <div className="mt-4 space-y-3">
            {draft.projects.slice(0, 3).map((project) => (
              <div key={project.id} className="rounded-xl bg-white/[0.035] p-3">
                <p className="text-sm font-medium text-slate-200">{project.title}</p>
                <p className="mt-1 line-clamp-2 text-xs leading-5 text-muted-foreground">{project.description}</p>
              </div>
            ))}
            {draft.projects.length === 0 && <p className="text-sm text-muted-foreground">Bạn đang dùng liên kết cá nhân làm tín hiệu chính.</p>}
          </div>
        </ReviewCard>
      </div>
    </div>
  );
}

function ReviewCard({ icon: Icon, title, subtitle, children }: { icon: ComponentType<{ className?: string }>; title: string; subtitle: string; children: ReactNode }) {
  return (
    <section className="rounded-3xl border border-white/[0.08] bg-white/[0.025] p-5">
      <div className="flex items-center gap-3">
        <div className="flex size-10 items-center justify-center rounded-xl bg-violet-400/10 text-violet-200"><Icon className="size-5" /></div>
        <div>
          <h3 className="font-semibold text-white">{title}</h3>
          <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>
        </div>
      </div>
      {children}
    </section>
  );
}
