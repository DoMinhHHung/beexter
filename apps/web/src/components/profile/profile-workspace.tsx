"use client";

import type { ComponentType, ReactNode } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { BriefcaseBusiness, ExternalLink, Github, Globe2, Linkedin, MapPin, Pencil, Radar, Sparkles, UserRound } from "lucide-react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { skillLevelLabels } from "@/lib/constants";
import { useOnboardingDraft } from "@/hooks/use-onboarding-draft";

export function ProfileWorkspace() {
  const { draft, score, hydrated } = useOnboardingDraft();
  if (!hydrated) return <div className="h-[44rem] animate-pulse rounded-[2rem] bg-white/[0.025]" />;

  const fullName = `${draft.personal.firstName || "Minh"} ${draft.personal.lastName || "Hoàng"}`;

  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-[2rem] border border-white/10 bg-slate-950/60 p-6 shadow-panel backdrop-blur-xl sm:p-8">
        <div className="absolute right-0 top-0 size-64 bg-[radial-gradient(circle,rgba(124,58,237,0.14),transparent_68%)]" />
        <div className="relative flex flex-col gap-6 lg:flex-row lg:items-center">
          <Avatar className="size-24 border-2 border-violet-300/20 shadow-glow sm:size-28">
            <AvatarFallback className="text-2xl">{fullName.split(" ").map((part) => part[0]).slice(-2).join("")}</AvatarFallback>
          </Avatar>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.045em] sm:text-4xl">{fullName}</h1>
              <Badge variant="success">Open to work</Badge>
            </div>
            <p className="mt-2 text-base text-slate-300">{draft.personal.headline || "Senior Go Backend Engineer · Distributed Systems"}</p>
            <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-sm text-slate-500">
              <span className="flex items-center gap-2"><MapPin className="size-4" /> {draft.personal.location || "Hồ Chí Minh, Việt Nam"}</span>
              <span className="flex items-center gap-2"><Radar className="size-4" /> {draft.personal.workPreference || "remote"}</span>
            </div>
          </div>
          <Button asChild variant="cosmic"><Link href="/onboarding?step=0"><Pencil /> Chỉnh sửa hồ sơ</Link></Button>
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(20rem,0.7fr)]">
        <div className="space-y-6">
          <ProfileSection icon={UserRound} title="Giới thiệu" actionHref="/onboarding?step=0">
            <p className="text-sm leading-7 text-slate-300/80">{draft.personal.about || "Tôi xây dựng các hệ thống backend có khả năng mở rộng, chú trọng bảo mật và trải nghiệm developer. Tôi thích biến bài toán phức tạp thành kiến trúc rõ ràng, dễ vận hành."}</p>
          </ProfileSection>

          <ProfileSection icon={Sparkles} title="Kỹ năng" actionHref="/onboarding?step=1">
            <div className="flex flex-wrap gap-2.5">
              {(draft.skills.length ? draft.skills : [
                { id: "1", name: "Go", level: "expert" as const },
                { id: "2", name: "PostgreSQL", level: "advanced" as const },
                { id: "3", name: "Redis", level: "advanced" as const }
              ]).map((skill) => <Badge key={skill.id} variant="outline" className="py-2">{skill.name} · {skillLevelLabels[skill.level]}</Badge>)}
            </div>
          </ProfileSection>

          <ProfileSection icon={BriefcaseBusiness} title="Kinh nghiệm" actionHref="/onboarding?step=2">
            <div className="space-y-5">
              {(draft.experiences.length ? draft.experiences : [{ id: "demo", role: "Senior Backend Engineer", company: "Nebula Labs", startDate: "2023-03", endDate: "", current: true, description: "Thiết kế identity platform và các hệ thống distributed phục vụ hàng triệu request mỗi ngày." }]).map((experience, index) => (
                <motion.article key={experience.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.04 }} className="relative border-l border-white/10 pl-6">
                  <span className="absolute -left-1.5 top-1.5 size-3 rounded-full border-2 border-slate-950 bg-violet-400" />
                  <h3 className="font-semibold text-white">{experience.role}</h3>
                  <p className="mt-1 text-sm text-violet-200">{experience.company}</p>
                  <p className="mt-1 text-xs text-slate-500">{experience.startDate} — {experience.current ? "Hiện tại" : experience.endDate}</p>
                  <p className="mt-3 text-sm leading-6 text-slate-400">{experience.description}</p>
                </motion.article>
              ))}
            </div>
          </ProfileSection>
        </div>

        <div className="space-y-6">
          <Card className="bg-slate-950/[0.55]">
            <CardHeader>
              <CardDescription>Profile signal</CardDescription>
              <div className="flex items-end justify-between gap-3"><CardTitle className="text-3xl">{score}%</CardTitle><span className="text-xs text-cyan-300">Strong signal</span></div>
            </CardHeader>
            <CardContent>
              <Progress value={score} />
              <p className="mt-4 text-sm leading-6 text-muted-foreground">Hồ sơ có headline rõ ràng, kỹ năng cụ thể và proof of work sẽ được ưu tiên trong matching.</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-950/[0.55]">
            <CardHeader><CardDescription>External signals</CardDescription><CardTitle>Liên kết</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              <SocialRow icon={Linkedin} label="LinkedIn" value={draft.links.linkedin} />
              <SocialRow icon={Github} label="GitHub" value={draft.links.github} />
              <SocialRow icon={Globe2} label="Website" value={draft.links.website} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function ProfileSection({ icon: Icon, title, actionHref, children }: { icon: ComponentType<{ className?: string }>; title: string; actionHref: string; children: ReactNode }) {
  return (
    <Card className="bg-slate-950/[0.55]">
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-xl bg-violet-400/10 text-violet-200"><Icon className="size-5" /></div>
          <CardTitle>{title}</CardTitle>
        </div>
        <Button asChild variant="ghost" size="sm"><Link href={actionHref}><Pencil /> Chỉnh sửa</Link></Button>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function SocialRow({ icon: Icon, label, value }: { icon: ComponentType<{ className?: string }>; label: string; value: string }) {
  return (
    <div className="flex min-h-12 items-center gap-3 rounded-xl px-2 transition-colors hover:bg-white/[0.035]">
      <Icon className="size-4 text-violet-300" />
      <span className="flex-1 text-sm text-slate-300">{value || `Thêm ${label}`}</span>
      <ExternalLink className="size-4 text-slate-600" />
    </div>
  );
}
