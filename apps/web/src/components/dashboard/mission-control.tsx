"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import {
  ArrowUpRight,
  BadgeCheck,
  BriefcaseBusiness,
  Building2,
  Clock3,
  MapPin,
  Orbit,
  Sparkles,
  TrendingUp,
  WandSparkles
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { useSession } from "@/components/auth/session-provider";
import { useOnboardingDraft } from "@/hooks/use-onboarding-draft";

const jobs = [
  { title: "Senior Backend Engineer", company: "Nebula Labs", location: "Remote · APAC", fit: 94, salary: "$3.5k–5k", tags: ["Go", "PostgreSQL", "Redis"] },
  { title: "Platform Engineer", company: "Orbit Commerce", location: "Hồ Chí Minh · Hybrid", fit: 89, salary: "$3k–4.5k", tags: ["Kubernetes", "Go", "AWS"] },
  { title: "Founding Backend Engineer", company: "Luma AI", location: "Remote", fit: 86, salary: "$4k–6k", tags: ["Systems", "TypeScript", "AI"] }
];

const activity = [
  { label: "Hồ sơ xuất hiện trong 18 lượt tìm kiếm", time: "2 giờ trước", icon: Orbit },
  { label: "Nebula Labs đã xem portfolio", time: "Hôm qua", icon: Building2 },
  { label: "Profile signal tăng thêm 8%", time: "2 ngày trước", icon: TrendingUp }
];

export function MissionControl() {
  const { user } = useSession();
  const { draft, score, hydrated } = useOnboardingDraft();
  const name = hydrated && draft.personal.firstName
    ? draft.personal.firstName
    : user.email.split("@", 1)[0] || "bạn";

  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-[2rem] border border-white/10 bg-gradient-to-br from-violet-500/[0.13] via-slate-950/80 to-sky-500/[0.08] p-6 shadow-panel sm:p-8 lg:p-10">
        <div className="absolute -right-20 -top-28 size-72 rounded-full border border-white/[0.05]" />
        <div className="absolute -right-8 -top-16 size-48 rounded-full border border-violet-300/10" />
        <div className="relative grid gap-8 lg:grid-cols-[1fr_auto] lg:items-end">
          <div>
            <Badge variant="outline" className="mb-5 border-cyan-300/[0.15] bg-cyan-300/[0.06] text-cyan-200">
              <Sparkles className="mr-1.5 size-3.5" /> Career signal online
            </Badge>
            <p className="text-sm text-slate-400">Chào buổi sáng, {name}</p>
            <h1 className="mt-2 max-w-3xl font-[family-name:var(--font-heading)] text-3xl font-bold leading-tight tracking-[-0.05em] sm:text-4xl lg:text-5xl">
              Cơ hội tốt đang tiến gần <span className="text-gradient">quỹ đạo của bạn.</span>
            </h1>
            <p className="mt-5 max-w-2xl text-sm leading-7 text-slate-300/75 sm:text-base">
              Hồ sơ của bạn phù hợp cao với 12 vị trí mới trong tuần này. Hoàn thiện proof of work để tăng khả năng được liên hệ.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <Button asChild variant="outline"><Link href="/profile">Xem hồ sơ</Link></Button>
            <Button asChild variant="cosmic"><Link href="/onboarding">Tăng profile signal <WandSparkles /></Link></Button>
          </div>
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(20rem,0.8fr)]">
        <div className="space-y-6">
          <section>
            <div className="mb-4 flex items-end justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-violet-300">Recommended orbit</p>
                <h2 className="mt-1 font-[family-name:var(--font-heading)] text-2xl font-bold tracking-[-0.035em]">Việc làm hợp với tín hiệu của bạn</h2>
              </div>
              <Button variant="ghost" className="hidden sm:flex">Xem tất cả <ArrowUpRight /></Button>
            </div>
            <div className="space-y-3">
              {jobs.map((job, index) => (
                <motion.article
                  key={job.title}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.25, delay: index * 0.05 }}
                  whileHover={{ y: -3 }}
                  className="group rounded-3xl border border-white/[0.08] bg-card/[0.65] p-5 shadow-panel backdrop-blur-xl transition-colors hover:border-violet-400/20 sm:p-6"
                >
                  <div className="flex flex-col gap-5 sm:flex-row sm:items-start">
                    <div className="flex size-12 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-gradient-to-br from-violet-400/[0.15] to-sky-300/[0.07] text-violet-200">
                      <Building2 className="size-5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                        <div>
                          <h3 className="text-lg font-semibold tracking-[-0.02em] text-white">{job.title}</h3>
                          <p className="mt-1 text-sm text-slate-400">{job.company}</p>
                        </div>
                        <div className="flex items-center gap-2 rounded-full border border-emerald-400/[0.15] bg-emerald-400/[0.07] px-3 py-1.5 text-xs font-semibold text-emerald-300">
                          <BadgeCheck className="size-3.5" /> {job.fit}% phù hợp
                        </div>
                      </div>
                      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-500">
                        <span className="flex items-center gap-1.5"><MapPin className="size-3.5" /> {job.location}</span>
                        <span className="flex items-center gap-1.5"><BriefcaseBusiness className="size-3.5" /> {job.salary}</span>
                        <span className="flex items-center gap-1.5"><Clock3 className="size-3.5" /> Đăng 1 ngày trước</span>
                      </div>
                      <div className="mt-4 flex flex-wrap gap-2">
                        {job.tags.map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>)}
                      </div>
                    </div>
                    <Button variant="ghost" size="icon" aria-label={`Xem ${job.title}`} className="self-end sm:self-center"><ArrowUpRight /></Button>
                  </div>
                </motion.article>
              ))}
            </div>
          </section>
        </div>

        <div className="space-y-6">
          <Card className="bg-slate-950/[0.55]">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardDescription>Profile signal</CardDescription>
                  <CardTitle className="mt-1 text-3xl">{score}%</CardTitle>
                </div>
                <div className="flex size-12 items-center justify-center rounded-2xl bg-violet-400/10 text-violet-200"><Sparkles /></div>
              </div>
            </CardHeader>
            <CardContent>
              <Progress value={score} />
              <div className="mt-5 space-y-3">
                <SignalItem done={Boolean(draft.personal.headline)} label="Headline rõ ràng" />
                <SignalItem done={draft.skills.length >= 3} label="Tối thiểu 3 kỹ năng" />
                <SignalItem done={draft.projects.length > 0} label="Dự án nổi bật" />
              </div>
              <Button asChild variant="outline" className="mt-5 w-full"><Link href="/onboarding">Hoàn thiện hồ sơ</Link></Button>
            </CardContent>
          </Card>

          <Card className="bg-slate-950/[0.55]">
            <CardHeader>
              <CardDescription>Recent activity</CardDescription>
              <CardTitle>Chuyển động gần đây</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {activity.map((item) => {
                const Icon = item.icon;
                return (
                  <div key={item.label} className="flex gap-3">
                    <div className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-white/[0.04] text-sky-200"><Icon className="size-4" /></div>
                    <div>
                      <p className="text-sm leading-6 text-slate-200">{item.label}</p>
                      <p className="mt-1 text-xs text-slate-500">{item.time}</p>
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function SignalItem({ done, label }: { done: boolean; label: string }) {
  return (
    <div className="flex items-center gap-3 text-sm">
      <span className={`flex size-6 items-center justify-center rounded-full ${done ? "bg-emerald-400/10 text-emerald-300" : "bg-white/[0.04] text-slate-600"}`}>
        {done ? <BadgeCheck className="size-4" /> : <span className="size-1.5 rounded-full bg-current" />}
      </span>
      <span className={done ? "text-slate-300" : "text-slate-500"}>{label}</span>
    </div>
  );
}
