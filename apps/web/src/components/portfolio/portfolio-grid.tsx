"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { ArrowUpRight, FolderKanban, Layers3, Plus, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useOnboardingDraft } from "@/hooks/use-onboarding-draft";

const demoProjects = [
  {
    id: "demo-1",
    title: "Identity Platform",
    description: "Authentication platform with refresh rotation, reuse detection, rate limiting and transactional email delivery.",
    url: "",
    tags: ["Go", "PostgreSQL", "Redis"]
  },
  {
    id: "demo-2",
    title: "Realtime Collaboration Engine",
    description: "Low-latency collaboration service supporting presence, cursor sync and resilient reconnect flows.",
    url: "",
    tags: ["WebSocket", "Go", "NATS"]
  }
];

export function PortfolioGrid() {
  const { draft, hydrated } = useOnboardingDraft();
  const projects = hydrated && draft.projects.length ? draft.projects : demoProjects;

  return (
    <div className="space-y-7">
      <section className="flex flex-col gap-5 rounded-[2rem] border border-white/10 bg-slate-950/[0.55] p-6 shadow-panel backdrop-blur-xl sm:flex-row sm:items-end sm:justify-between sm:p-8">
        <div>
          <div className="mb-4 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-violet-300"><Sparkles className="size-4" /> Proof of work</div>
          <h1 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.045em] sm:text-4xl">Portfolio constellation</h1>
          <p className="mt-3 max-w-2xl text-sm leading-7 text-muted-foreground sm:text-base">Những dự án thể hiện cách bạn tư duy, xây dựng và tạo ra tác động thực tế.</p>
        </div>
        <Button asChild variant="cosmic"><Link href="/onboarding?step=3"><Plus /> Thêm dự án</Link></Button>
      </section>

      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        {projects.map((project, index) => (
          <motion.article
            key={project.id}
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.28, delay: index * 0.05 }}
            whileHover={{ y: -5 }}
            className="group flex min-h-[21rem] flex-col overflow-hidden rounded-[1.75rem] border border-white/[0.08] bg-card/[0.65] shadow-panel backdrop-blur-xl transition-colors hover:border-violet-400/25"
          >
            <div className="relative h-36 overflow-hidden border-b border-white/[0.06] bg-gradient-to-br from-violet-600/20 via-indigo-500/10 to-sky-400/[0.06]">
              <div className="absolute inset-0 cosmic-grid opacity-70" />
              <div className="absolute left-5 top-5 flex size-11 items-center justify-center rounded-2xl border border-white/10 bg-slate-950/60 text-violet-200 backdrop-blur-xl">
                <Layers3 className="size-5" />
              </div>
              <div className="absolute -bottom-12 -right-8 size-32 rounded-full border border-cyan-300/10" />
              <div className="absolute -bottom-4 right-7 size-20 rounded-full border border-violet-300/[0.15]" />
            </div>
            <div className="flex flex-1 flex-col p-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-xs font-medium uppercase tracking-[0.16em] text-slate-500">Featured project</p>
                  <h2 className="mt-2 text-xl font-semibold tracking-[-0.025em] text-white">{project.title}</h2>
                </div>
                <Button variant="ghost" size="icon" aria-label={`Mở dự án ${project.title}`}><ArrowUpRight /></Button>
              </div>
              <p className="mt-4 line-clamp-3 text-sm leading-6 text-slate-400">{project.description}</p>
              <div className="mt-auto flex flex-wrap gap-2 pt-6">
                {project.tags.map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>)}
              </div>
            </div>
          </motion.article>
        ))}

        <Link
          href="/onboarding?step=3"
          className="flex min-h-[21rem] flex-col items-center justify-center rounded-[1.75rem] border border-dashed border-white/10 bg-white/[0.02] p-8 text-center transition-colors hover:border-violet-400/25 hover:bg-violet-400/[0.04] focus-visible:ring-2 focus-visible:ring-ring"
        >
          <div className="flex size-14 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.035] text-violet-200"><FolderKanban /></div>
          <p className="mt-5 font-semibold text-white">Thêm một tín hiệu mới</p>
          <p className="mt-2 max-w-xs text-sm leading-6 text-muted-foreground">Dự án cá nhân, open source, case study hoặc sản phẩm bạn tự hào.</p>
        </Link>
      </div>
    </div>
  );
}
