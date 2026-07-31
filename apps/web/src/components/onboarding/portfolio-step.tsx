"use client";

import type { ComponentType } from "react";
import { ExternalLink, Github, Globe2, Linkedin, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import type { PortfolioProject, SocialLinks } from "@/types/profile";
import { StepHeader } from "./step-header";

interface PortfolioStepProps {
  projects: PortfolioProject[];
  links: SocialLinks;
  onChange: (projects: PortfolioProject[], links: SocialLinks) => void;
  submitSignal: number;
}

function emptyProject(): PortfolioProject {
  return { id: crypto.randomUUID(), title: "", description: "", url: "", tags: [] };
}

export function PortfolioStep({ projects, links, onChange, submitSignal }: PortfolioStepProps) {

  const updateProject = (id: string, patch: Partial<PortfolioProject>) => {
    onChange(projects.map((project) => (project.id === id ? { ...project, ...patch } : project)), links);
  };

  const updateLinks = (patch: Partial<SocialLinks>) => onChange(projects, { ...links, ...patch });

  return (
    <div>
      <StepHeader
        eyebrow="04 · Proof of work"
        title="Biến năng lực thành tín hiệu đáng tin"
        description="Đính kèm dự án, GitHub, LinkedIn hoặc website. Một bằng chứng cụ thể thường thuyết phục hơn nhiều dòng mô tả chung chung."
      />

      <div className="grid gap-5 sm:grid-cols-3">
        <LinkField id="linkedin" icon={Linkedin} label="LinkedIn" value={links.linkedin} onChange={(value) => updateLinks({ linkedin: value })} placeholder="linkedin.com/in/you" />
        <LinkField id="github" icon={Github} label="GitHub" value={links.github} onChange={(value) => updateLinks({ github: value })} placeholder="github.com/you" />
        <LinkField id="website" icon={Globe2} label="Website" value={links.website} onChange={(value) => updateLinks({ website: value })} placeholder="your-site.dev" />
      </div>

      <div className="my-8 flex items-center gap-4">
        <div className="h-px flex-1 bg-white/[0.08]" />
        <span className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Dự án nổi bật</span>
        <div className="h-px flex-1 bg-white/[0.08]" />
      </div>

      <div className="space-y-4">
        {projects.map((project, index) => (
          <fieldset key={project.id} className="rounded-3xl border border-white/[0.08] bg-white/[0.025] p-5 sm:p-6">
            <legend className="sr-only">Dự án {index + 1}</legend>
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="font-semibold text-white">Dự án {index + 1}</p>
                <p className="mt-1 text-xs text-muted-foreground">Nêu rõ vấn đề, vai trò và kết quả</p>
              </div>
              <Button type="button" variant="ghost" size="icon" onClick={() => onChange(projects.filter((item) => item.id !== project.id), links)} aria-label={`Xóa dự án ${index + 1}`}>
                <Trash2 />
              </Button>
            </div>
            <div className="grid gap-5 sm:grid-cols-2">
              <div className="space-y-2.5">
                <Label htmlFor={`project-title-${project.id}`}>Tên dự án</Label>
                <Input id={`project-title-${project.id}`} value={project.title} onChange={(event) => updateProject(project.id, { title: event.target.value })} placeholder="Realtime Collaboration Engine" />
              </div>
              <div className="space-y-2.5">
                <Label htmlFor={`project-url-${project.id}`}>Liên kết</Label>
                <div className="relative">
                  <ExternalLink className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-slate-500" />
                  <Input id={`project-url-${project.id}`} value={project.url} onChange={(event) => updateProject(project.id, { url: event.target.value })} className="pl-11" placeholder="https://..." />
                </div>
              </div>
              <div className="space-y-2.5 sm:col-span-2">
                <Label htmlFor={`project-description-${project.id}`}>Mô tả tác động</Label>
                <Textarea id={`project-description-${project.id}`} value={project.description} onChange={(event) => updateProject(project.id, { description: event.target.value })} placeholder="Bạn đã xây gì, dùng công nghệ nào và kết quả đo được là gì?" />
              </div>
              <div className="space-y-2.5 sm:col-span-2">
                <Label htmlFor={`project-tags-${project.id}`}>Công nghệ hoặc kỹ năng</Label>
                <Input id={`project-tags-${project.id}`} value={project.tags.join(", ")} onChange={(event) => updateProject(project.id, { tags: event.target.value.split(",").map((tag) => tag.trim()).filter(Boolean) })} placeholder="Go, Redis, WebSocket" />
              </div>
            </div>
          </fieldset>
        ))}

        <Button type="button" variant="outline" className="w-full border-dashed" onClick={() => onChange([...projects, emptyProject()], links)}>
          <Plus /> Thêm dự án nổi bật
        </Button>
      </div>

      {submitSignal > 0 && projects.length === 0 && !Object.values(links).some(Boolean) && (
        <p className="mt-4 text-sm text-red-300" role="alert">Thêm ít nhất một liên kết hoặc dự án để tạo tín hiệu tin cậy.</p>
      )}
    </div>
  );
}

function LinkField({ id, icon: Icon, label, value, onChange, placeholder }: { id: string; icon: ComponentType<{ className?: string }>; label: string; value: string; onChange: (value: string) => void; placeholder: string }) {
  return (
    <div className="space-y-2.5">
      <Label htmlFor={id} className="flex items-center gap-2"><Icon className="size-4 text-violet-300" /> {label}</Label>
      <Input id={id} type="url" inputMode="url" value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} />
    </div>
  );
}
