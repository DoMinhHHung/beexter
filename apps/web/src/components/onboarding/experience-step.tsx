"use client";


import { motion } from "framer-motion";
import { BriefcaseBusiness, Building2, CalendarDays, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import type { Experience } from "@/types/profile";
import { StepHeader } from "./step-header";

interface ExperienceStepProps {
  value: Experience[];
  onChange: (value: Experience[]) => void;
  submitSignal: number;
  skipped: boolean;
  onSkippedChange: (value: boolean) => void;
}

function emptyExperience(): Experience {
  return {
    id: crypto.randomUUID(),
    role: "",
    company: "",
    startDate: "",
    endDate: "",
    current: false,
    description: ""
  };
}

export function ExperienceStep({ value, onChange, submitSignal, skipped, onSkippedChange }: ExperienceStepProps) {

  const update = (id: string, patch: Partial<Experience>) => {
    onChange(value.map((item) => (item.id === id ? { ...item, ...patch } : item)));
  };

  return (
    <div>
      <StepHeader
        eyebrow="03 · Career journey"
        title="Những chặng đường đã tạo nên bạn"
        description="Thêm kinh nghiệm có liên quan nhất. Fresher có thể bỏ qua và dùng portfolio, dự án cá nhân hoặc hoạt động cộng đồng để kể câu chuyện năng lực."
      />

      <div className="mb-5 flex flex-col gap-3 rounded-2xl border border-white/[0.08] bg-white/[0.025] p-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-200">Bạn chưa có kinh nghiệm chính thức?</p>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">Bật tùy chọn này để tiếp tục và tập trung vào portfolio.</p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={skipped}
          aria-label="Bỏ qua bước kinh nghiệm"
          onClick={() => onSkippedChange(!skipped)}
          className={`relative h-11 w-14 shrink-0 rounded-full transition-colors focus-visible:ring-2 focus-visible:ring-ring ${skipped ? "bg-violet-500" : "bg-white/10"}`}
        >
          <span className={`absolute left-0 top-3 size-5 rounded-full bg-white shadow transition-transform ${skipped ? "translate-x-8" : "translate-x-1"}`} />
        </button>
      </div>

      {!skipped && (
        <div className="space-y-4">
          {value.map((experience, index) => (
            <motion.fieldset
              key={experience.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-3xl border border-white/[0.08] bg-white/[0.025] p-5 sm:p-6"
            >
              <legend className="sr-only">Kinh nghiệm {index + 1}</legend>
              <div className="mb-5 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="flex size-10 items-center justify-center rounded-xl bg-sky-400/10 text-sky-200"><BriefcaseBusiness className="size-5" /></div>
                  <div>
                    <p className="font-semibold text-white">Chặng đường {index + 1}</p>
                    <p className="text-xs text-muted-foreground">Ưu tiên kết quả và tác động đo được</p>
                  </div>
                </div>
                <Button type="button" variant="ghost" size="icon" onClick={() => onChange(value.filter((item) => item.id !== experience.id))} aria-label={`Xóa kinh nghiệm ${index + 1}`}>
                  <Trash2 />
                </Button>
              </div>

              <div className="grid gap-5 sm:grid-cols-2">
                <div className="space-y-2.5">
                  <Label htmlFor={`role-${experience.id}`} className="flex items-center gap-2"><BriefcaseBusiness className="size-4 text-violet-300" /> Vai trò</Label>
                  <Input id={`role-${experience.id}`} value={experience.role} onChange={(event) => update(experience.id, { role: event.target.value })} placeholder="Backend Engineer" />
                </div>
                <div className="space-y-2.5">
                  <Label htmlFor={`company-${experience.id}`} className="flex items-center gap-2"><Building2 className="size-4 text-violet-300" /> Công ty</Label>
                  <Input id={`company-${experience.id}`} value={experience.company} onChange={(event) => update(experience.id, { company: event.target.value })} placeholder="Nebula Labs" />
                </div>
                <div className="space-y-2.5">
                  <Label htmlFor={`start-${experience.id}`} className="flex items-center gap-2"><CalendarDays className="size-4 text-violet-300" /> Bắt đầu</Label>
                  <Input id={`start-${experience.id}`} type="month" value={experience.startDate} onChange={(event) => update(experience.id, { startDate: event.target.value })} />
                </div>
                <div className="space-y-2.5">
                  <Label htmlFor={`end-${experience.id}`}>Kết thúc</Label>
                  <Input id={`end-${experience.id}`} type="month" disabled={experience.current} value={experience.endDate} onChange={(event) => update(experience.id, { endDate: event.target.value })} />
                  <label className="flex min-h-11 cursor-pointer items-center gap-2 text-sm text-muted-foreground">
                    <input type="checkbox" checked={experience.current} onChange={(event) => update(experience.id, { current: event.target.checked, endDate: event.target.checked ? "" : experience.endDate })} className="size-4 rounded border-white/20 bg-white/5 accent-violet-500" />
                    Tôi vẫn đang làm việc tại đây
                  </label>
                </div>
                <div className="space-y-2.5 sm:col-span-2">
                  <Label htmlFor={`description-${experience.id}`}>Điểm nổi bật</Label>
                  <Textarea id={`description-${experience.id}`} value={experience.description} onChange={(event) => update(experience.id, { description: event.target.value })} placeholder="Mô tả bài toán, hành động và kết quả nổi bật..." />
                </div>
              </div>
            </motion.fieldset>
          ))}

          <Button type="button" variant="outline" className="w-full border-dashed" onClick={() => onChange([...value, emptyExperience()])}>
            <Plus /> Thêm kinh nghiệm
          </Button>
        </div>
      )}

      {submitSignal > 0 && !skipped && value.some((item) => !item.role.trim() || !item.company.trim() || !item.startDate) && (
        <p className="mt-4 text-sm text-red-300" role="alert">Hoàn thiện vai trò, công ty và thời gian bắt đầu cho mỗi kinh nghiệm.</p>
      )}
    </div>
  );
}
