"use client";

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Plus, Search, Sparkles, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { skillLevelLabels, suggestedSkills } from "@/lib/constants";
import type { Skill, SkillLevel } from "@/types/profile";
import { StepHeader } from "./step-header";

interface SkillsStepProps {
  value: Skill[];
  onChange: (value: Skill[]) => void;
  submitSignal: number;
}

export function SkillsStep({ value, onChange, submitSignal }: SkillsStepProps) {
  const [query, setQuery] = useState("");
  const filteredSuggestions = useMemo(
    () => suggestedSkills.filter((skill) => skill.toLowerCase().includes(query.toLowerCase()) && !value.some((item) => item.name.toLowerCase() === skill.toLowerCase())),
    [query, value]
  );

  const addSkill = (name: string) => {
    const normalized = name.trim();
    if (!normalized || value.some((item) => item.name.toLowerCase() === normalized.toLowerCase())) return;
    onChange([...value, { id: crypto.randomUUID(), name: normalized, level: "working" }]);
    setQuery("");
  };

  const removeSkill = (id: string) => onChange(value.filter((skill) => skill.id !== id));
  const updateLevel = (id: string, level: SkillLevel) => onChange(value.map((skill) => (skill.id === id ? { ...skill, level } : skill)));

  return (
    <div>
      <StepHeader
        eyebrow="02 · Capability map"
        title="Vẽ bản đồ năng lực của bạn"
        description="Chọn tối thiểu 3 kỹ năng quan trọng. Cấp độ giúp nhà tuyển dụng hiểu bạn có thể đóng góp ở đâu ngay từ ngày đầu."
      />

      <div className="rounded-2xl border border-white/[0.08] bg-white/[0.025] p-4 sm:p-5">
        <label htmlFor="skill-search" className="mb-3 flex items-center gap-2 text-sm font-medium">
          <Search className="size-4 text-violet-300" /> Tìm hoặc thêm kỹ năng
        </label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <Input
            id="skill-search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                addSkill(query);
              }
            }}
            placeholder="Ví dụ: Go, Product Design, AWS..."
          />
          <Button type="button" variant="outline" onClick={() => addSkill(query)} className="sm:w-auto">
            <Plus /> Thêm kỹ năng
          </Button>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {filteredSuggestions.slice(0, 8).map((skill) => (
            <button
              key={skill}
              type="button"
              onClick={() => addSkill(skill)}
              className="min-h-11 rounded-full border border-white/10 bg-white/[0.035] px-3.5 text-xs font-medium text-slate-300 transition-colors hover:border-violet-400/30 hover:bg-violet-400/[0.08] hover:text-white focus-visible:ring-2 focus-visible:ring-ring"
            >
              + {skill}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-6 space-y-3">
        {value.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-white/10 px-6 py-12 text-center">
            <Sparkles className="mx-auto size-7 text-violet-300" />
            <p className="mt-4 font-medium text-slate-200">Chưa có kỹ năng nào trong quỹ đạo</p>
            <p className="mt-2 text-sm text-muted-foreground">Bắt đầu với những năng lực bạn muốn được nhớ đến.</p>
          </div>
        ) : (
          value.map((skill, index) => (
            <motion.div
              key={skill.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2, delay: Math.min(index * 0.03, 0.18) }}
              className="flex flex-col gap-3 rounded-2xl border border-white/[0.08] bg-white/[0.035] p-3 sm:flex-row sm:items-center"
            >
              <div className="flex min-w-0 flex-1 items-center gap-3">
                <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-violet-400/10 text-sm font-bold text-violet-200">{skill.name.slice(0, 2).toUpperCase()}</div>
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-white">{skill.name}</p>
                  <Badge variant="outline" className="mt-1 px-2 py-0.5 text-[10px]">Skill {index + 1}</Badge>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Select value={skill.level} onValueChange={(level) => updateLevel(skill.id, level as SkillLevel)}>
                  <SelectTrigger className="h-10 min-h-10 w-full sm:w-48"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Object.entries(skillLevelLabels).map(([level, label]) => <SelectItem key={level} value={level}>{label}</SelectItem>)}
                  </SelectContent>
                </Select>
                <Button type="button" variant="ghost" size="icon" onClick={() => removeSkill(skill.id)} aria-label={`Xóa kỹ năng ${skill.name}`}>
                  <X />
                </Button>
              </div>
            </motion.div>
          ))
        )}
      </div>

      {submitSignal > 0 && value.length < 3 && <p className="mt-4 text-sm text-red-300" role="alert">Thêm ít nhất 3 kỹ năng để tiếp tục.</p>}
    </div>
  );
}
