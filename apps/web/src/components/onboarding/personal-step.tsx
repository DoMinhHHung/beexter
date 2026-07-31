"use client";

import { useEffect } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { BriefcaseBusiness, MapPin, Radar, UserRound } from "lucide-react";
import { useForm } from "react-hook-form";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { personalProfileSchema, type PersonalProfileValues } from "@/lib/validation/onboarding";
import type { PersonalProfile } from "@/types/profile";
import { StepHeader } from "./step-header";

interface PersonalStepProps {
  value: PersonalProfile;
  onChange: (value: PersonalProfile) => void;
  submitSignal: number;
}

export function PersonalStep({ value, onChange, submitSignal }: PersonalStepProps) {
  const form = useForm<PersonalProfileValues>({
    resolver: zodResolver(personalProfileSchema),
    defaultValues: value,
    mode: "onBlur"
  });

  useEffect(() => {
    if (submitSignal === 0) return;
    void form.trigger();
  }, [form, submitSignal]);

  useEffect(() => {
    const subscription = form.watch((next) => {
      onChange(next as PersonalProfile);
    });
    return () => subscription.unsubscribe();
  }, [form, onChange]);

  const errors = form.formState.errors;

  return (
    <div>
      <StepHeader
        eyebrow="01 · Personal signal"
        title="Bạn muốn thế giới nghề nghiệp nhìn thấy điều gì?"
        description="Tạo phần giới thiệu rõ ràng, có cá tính và đủ dữ liệu để hệ thống matching hiểu đúng hướng phát triển của bạn."
      />

      <div className="grid gap-5 sm:grid-cols-2">
        <Field id="lastName" label="Họ" error={errors.lastName?.message} icon={UserRound}>
          <Input id="lastName" autoComplete="family-name" placeholder="Nguyễn" {...form.register("lastName")} />
        </Field>
        <Field id="firstName" label="Tên" error={errors.firstName?.message} icon={UserRound}>
          <Input id="firstName" autoComplete="given-name" placeholder="Minh" {...form.register("firstName")} />
        </Field>
        <div className="sm:col-span-2">
          <Field id="headline" label="Headline nghề nghiệp" error={errors.headline?.message} icon={BriefcaseBusiness} helper="Cụ thể hơn chức danh hiện tại và thể hiện giá trị bạn tạo ra.">
            <Input id="headline" placeholder="Senior Go Backend Engineer · Distributed Systems" {...form.register("headline")} />
          </Field>
        </div>
        <Field id="location" label="Địa điểm" error={errors.location?.message} icon={MapPin}>
          <Input id="location" autoComplete="address-level2" placeholder="Hồ Chí Minh, Việt Nam" {...form.register("location")} />
        </Field>
        <Field id="workPreference" label="Hình thức làm việc" icon={Radar}>
          <Select value={form.watch("workPreference")} onValueChange={(value) => form.setValue("workPreference", value as PersonalProfileValues["workPreference"], { shouldValidate: true })}>
            <SelectTrigger id="workPreference"><SelectValue placeholder="Chọn hình thức" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="remote">Remote</SelectItem>
              <SelectItem value="hybrid">Hybrid</SelectItem>
              <SelectItem value="onsite">On-site</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <div className="sm:col-span-2">
          <Field id="talentTrack" label="Mục tiêu hiện tại" icon={BriefcaseBusiness}>
            <Select value={form.watch("talentTrack")} onValueChange={(value) => form.setValue("talentTrack", value as PersonalProfileValues["talentTrack"], { shouldValidate: true })}>
              <SelectTrigger id="talentTrack"><SelectValue placeholder="Chọn mục tiêu" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="job_seeker">Tìm vị trí toàn thời gian</SelectItem>
                <SelectItem value="freelancer">Tìm dự án freelance</SelectItem>
                <SelectItem value="open_to_both">Mở cho cả hai</SelectItem>
              </SelectContent>
            </Select>
          </Field>
        </div>
        <div className="sm:col-span-2">
          <Field id="about" label="Giới thiệu ngắn" error={errors.about?.message} helper={`${form.watch("about").length}/600 ký tự`}>
            <Textarea id="about" placeholder="Bạn giỏi điều gì, thích giải quyết loại bài toán nào và muốn tạo ảnh hưởng ra sao?" {...form.register("about")} />
          </Field>
        </div>
      </div>
    </div>
  );
}

interface FieldProps {
  id: string;
  label: string;
  error?: string;
  helper?: string;
  icon?: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
}

function Field({ id, label, error, helper, icon: Icon, children }: FieldProps) {
  return (
    <div className="space-y-2.5">
      <div className="flex items-center justify-between gap-3">
        <Label htmlFor={id} className="flex items-center gap-2">
          {Icon && <Icon className="size-4 text-violet-300" />}
          {label}
        </Label>
        {helper && <span className="text-xs text-muted-foreground">{helper}</span>}
      </div>
      {children}
      {error && <p className="text-sm text-red-300" role="alert">{error}</p>}
    </div>
  );
}
