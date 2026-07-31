"use client";

import { useState } from "react";
import Link from "next/link";
import { zodResolver } from "@hookform/resolvers/zod";
import { ArrowLeft, LoaderCircle, MailCheck, Send } from "lucide-react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { forgotPasswordSchema, type ForgotPasswordValues } from "@/lib/validation/onboarding";

export function ForgotPasswordForm() {
  const [submitted, setSubmitted] = useState(false);
  const form = useForm<ForgotPasswordValues>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: { email: "" }
  });

  const submit = form.handleSubmit(async (values) => {
    try {
      const response = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values)
      });
      const payload = (await response.json()) as { error?: { message?: string } };

      if (!response.ok) {
        toast.error(payload.error?.message || "Không thể gửi yêu cầu lúc này");
        return;
      }

      setSubmitted(true);
      toast.success("Yêu cầu đã được tiếp nhận");
    } catch {
      toast.error("Không thể kết nối tới máy chủ");
    }
  });

  if (submitted) {
    return (
      <div className="text-center">
        <div className="mx-auto mb-7 flex size-20 items-center justify-center rounded-3xl border border-emerald-400/[0.15] bg-emerald-400/[0.08]">
          <MailCheck className="size-9 text-emerald-300" />
        </div>
        <h1 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.04em]">Kiểm tra hộp thư</h1>
        <p className="mt-4 leading-7 text-muted-foreground">Nếu email thuộc một tài khoản hợp lệ, Beexster sẽ gửi liên kết đặt lại mật khẩu. Thông báo này không tiết lộ tài khoản có tồn tại hay không.</p>
        <Button asChild variant="outline" size="lg" className="mt-8 w-full">
          <Link href="/sign-in"><ArrowLeft /> Về trang đăng nhập</Link>
        </Button>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-8">
        <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-violet-300">Account recovery</p>
        <h1 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.04em] sm:text-4xl">Quên mật khẩu?</h1>
        <p className="mt-3 leading-7 text-muted-foreground">Nhập email để nhận liên kết đặt lại mật khẩu có thời hạn.</p>
      </div>

      <form onSubmit={submit} className="space-y-5" noValidate>
        <div className="space-y-2.5">
          <Label htmlFor="recovery-email">Email</Label>
          <Input
            id="recovery-email"
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            aria-invalid={Boolean(form.formState.errors.email)}
            {...form.register("email")}
          />
          {form.formState.errors.email && <p className="text-sm text-red-300" role="alert">{form.formState.errors.email.message}</p>}
        </div>

        <Button type="submit" variant="cosmic" size="lg" className="w-full" disabled={form.formState.isSubmitting}>
          {form.formState.isSubmitting ? <LoaderCircle className="animate-spin" /> : <Send />}
          {form.formState.isSubmitting ? "Đang gửi..." : "Gửi liên kết đặt lại"}
        </Button>
      </form>

      <Button asChild variant="ghost" className="mt-5 w-full">
        <Link href="/sign-in"><ArrowLeft /> Quay lại đăng nhập</Link>
      </Button>
    </div>
  );
}
