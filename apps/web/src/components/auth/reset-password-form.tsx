"use client";

import { useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { zodResolver } from "@hookform/resolvers/zod";
import { Eye, EyeOff, KeyRound, LoaderCircle } from "lucide-react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clearLocalIdentityData } from "@/lib/client-storage";
import { resetPasswordSchema, type ResetPasswordValues } from "@/lib/validation/onboarding";

export function ResetPasswordForm() {
  const token = useSearchParams().get("token") || "";
  const [showPassword, setShowPassword] = useState(false);
  const [completed, setCompleted] = useState(false);
  const form = useForm<ResetPasswordValues>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: { password: "", confirmPassword: "" }
  });

  const submit = form.handleSubmit(async (values) => {
    if (!token) {
      toast.error("Liên kết đặt lại mật khẩu không có token");
      return;
    }

    try {
      const response = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: values.password })
      });
      const payload = (await response.json()) as { error?: { message?: string } };

      if (!response.ok) {
        toast.error(payload.error?.message || "Không thể đặt lại mật khẩu");
        return;
      }

      clearLocalIdentityData();
      window.history.replaceState(null, "", window.location.pathname);
      setCompleted(true);
      toast.success("Mật khẩu đã được cập nhật");
    } catch {
      toast.error("Không thể kết nối tới máy chủ");
    }
  });

  if (completed) {
    return (
      <div className="text-center">
        <div className="mx-auto mb-7 flex size-20 items-center justify-center rounded-3xl border border-emerald-400/[0.15] bg-emerald-400/[0.08]">
          <KeyRound className="size-9 text-emerald-300" />
        </div>
        <h1 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.04em]">Mật khẩu đã đổi</h1>
        <p className="mt-4 leading-7 text-muted-foreground">Tất cả refresh session cũ đã được thu hồi. Hãy đăng nhập lại bằng mật khẩu mới.</p>
        <Button asChild variant="cosmic" size="lg" className="mt-8 w-full">
          <Link href="/sign-in">Đăng nhập lại</Link>
        </Button>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-8">
        <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-violet-300">Secure reset</p>
        <h1 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.04em] sm:text-4xl">Tạo mật khẩu mới</h1>
        <p className="mt-3 leading-7 text-muted-foreground">Mật khẩu cần chữ hoa, chữ thường, chữ số và ký tự đặc biệt.</p>
      </div>

      {!token && (
        <div className="mb-6 rounded-2xl border border-amber-400/[0.15] bg-amber-400/[0.07] p-4 text-sm leading-6 text-amber-200">
          Hãy mở trang này từ liên kết trong email đặt lại mật khẩu.
        </div>
      )}

      <form onSubmit={submit} className="space-y-5" noValidate>
        <div className="space-y-2.5">
          <Label htmlFor="new-password">Mật khẩu mới</Label>
          <div className="relative">
            <Input
              id="new-password"
              type={showPassword ? "text" : "password"}
              autoComplete="new-password"
              className="pr-12"
              aria-invalid={Boolean(form.formState.errors.password)}
              {...form.register("password")}
            />
            <button
              type="button"
              onClick={() => setShowPassword((value) => !value)}
              className="absolute right-1 top-1 flex size-10 items-center justify-center rounded-lg text-muted-foreground hover:bg-white/[0.06] hover:text-white focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={showPassword ? "Ẩn mật khẩu" : "Hiện mật khẩu"}
            >
              {showPassword ? <EyeOff /> : <Eye />}
            </button>
          </div>
          {form.formState.errors.password && <p className="text-sm text-red-300" role="alert">{form.formState.errors.password.message}</p>}
        </div>

        <div className="space-y-2.5">
          <Label htmlFor="confirm-password">Xác nhận mật khẩu</Label>
          <Input
            id="confirm-password"
            type={showPassword ? "text" : "password"}
            autoComplete="new-password"
            aria-invalid={Boolean(form.formState.errors.confirmPassword)}
            {...form.register("confirmPassword")}
          />
          {form.formState.errors.confirmPassword && <p className="text-sm text-red-300" role="alert">{form.formState.errors.confirmPassword.message}</p>}
        </div>

        <Button type="submit" variant="cosmic" size="lg" className="w-full" disabled={!token || form.formState.isSubmitting}>
          {form.formState.isSubmitting ? <LoaderCircle className="animate-spin" /> : <KeyRound />}
          {form.formState.isSubmitting ? "Đang cập nhật..." : "Cập nhật mật khẩu"}
        </Button>
      </form>
    </div>
  );
}
