"use client";

import { useState } from "react";
import Link from "next/link";
import { zodResolver } from "@hookform/resolvers/zod";
import { Eye, EyeOff, LoaderCircle, MailCheck, UserPlus } from "lucide-react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { signUpSchema, type SignUpValues } from "@/lib/validation/onboarding";

export function SignUpForm() {
  const [showPassword, setShowPassword] = useState(false);
  const [createdEmail, setCreatedEmail] = useState("");
  const form = useForm<SignUpValues>({
    resolver: zodResolver(signUpSchema),
    defaultValues: { email: "", password: "", confirmPassword: "" }
  });

  const submit = form.handleSubmit(async (values) => {
    try {
      const response = await fetch("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: values.email, password: values.password })
      });
      const payload = (await response.json()) as {
        data?: { email?: string };
        error?: { message?: string };
      };

      if (!response.ok) {
        toast.error(payload.error?.message || "Không thể tạo tài khoản lúc này");
        return;
      }

      setCreatedEmail(payload.data?.email || values.email.trim().toLowerCase());
      toast.success("Tài khoản đã được tạo");
    } catch {
      toast.error("Không thể kết nối tới máy chủ");
    }
  });

  if (createdEmail) {
    return (
      <div className="text-center">
        <div className="mx-auto mb-7 flex size-20 items-center justify-center rounded-3xl border border-emerald-400/[0.15] bg-emerald-400/[0.08]">
          <MailCheck className="size-9 text-emerald-300" />
        </div>
        <h1 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.04em]">Kiểm tra email của bạn</h1>
        <p className="mt-4 leading-7 text-muted-foreground">
          Beexster đã gửi liên kết xác minh tới <span className="font-medium text-slate-200">{createdEmail}</span>. Hãy xác minh email trước khi đăng nhập.
        </p>
        <Button asChild variant="cosmic" size="lg" className="mt-8 w-full">
          <Link href="/sign-in">Về trang đăng nhập</Link>
        </Button>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-8">
        <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-violet-300">Create your orbit</p>
        <h1 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.04em] sm:text-4xl">Tạo tài khoản Beexster</h1>
        <p className="mt-3 leading-7 text-muted-foreground">Tài khoản mới là một danh tính thông thường, không gắn vai trò quản trị nền tảng.</p>
      </div>

      <form onSubmit={submit} className="space-y-5" noValidate>
        <div className="space-y-2.5">
          <Label htmlFor="signup-email">Email</Label>
          <Input
            id="signup-email"
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            aria-invalid={Boolean(form.formState.errors.email)}
            {...form.register("email")}
          />
          {form.formState.errors.email && <p className="text-sm text-red-300" role="alert">{form.formState.errors.email.message}</p>}
        </div>

        <div className="space-y-2.5">
          <Label htmlFor="signup-password">Mật khẩu</Label>
          <div className="relative">
            <Input
              id="signup-password"
              type={showPassword ? "text" : "password"}
              autoComplete="new-password"
              className="pr-12"
              aria-invalid={Boolean(form.formState.errors.password)}
              {...form.register("password")}
            />
            <button
              type="button"
              onClick={() => setShowPassword((value) => !value)}
              className="absolute right-1 top-1 flex size-10 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={showPassword ? "Ẩn mật khẩu" : "Hiện mật khẩu"}
            >
              {showPassword ? <EyeOff /> : <Eye />}
            </button>
          </div>
          {form.formState.errors.password && <p className="text-sm text-red-300" role="alert">{form.formState.errors.password.message}</p>}
        </div>

        <div className="space-y-2.5">
          <Label htmlFor="signup-confirm-password">Xác nhận mật khẩu</Label>
          <Input
            id="signup-confirm-password"
            type={showPassword ? "text" : "password"}
            autoComplete="new-password"
            aria-invalid={Boolean(form.formState.errors.confirmPassword)}
            {...form.register("confirmPassword")}
          />
          {form.formState.errors.confirmPassword && <p className="text-sm text-red-300" role="alert">{form.formState.errors.confirmPassword.message}</p>}
        </div>

        <Button type="submit" variant="cosmic" size="lg" className="w-full" disabled={form.formState.isSubmitting}>
          {form.formState.isSubmitting ? <LoaderCircle className="animate-spin" /> : <UserPlus />}
          {form.formState.isSubmitting ? "Đang tạo tài khoản..." : "Tạo tài khoản"}
        </Button>
      </form>

      <p className="mt-8 text-center text-sm text-muted-foreground">
        Đã có tài khoản? <Link href="/sign-in" className="inline-flex min-h-11 items-center font-medium text-violet-300 transition-colors hover:text-violet-200">Đăng nhập</Link>
      </p>
    </div>
  );
}
