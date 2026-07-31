"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { zodResolver } from "@hookform/resolvers/zod";
import { motion } from "framer-motion";
import { Eye, EyeOff, LoaderCircle, LogIn, ShieldCheck } from "lucide-react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { bindLocalDataToIdentity } from "@/lib/client-storage";
import { signInSchema, type SignInValues } from "@/lib/validation/onboarding";

export function SignInForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [showPassword, setShowPassword] = useState(false);
  const form = useForm<SignInValues>({
    resolver: zodResolver(signInSchema),
    defaultValues: { email: "", password: "" }
  });

  const fillDemo = () => {
    form.setValue("email", "demo@beexster.vn", { shouldValidate: true });
    form.setValue("password", "Cosmic123!", { shouldValidate: true });
  };

  const submit = form.handleSubmit(async (values) => {
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values)
      });
      const payload = (await response.json()) as {
        data?: { user?: { id?: string } };
        error?: { message?: string };
      };

      if (!response.ok) {
        toast.error(payload.error?.message || "Đăng nhập chưa thành công");
        return;
      }

      const identityId = payload.data?.user?.id;
      if (identityId) {
        bindLocalDataToIdentity(identityId);
      }
      toast.success("Đã kết nối với quỹ đạo của bạn");
      router.push(safeWorkspaceDestination(searchParams.get("next")));
      router.refresh();
    } catch {
      toast.error("Không thể kết nối tới máy chủ");
    }
  });

  return (
    <div>
      <div className="mb-8">
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-emerald-400/[0.15] bg-emerald-400/[0.07] px-3 py-1.5 text-xs font-medium text-emerald-300">
          <ShieldCheck className="size-3.5" /> Phiên đăng nhập được bảo vệ
        </div>
        <h2 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.04em] sm:text-4xl">Chào mừng trở lại</h2>
        <p className="mt-3 leading-7 text-muted-foreground">Đăng nhập để tiếp tục hoàn thiện hồ sơ và khám phá cơ hội phù hợp.</p>
      </div>

      <form onSubmit={submit} className="space-y-5" noValidate>
        <div className="space-y-2.5">
          <Label htmlFor="email">Email</Label>
          <Input
            id="email"
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            aria-invalid={Boolean(form.formState.errors.email)}
            {...form.register("email")}
          />
          {form.formState.errors.email && <p className="text-sm text-red-300" role="alert">{form.formState.errors.email.message}</p>}
        </div>

        <div className="space-y-2.5">
          <div className="flex items-center justify-between">
            <Label htmlFor="password">Mật khẩu</Label>
            <Link href="/forgot-password" className="inline-flex min-h-11 items-center text-sm font-medium text-violet-300 transition-colors hover:text-violet-200">
              Quên mật khẩu?
            </Link>
          </div>
          <div className="relative">
            <Input
              id="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              placeholder="••••••••"
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

        <motion.div whileHover={{ y: -2 }} whileTap={{ scale: 0.985 }}>
          <Button type="submit" variant="cosmic" size="lg" className="w-full" disabled={form.formState.isSubmitting}>
            {form.formState.isSubmitting ? <LoaderCircle className="animate-spin" /> : <LogIn />}
            {form.formState.isSubmitting ? "Đang kết nối..." : "Đăng nhập"}
          </Button>
        </motion.div>
      </form>

      <div className="mt-6 rounded-2xl border border-white/[0.08] bg-white/[0.035] p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium text-slate-200">Chế độ demo</p>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">Dùng khi chưa bật Identity API.</p>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={fillDemo}>Điền tài khoản demo</Button>
        </div>
      </div>

      <p className="mt-8 text-center text-sm text-muted-foreground">
        Chưa có tài khoản? <Link href="/sign-up" className="inline-flex min-h-11 items-center font-medium text-violet-300 transition-colors hover:text-violet-200">Tạo tài khoản</Link>
      </p>
    </div>
  );
}

const workspaceDestinations = ["/onboarding", "/dashboard", "/profile", "/portfolio"] as const;

function safeWorkspaceDestination(candidate: string | null) {
  if (!candidate) {
    return "/onboarding";
  }

  const allowed = workspaceDestinations.some(
    (destination) => candidate === destination || candidate.startsWith(`${destination}/`)
  );
  return allowed ? candidate : "/onboarding";
}
