import type { Metadata } from "next";
import { Suspense } from "react";
import { ResetPasswordForm } from "@/components/auth/reset-password-form";

export const metadata: Metadata = { title: "Đặt lại mật khẩu" };

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<div className="h-[32rem] animate-pulse rounded-3xl bg-white/[0.04]" />}>
      <ResetPasswordForm />
    </Suspense>
  );
}
