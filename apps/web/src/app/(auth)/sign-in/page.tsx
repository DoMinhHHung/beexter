import type { Metadata } from "next";
import { Suspense } from "react";
import { SignInForm } from "@/components/auth/sign-in-form";

export const metadata: Metadata = { title: "Đăng nhập" };

export default function SignInPage() {
  return (
    <Suspense fallback={<div className="h-[34rem] animate-pulse rounded-3xl bg-white/[0.04]" />}>
      <SignInForm />
    </Suspense>
  );
}
