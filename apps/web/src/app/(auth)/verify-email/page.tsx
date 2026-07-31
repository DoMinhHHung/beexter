import type { Metadata } from "next";
import { Suspense } from "react";
import { VerifyEmailCard } from "@/components/auth/verify-email-card";

export const metadata: Metadata = { title: "Xác minh email" };

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={<div className="h-80 animate-pulse rounded-3xl bg-white/[0.04]" />}>
      <VerifyEmailCard />
    </Suspense>
  );
}
