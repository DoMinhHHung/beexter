"use client";

import { useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { motion } from "framer-motion";
import { BadgeCheck, CircleAlert, LoaderCircle, LogIn, MailCheck, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface VerifyState {
  status: "idle" | "loading" | "success" | "error";
  reactivated: boolean;
  message: string;
}

export function VerifyEmailCard() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token") || "";
  const [state, setState] = useState<VerifyState>({
    status: "idle",
    reactivated: false,
    message: token
      ? "Sẵn sàng xác minh địa chỉ email cho tài khoản Beexster của bạn."
      : "Liên kết xác minh không có token."
  });

  async function verify() {
    if (!token) {
      setState({ status: "error", reactivated: false, message: "Liên kết xác minh không có token." });
      return;
    }

    setState({ status: "loading", reactivated: false, message: "Đang xác minh tín hiệu email..." });
    try {
      const response = await fetch("/api/auth/verify-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token })
      });
      const payload = (await response.json()) as {
        data?: { email_verified?: boolean; reactivated?: boolean };
        error?: { message?: string };
      };

      if (!response.ok) {
        setState({ status: "error", reactivated: false, message: payload.error?.message || "Liên kết đã hết hạn hoặc không hợp lệ." });
        return;
      }

      const reactivated = Boolean(payload.data?.reactivated);
      window.history.replaceState(null, "", window.location.pathname);
      setState({
        status: "success",
        reactivated,
        message: reactivated ? "Tài khoản đã được kích hoạt lại và email đã xác minh." : "Email của bạn đã được xác minh thành công."
      });
    } catch {
      setState({ status: "error", reactivated: false, message: "Không thể kết nối tới máy chủ. Hãy thử lại." });
    }
  }

  const Icon = state.status === "idle" ? MailCheck : state.status === "loading" ? LoaderCircle : state.status === "success" ? BadgeCheck : CircleAlert;

  return (
    <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.28 }} className="text-center">
      <div className="mx-auto mb-7 flex size-20 items-center justify-center rounded-3xl border border-white/10 bg-white/[0.05]">
        <Icon className={`size-9 ${state.status === "loading" ? "animate-spin text-violet-300" : state.status === "success" ? "text-emerald-300" : "text-red-300"}`} />
      </div>
      <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-violet-300">Email verification</p>
      <h1 className="font-[family-name:var(--font-heading)] text-3xl font-bold tracking-[-0.04em]">
        {state.status === "idle" ? "Xác minh địa chỉ email" : state.status === "loading" ? "Đang kiểm tra quỹ đạo" : state.status === "success" ? "Tín hiệu đã xác nhận" : "Tín hiệu bị gián đoạn"}
      </h1>
      <p className="mx-auto mt-4 max-w-sm leading-7 text-muted-foreground">{state.message}</p>
      <div className="mt-8">
        {state.status === "success" ? (
          <Button asChild variant="cosmic" size="lg" className="w-full">
            <Link href="/sign-in"><LogIn /> Đăng nhập</Link>
          </Button>
        ) : state.status === "loading" ? null : token ? (
          <Button type="button" variant={state.status === "error" ? "outline" : "cosmic"} size="lg" className="w-full" onClick={verify}>
            <RotateCcw /> {state.status === "error" ? "Thử xác minh lại" : "Xác minh email"}
          </Button>
        ) : (
          <Button asChild variant="outline" size="lg" className="w-full">
            <Link href="/sign-in"><RotateCcw /> Quay lại đăng nhập</Link>
          </Button>
        )}
      </div>
    </motion.div>
  );
}
