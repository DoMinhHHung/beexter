"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LogOut, Sparkles } from "lucide-react";
import { OrbitLogo } from "@/components/cosmic/orbit-logo";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { clearLocalIdentityData } from "@/lib/client-storage";
import { cn } from "@/lib/utils";
import { workspaceNavigation } from "./navigation";

export function DesktopSidebar() {
  const pathname = usePathname();
  const router = useRouter();

  const logout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {
      // The local session is still cleared when remote logout is unavailable.
    } finally {
      clearLocalIdentityData();
      router.replace("/sign-in");
      router.refresh();
    }
  };

  return (
    <aside className="fixed inset-y-4 left-4 z-40 hidden w-[17.5rem] flex-col rounded-[1.75rem] border border-white/10 bg-slate-950/70 p-4 shadow-panel backdrop-blur-2xl lg:flex">
      <div className="px-2 pb-7 pt-2">
        <OrbitLogo />
      </div>

      <nav className="space-y-1.5" aria-label="Điều hướng chính">
        {workspaceNavigation.map((item) => {
          const active = pathname.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              aria-current={active ? "page" : undefined}
              className={cn(
                "group flex min-h-12 items-center gap-3 rounded-2xl px-3.5 text-sm font-medium transition-all duration-200 focus-visible:ring-2 focus-visible:ring-ring",
                active
                  ? "bg-gradient-to-r from-violet-500/[0.18] to-sky-400/[0.08] text-white shadow-[inset_0_0_0_1px_rgba(167,139,250,0.18)]"
                  : "text-slate-400 hover:bg-white/[0.05] hover:text-white"
              )}
            >
              <span className={cn("flex size-9 items-center justify-center rounded-xl transition-colors", active ? "bg-violet-400/[0.15] text-violet-200" : "bg-white/[0.035] text-slate-500 group-hover:text-slate-200")}>
                <Icon className="size-[18px]" strokeWidth={1.8} />
              </span>
              {item.label}
              {active && <span className="ml-auto size-1.5 rounded-full bg-cyan-300 shadow-[0_0_12px_rgba(103,232,249,0.9)]" />}
            </Link>
          );
        })}
      </nav>

      <div className="mt-auto space-y-4">
        <div className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <Sparkles className="size-4 text-violet-300" /> Profile signal
            </div>
            <span className="text-xs font-semibold text-cyan-300">72%</span>
          </div>
          <Progress value={72} />
          <p className="mt-3 text-xs leading-5 text-slate-500">Thêm một dự án nổi bật để tăng độ tin cậy.</p>
        </div>
        <Button variant="ghost" className="w-full justify-start text-slate-400" onClick={logout}>
          <LogOut /> Đăng xuất
        </Button>
      </div>
    </aside>
  );
}
