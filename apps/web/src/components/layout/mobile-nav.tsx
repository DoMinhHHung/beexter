"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LogOut } from "lucide-react";
import { clearLocalIdentityData } from "@/lib/client-storage";
import { cn } from "@/lib/utils";
import { workspaceNavigation } from "./navigation";

export function MobileNav() {
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
    <nav
      className="safe-bottom fixed inset-x-3 z-50 grid grid-cols-5 rounded-2xl border border-white/10 bg-slate-950/90 p-1.5 shadow-panel backdrop-blur-2xl lg:hidden"
      aria-label="Điều hướng di động"
    >
      {workspaceNavigation.map((item) => {
        const active = pathname.startsWith(item.href);
        const Icon = item.icon;
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex min-h-14 flex-col items-center justify-center gap-1 rounded-xl px-1 text-[10px] font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring",
              active ? "bg-violet-500/[0.15] text-violet-200" : "text-slate-500 hover:text-slate-200"
            )}
          >
            <Icon className="size-5" strokeWidth={1.8} />
            <span>{item.label}</span>
          </Link>
        );
      })}
      <button
        type="button"
        onClick={logout}
        className="flex min-h-14 flex-col items-center justify-center gap-1 rounded-xl px-1 text-[10px] font-medium text-slate-500 transition-colors hover:text-red-200 focus-visible:ring-2 focus-visible:ring-ring"
        aria-label="Đăng xuất"
      >
        <LogOut className="size-5" strokeWidth={1.8} />
        <span>Thoát</span>
      </button>
    </nav>
  );
}
