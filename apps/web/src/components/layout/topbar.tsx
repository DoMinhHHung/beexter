"use client";

import { Bell, Command, Search } from "lucide-react";
import { useSession } from "@/components/auth/session-provider";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function Topbar() {
  const { user } = useSession();
  const accountName = user.email.split("@", 1)[0] || user.email;
  const initials = accountName.slice(0, 2).toUpperCase();
  const accountLabel = user.platformRole === "ADMIN"
    ? "Platform admin"
    : user.platformRole === "VICE_ADMIN"
      ? "Vice admin"
      : "Thành viên";

  return (
    <header className="sticky top-0 z-30 flex min-h-20 items-center justify-between gap-4 border-b border-white/[0.06] bg-background/70 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
      <div className="hidden max-w-md flex-1 md:block">
        <div className="relative">
          <Search className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-slate-500" />
          <Input className="h-11 bg-white/[0.035] pl-11 pr-16" placeholder="Tìm công việc, kỹ năng, công ty..." aria-label="Tìm kiếm" />
          <div className="pointer-events-none absolute right-3 top-1/2 flex -translate-y-1/2 items-center gap-1 rounded-md border border-white/10 bg-white/[0.04] px-1.5 py-1 text-[10px] text-slate-500">
            <Command className="size-3" /> K
          </div>
        </div>
      </div>
      <div className="min-w-0 md:hidden">
        <p className="truncate text-xs font-medium uppercase tracking-[0.2em] text-violet-300">Mission control</p>
        <p className="truncate text-sm font-semibold text-white">Chào, {accountName}</p>
      </div>
      <div className="flex items-center gap-2.5">
        <Button variant="ghost" size="icon" aria-label="Thông báo" className="relative">
          <Bell />
          <span className="absolute right-2.5 top-2.5 size-2 rounded-full border-2 border-background bg-cyan-300" />
        </Button>
        <div className="hidden h-8 w-px bg-white/10 sm:block" />
        <button type="button" className="flex min-h-11 items-center gap-3 rounded-xl px-1.5 pr-3 transition-colors hover:bg-white/[0.05] focus-visible:ring-2 focus-visible:ring-ring" aria-label="Mở menu tài khoản">
          <Avatar className="size-9 border border-white/10">
            <AvatarFallback>{initials}</AvatarFallback>
          </Avatar>
          <div className="hidden text-left sm:block">
            <p className="max-w-40 truncate text-sm font-medium text-white">{user.email}</p>
            <p className="text-[11px] text-slate-500">{accountLabel}</p>
          </div>
        </button>
      </div>
    </header>
  );
}
