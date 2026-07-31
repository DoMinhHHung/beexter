import type { ReactNode } from "react";
import { DesktopSidebar } from "@/components/layout/desktop-sidebar";
import { MobileNav } from "@/components/layout/mobile-nav";
import { Topbar } from "@/components/layout/topbar";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-dvh lg:pl-[19.5rem]">
      <DesktopSidebar />
      <div className="min-h-dvh">
        <Topbar />
        <main id="main-content" className="mx-auto w-full max-w-[1480px] px-4 pb-28 pt-6 sm:px-6 sm:pt-8 lg:px-8 lg:pb-12">
          {children}
        </main>
      </div>
      <MobileNav />
    </div>
  );
}
