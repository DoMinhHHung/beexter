import { BriefcaseBusiness, LayoutDashboard, Orbit, UserRound } from "lucide-react";

export const workspaceNavigation = [
  { href: "/dashboard", label: "Tổng quan", icon: LayoutDashboard },
  { href: "/profile", label: "Hồ sơ", icon: UserRound },
  { href: "/portfolio", label: "Portfolio", icon: Orbit },
  { href: "/onboarding", label: "Thiết lập", icon: BriefcaseBusiness }
] as const;
