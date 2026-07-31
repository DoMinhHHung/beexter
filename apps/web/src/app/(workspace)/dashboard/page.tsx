import type { Metadata } from "next";
import { MissionControl } from "@/components/dashboard/mission-control";
import { AnimatedPage } from "@/components/shared/animated-page";

export const metadata: Metadata = { title: "Mission Control" };

export default function DashboardPage() {
  return <AnimatedPage><MissionControl /></AnimatedPage>;
}
