import type { Metadata } from "next";
import { ProfileWorkspace } from "@/components/profile/profile-workspace";
import { AnimatedPage } from "@/components/shared/animated-page";

export const metadata: Metadata = { title: "Hồ sơ" };

export default function ProfilePage() {
  return <AnimatedPage><ProfileWorkspace /></AnimatedPage>;
}
