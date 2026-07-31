import type { Metadata } from "next";
import { PortfolioGrid } from "@/components/portfolio/portfolio-grid";
import { AnimatedPage } from "@/components/shared/animated-page";

export const metadata: Metadata = { title: "Portfolio" };

export default function PortfolioPage() {
  return <AnimatedPage><PortfolioGrid /></AnimatedPage>;
}
