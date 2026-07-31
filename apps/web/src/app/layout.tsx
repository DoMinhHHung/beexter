import type { ReactNode } from "react";
import type { Metadata, Viewport } from "next";
import { Be_Vietnam_Pro, Space_Grotesk } from "next/font/google";
import { CosmicBackground } from "@/components/cosmic/cosmic-background";
import { MotionProvider } from "@/components/shared/motion-provider";
import { Toaster } from "@/components/ui/sonner";
import "./globals.css";

const headingFont = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-heading",
  display: "swap"
});

const bodyFont = Be_Vietnam_Pro({
  subsets: ["latin", "vietnamese"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-body",
  display: "swap"
});

export const metadata: Metadata = {
  title: {
    default: "Beexster — Find your next orbit",
    template: "%s · Beexster"
  },
  description: "A premium job marketplace connecting ambitious talent with teams building the future.",
  applicationName: "Beexster"
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  colorScheme: "dark",
  themeColor: "#050816"
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="vi" className="dark">
      <body className={`${headingFont.variable} ${bodyFont.variable} font-[family-name:var(--font-body)]`}>
        <a
          href="#main-content"
          className="fixed left-4 top-4 z-[1000] -translate-y-24 rounded-xl bg-white px-4 py-3 font-semibold text-slate-950 transition-transform focus:translate-y-0"
        >
          Bỏ qua điều hướng
        </a>
        <MotionProvider>
          <CosmicBackground />
          {children}
          <Toaster />
        </MotionProvider>
      </body>
    </html>
  );
}
