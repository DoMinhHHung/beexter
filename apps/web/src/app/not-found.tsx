import Link from "next/link";
import { ArrowLeft, Satellite } from "lucide-react";
import { OrbitLogo } from "@/components/cosmic/orbit-logo";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <main className="flex min-h-dvh items-center justify-center px-6 py-16">
      <div className="w-full max-w-xl text-center">
        <OrbitLogo className="mb-10 justify-center" />
        <div className="mx-auto mb-6 flex size-20 items-center justify-center rounded-3xl border border-white/10 bg-white/[0.05]">
          <Satellite className="size-9 text-violet-300" />
        </div>
        <p className="mb-3 text-sm font-semibold uppercase tracking-[0.28em] text-violet-300">404 · Lost in space</p>
        <h1 className="font-[family-name:var(--font-heading)] text-4xl font-bold tracking-[-0.04em] sm:text-5xl">Tín hiệu này chưa tồn tại</h1>
        <p className="mx-auto mt-5 max-w-md leading-7 text-muted-foreground">Trang bạn tìm kiếm đã trôi khỏi quỹ đạo hoặc chưa được triển khai.</p>
        <Button asChild variant="cosmic" size="lg" className="mt-8">
          <Link href="/dashboard">
            <ArrowLeft /> Trở về Mission Control
          </Link>
        </Button>
      </div>
    </main>
  );
}
