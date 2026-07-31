"use client";

import { CircleAlert, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function WorkspaceError({ reset }: { reset: () => void }) {
  return (
    <Card className="mx-auto max-w-xl bg-slate-950/[0.65]">
      <CardContent className="p-8 text-center sm:p-10">
        <div className="mx-auto flex size-16 items-center justify-center rounded-2xl border border-red-400/[0.15] bg-red-400/[0.08] text-red-300">
          <CircleAlert className="size-7" />
        </div>
        <h1 className="mt-6 font-[family-name:var(--font-heading)] text-2xl font-bold text-white">Quỹ đạo vừa bị gián đoạn</h1>
        <p className="mt-3 leading-7 text-muted-foreground">Dữ liệu chưa tải được. Bản nháp onboarding trên thiết bị vẫn được giữ nguyên.</p>
        <Button type="button" variant="cosmic" className="mt-7" onClick={reset}>
          <RotateCcw /> Thử lại
        </Button>
      </CardContent>
    </Card>
  );
}
