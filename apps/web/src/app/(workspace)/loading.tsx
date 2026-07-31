import { Skeleton } from "@/components/ui/skeleton";

export default function WorkspaceLoading() {
  return (
    <div className="space-y-6" aria-label="Đang tải không gian làm việc">
      <div className="space-y-3">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-10 w-full max-w-lg" />
        <Skeleton className="h-5 w-full max-w-2xl" />
      </div>
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 6 }).map((_, index) => (
          <Skeleton key={index} className="h-56 rounded-3xl" />
        ))}
      </div>
    </div>
  );
}
