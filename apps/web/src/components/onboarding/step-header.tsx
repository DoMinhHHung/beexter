import { Badge } from "@/components/ui/badge";

interface StepHeaderProps {
  eyebrow: string;
  title: string;
  description: string;
}

export function StepHeader({ eyebrow, title, description }: StepHeaderProps) {
  return (
    <div className="mb-8">
      <Badge variant="outline" className="mb-4 border-violet-400/20 bg-violet-400/[0.08] text-violet-200">{eyebrow}</Badge>
      <h2 className="font-[family-name:var(--font-heading)] text-2xl font-bold tracking-[-0.035em] sm:text-3xl">{title}</h2>
      <p className="mt-3 max-w-2xl text-sm leading-7 text-muted-foreground sm:text-base">{description}</p>
    </div>
  );
}
