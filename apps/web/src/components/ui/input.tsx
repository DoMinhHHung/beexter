import * as React from "react";
import { cn } from "@/lib/utils";

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

const Input = React.forwardRef<HTMLInputElement, InputProps>(({ className, type, ...props }, ref) => (
  <input
    type={type}
    className={cn(
      "flex h-12 w-full rounded-xl border border-white/10 bg-white/[0.045] px-4 py-3 text-base text-foreground shadow-sm transition-colors placeholder:text-muted-foreground/70 focus-visible:border-primary/70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/[0.45] disabled:cursor-not-allowed disabled:opacity-50 md:text-sm",
      className
    )}
    ref={ref}
    {...props}
  />
));
Input.displayName = "Input";

export { Input };
