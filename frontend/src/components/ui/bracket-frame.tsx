import * as React from "react";
import { cn } from "@/lib/utils";

export function BracketFrame({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("rb-bracket-box", className)}>
      <span className="rb-bracket-corner rb-bracket-tl" aria-hidden="true" />
      <span className="rb-bracket-corner rb-bracket-tr" aria-hidden="true" />
      <span className="rb-bracket-corner rb-bracket-bl" aria-hidden="true" />
      <span className="rb-bracket-corner rb-bracket-br" aria-hidden="true" />
      {children}
    </div>
  );
}

export function Card({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-xl border border-border bg-card text-card-foreground shadow-[0_1px_2px_rgba(0,0,0,0.04)]",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function SectionTag({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border border-border bg-muted px-2.5 py-1 font-mono text-[11px] uppercase tracking-[0.08em] text-muted-foreground",
        className
      )}
    >
      {children}
    </span>
  );
}
