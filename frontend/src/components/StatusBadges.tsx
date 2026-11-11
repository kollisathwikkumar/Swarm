"use client";

import React from "react";
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Info,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Square,
  XCircle,
} from "lucide-react";

export function RecommendationBadge({ recommendation }: { recommendation: string }) {
  if (recommendation === "Approve") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/12 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
        Approve
      </span>
    );
  }
  if (recommendation === "Request Changes") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/40 bg-rose-500/12 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-rose-700 dark:text-rose-300">
        <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
        Request Changes
      </span>
    );
  }
  if (recommendation === "Incomplete") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/12 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-amber-800 dark:text-amber-300">
        <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
        Incomplete
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted px-2.5 py-0.5 font-mono text-[11px] font-semibold text-foreground">
      <Clock className="h-3.5 w-3.5" aria-hidden="true" />
      {recommendation || "Pending"}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  if (severity === "Critical") {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-red-500/45 bg-red-500/12 px-2 py-0.5 font-mono text-[11px] font-bold text-red-700 dark:text-red-300">
        <AlertOctagon className="h-3 w-3" aria-hidden="true" />
        Critical
      </span>
    );
  }
  if (severity === "High") {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-orange-500/45 bg-orange-500/12 px-2 py-0.5 font-mono text-[11px] font-semibold text-orange-700 dark:text-orange-300">
        <ShieldAlert className="h-3 w-3" aria-hidden="true" />
        High
      </span>
    );
  }
  if (severity === "Medium") {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/12 px-2 py-0.5 font-mono text-[11px] font-semibold text-amber-800 dark:text-amber-300">
        <AlertTriangle className="h-3 w-3" aria-hidden="true" />
        Medium
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded border border-border bg-muted px-2 py-0.5 font-mono text-[11px] font-medium text-muted-foreground">
      <Info className="h-3 w-3" aria-hidden="true" />
      Low
    </span>
  );
}

export function VerificationBadge({ status }: { status: string }) {
  if (status === "Verified") {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/12 px-2 py-0.5 font-mono text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
        <ShieldCheck className="h-3 w-3" aria-hidden="true" />
        Verified
      </span>
    );
  }
  if (status === "Needs Verification") {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/12 px-2 py-0.5 font-mono text-[11px] font-medium text-amber-800 dark:text-amber-300">
        <AlertTriangle className="h-3 w-3" aria-hidden="true" />
        Needs Verification
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded border border-border bg-muted px-2 py-0.5 font-mono text-[11px] font-medium text-muted-foreground">
      <Info className="h-3 w-3" aria-hidden="true" />
      Unverified
    </span>
  );
}

export function AgentStatusBadge({ status }: { status: string }) {
  if (status === "completed") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/12 px-2 py-0.5 font-mono text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
        <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
        Completed
      </span>
    );
  }
  if (status === "running") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-sky-500/40 bg-sky-500/12 px-2 py-0.5 font-mono text-[11px] font-semibold text-sky-700 dark:text-sky-300">
        <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
        Running
      </span>
    );
  }
  if (status === "incomplete") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/12 px-2 py-0.5 font-mono text-[11px] font-semibold text-amber-800 dark:text-amber-300">
        <AlertTriangle className="h-3 w-3" aria-hidden="true" />
        Incomplete
      </span>
    );
  }
  if (status === "stopped") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-2 py-0.5 font-mono text-[11px] font-medium text-muted-foreground">
        <Square className="h-3 w-3" aria-hidden="true" />
        Stopped
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/12 px-2 py-0.5 font-mono text-[11px] font-semibold text-rose-700 dark:text-rose-300">
        <XCircle className="h-3 w-3" aria-hidden="true" />
        Failed
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-2 py-0.5 font-mono text-[11px] font-medium text-muted-foreground">
      <Clock className="h-3 w-3" aria-hidden="true" />
      {status || "Queued"}
    </span>
  );
}
