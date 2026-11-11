"use client";

import React, { useEffect, useState } from "react";
import { BarChart3 } from "lucide-react";
import { apiFetch } from "@/lib/api";
import type { AnalyticsSummary } from "@/lib/types";

function BarRow({
  label,
  value,
  max,
  colorClass,
}: {
  label: string;
  value: number;
  max: number;
  colorClass: string;
}) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between text-xs">
        <span className="font-medium">{label}</span>
        <span className="font-mono text-muted-foreground">{value}</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
        <div className={`h-full rounded-full ${colorClass}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export default function AnalyticsPage() {
  const [data, setData] = useState<AnalyticsSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void apiFetch<AnalyticsSummary>("/api/analytics/summary")
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="p-6 font-mono text-xs text-muted-foreground">Loading analytics...</div>;
  }

  if (!data || data.totals.reviews === 0) {
    return (
      <div className="space-y-6">
        <header className="border-b border-border pb-4">
          <h1 className="text-2xl font-semibold tracking-tight">Analytics</h1>
        </header>
        <div className="rounded-xl border border-dashed border-border bg-card p-10 text-center">
          <BarChart3 className="mx-auto mb-2 h-6 w-6 text-muted-foreground" aria-hidden="true" />
          <p className="text-sm font-medium">No review analytics yet</p>
        </div>
      </div>
    );
  }

  const maxSev = Math.max(1, ...Object.values(data.severity_breakdown));
  const maxTool = Math.max(1, ...Object.values(data.findings_by_tool));
  const maxAgent = Math.max(1, ...Object.values(data.findings_by_agent));

  return (
    <div className="space-y-6">
      <header className="border-b border-border pb-4">
        <h1 className="text-2xl font-semibold tracking-tight">Analytics</h1>
        <p className="mt-1 font-mono text-xs text-muted-foreground">
          {data.totals.reviews} reviews · {data.totals.findings} findings
        </p>
      </header>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-border bg-card p-4">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Total Reviews</p>
          <p className="mt-1 text-2xl font-semibold">{data.totals.reviews}</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Approved</p>
          <p className="mt-1 text-2xl font-semibold text-emerald-700 dark:text-emerald-300">{data.totals.approved_reviews}</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Request Changes</p>
          <p className="mt-1 text-2xl font-semibold text-rose-700 dark:text-rose-300">{data.totals.request_changes_reviews}</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Incomplete</p>
          <p className="mt-1 text-2xl font-semibold text-amber-800 dark:text-amber-300">{data.totals.incomplete_reviews}</p>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <section className="space-y-3 rounded-xl border border-border bg-card p-5">
          <h2 className="text-sm font-semibold">Findings by Severity</h2>
          <BarRow label="Critical" value={data.severity_breakdown.Critical ?? 0} max={maxSev} colorClass="bg-red-500" />
          <BarRow label="High" value={data.severity_breakdown.High ?? 0} max={maxSev} colorClass="bg-orange-500" />
          <BarRow label="Medium" value={data.severity_breakdown.Medium ?? 0} max={maxSev} colorClass="bg-amber-500" />
          <BarRow label="Low" value={data.severity_breakdown.Low ?? 0} max={maxSev} colorClass="bg-zinc-400" />
        </section>

        <section className="space-y-3 rounded-xl border border-border bg-card p-5">
          <h2 className="text-sm font-semibold">Findings by Tool</h2>
          {Object.entries(data.findings_by_tool).map(([tool, count]) => (
            <BarRow key={tool} label={tool} value={count} max={maxTool} colorClass="bg-foreground" />
          ))}
        </section>

        <section className="space-y-3 rounded-xl border border-border bg-card p-5">
          <h2 className="text-sm font-semibold">Findings by Agent</h2>
          {Object.entries(data.findings_by_agent).map(([agent, count]) => (
            <BarRow key={agent} label={agent} value={count} max={maxAgent} colorClass="bg-foreground/75" />
          ))}
        </section>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <section className="rounded-xl border border-border bg-card p-5">
          <h2 className="mb-3 text-sm font-semibold">Top Affected Files</h2>
          <ul className="space-y-2 text-xs">
            {data.top_affected_files.map((item) => (
              <li
                key={item.file_path}
                className="flex items-center justify-between rounded-lg border border-border bg-muted/60 px-3 py-2 font-mono"
              >
                <span className="truncate">{item.file_path}</span>
                <span className="font-bold">{item.count}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="rounded-xl border border-border bg-card p-5">
          <h2 className="mb-3 text-sm font-semibold">Average Agent Latency (ms)</h2>
          <ul className="space-y-2 text-xs">
            {Object.entries(data.agent_avg_latency_ms).map(([label, ms]) => (
              <li
                key={label}
                className="flex items-center justify-between rounded-lg border border-border bg-muted/60 px-3 py-2"
              >
                <span className="font-medium">{label}</span>
                <span className="font-mono text-muted-foreground">{ms} ms</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
