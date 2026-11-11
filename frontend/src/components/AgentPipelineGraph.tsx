"use client";

import React from "react";
import { AlertTriangle, ArrowDown, CheckCircle2, Loader2, Square } from "lucide-react";
import type { AgentRunItem } from "@/lib/types";
import { LiveOrb, type LiveOrbExpression, type LiveOrbVariant } from "@/components/ui/live-orb";

export const AGENT_ORB_PALETTES: Record<string, string[]> = {
  diff_agent: ["#38BDF8", "#818CF8", "#BAE6FD"],
  style_agent: ["#F472B6", "#FB7185", "#FDE68A"],
  security_agent: ["#34D399", "#06B6D4", "#A7F3D0"],
  test_coverage_agent: ["#FBBF24", "#34D399", "#93C5FD"],
  reviewer_manager: ["#7C6AF7", "#7DD3C7", "#E8B4D4"],
  fix_suggestion_agent: ["#60A5FA", "#A78BFA", "#5EEAD4"],
};

export function orbVisualForStatus(status: string): {
  variant: LiveOrbVariant | undefined;
  expression: LiveOrbExpression;
  color?: string;
  eyeColor?: string;
} {
  if (status === "completed") {
    return { variant: "webgl", expression: "completed" };
  }
  if (status === "running") {
    return { variant: "webgl", expression: "running" };
  }
  if (status === "stopped") {
    // Neutral theme-matched orb (no red warning tint) with calm paused eyes
    return {
      variant: undefined,
      expression: "alert",
    };
  }
  if (status === "incomplete" || status === "failed") {
    return {
      variant: "custom",
      expression: "alert",
      color: "#F59E0B",
      eyeColor: "#09090B",
    };
  }
  return { variant: undefined, expression: "neutral" };
}

interface AgentPipelineGraphProps {
  agentRuns: AgentRunItem[];
  liveMessages?: Record<string, string>;
  reviewStatus?: string;
  showWorkflowHero?: boolean;
  findingsCount?: number;
  patchCount?: number;
  reportCount?: number;
  timelineValues?: number[];
  timelineLabels?: string[];
}

function AgentOrbNode({
  run,
  liveMsg,
  size = 92,
}: {
  run: AgentRunItem;
  liveMsg?: string;
  size?: number;
}) {
  const palette = AGENT_ORB_PALETTES[run.agent_name] || ["#7C6AF7", "#7DD3C7", "#E8B4D4"];
  const visual = orbVisualForStatus(run.status);

  return (
    <div
      className="flex flex-col items-center text-center"
      title={liveMsg || run.error_message || run.summary || `${run.agent_label} (${run.status})`}
    >
      <LiveOrb
        size={size}
        variant={visual.variant}
        expression={visual.expression}
        colors={palette}
        color={visual.color}
        eyeColor={visual.eyeColor}
        interactive={run.status !== "stopped"}
        blink={run.status !== "completed" && run.status !== "stopped"}
      />

      <p className="mt-2.5 text-sm font-semibold tracking-tight">{run.agent_label}</p>
      <p className="font-mono text-[11px] text-muted-foreground">{run.model_used}</p>

      <div className="mt-1.5 flex items-center justify-center gap-1.5 font-mono text-[11px]">
        {run.status === "completed" ? (
          <span className="inline-flex items-center gap-1 font-medium text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
            Completed{run.duration_ms > 0 ? ` · ${(run.duration_ms / 1000).toFixed(1)}s` : ""}
          </span>
        ) : run.status === "running" ? (
          <span className="inline-flex items-center gap-1 font-medium text-sky-600 dark:text-sky-400">
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            Running
          </span>
        ) : run.status === "stopped" ? (
          <span className="inline-flex items-center gap-1 font-medium text-muted-foreground">
            <Square className="h-3 w-3" aria-hidden="true" />
            Stopped
          </span>
        ) : run.status === "incomplete" || run.status === "failed" ? (
          <span className="inline-flex items-center gap-1 font-medium text-amber-600 dark:text-amber-400">
            <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
            Incomplete
          </span>
        ) : (
          <span className="text-muted-foreground">Queued</span>
        )}
      </div>

      {run.error_message && (
        <p
          className={`mt-1 max-w-[200px] truncate text-[11px] ${
            run.status === "stopped"
              ? "text-muted-foreground/80"
              : "text-amber-700 dark:text-amber-300"
          }`}
        >
          {run.error_message}
        </p>
      )}
    </div>
  );
}

export function AgentPipelineGraph({ agentRuns, liveMessages = {} }: AgentPipelineGraphProps) {
  const byKey = new Map<string, AgentRunItem>();
  for (const r of agentRuns) byKey.set(r.agent_name, r);

  const getOrFallback = (key: string, label: string, model: string): AgentRunItem =>
    byKey.get(key) || {
      id: key,
      agent_name: key,
      agent_label: label,
      model_used: model,
      status: "queued",
      summary: "",
      duration_ms: 0,
    };

  const parallelRuns = [
    getOrFallback("diff_agent", "Diff Agent", "deepseek-flash"),
    getOrFallback("style_agent", "Style Agent", "deepseek-flash"),
    getOrFallback("security_agent", "Security Agent", "deepseek-v4-pro"),
    getOrFallback("test_coverage_agent", "Test-Coverage Agent", "deepseek-flash"),
  ];
  const managerRun = getOrFallback("reviewer_manager", "Reviewer Manager", "deepseek-v4-pro");
  const fixRun = getOrFallback("fix_suggestion_agent", "Fix-Suggestion Agent", "deepseek-v4-pro");

  return (
    <div className="space-y-8 py-4">
      {/* Tier 1: Parallel Specialists (4 Borderless Expressive Live Orbs) */}
      <div className="grid grid-cols-2 gap-8 md:grid-cols-4">
        {parallelRuns.map((run) => (
          <AgentOrbNode key={run.agent_name} run={run} liveMsg={liveMessages[run.agent_name]} />
        ))}
      </div>

      <div className="flex justify-center">
        <ArrowDown className="h-4 w-4 text-muted-foreground/60" aria-hidden="true" />
      </div>

      {/* Tier 2: Consolidator Orb */}
      <div className="flex justify-center">
        <AgentOrbNode
          run={managerRun}
          liveMsg={liveMessages[managerRun.agent_name]}
          size={100}
        />
      </div>

      <div className="flex justify-center">
        <ArrowDown className="h-4 w-4 text-muted-foreground/60" aria-hidden="true" />
      </div>

      {/* Tier 3: Patch Generator Orb */}
      <div className="flex justify-center">
        <AgentOrbNode run={fixRun} liveMsg={liveMessages[fixRun.agent_name]} size={92} />
      </div>
    </div>
  );
}
