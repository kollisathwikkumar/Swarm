"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { LogOut, Radio, RefreshCw, Square } from "lucide-react";
import { apiFetch, connectResilientWebSocket } from "@/lib/api";
import type { AgentRunItem, ReviewDetailResponse, ReviewSummaryItem } from "@/lib/types";
import { AgentPipelineGraph } from "@/components/AgentPipelineGraph";
import { AgentStatusBadge } from "@/components/StatusBadges";

interface LiveEvent {
  review_id: string;
  event_type: string;
  timestamp: string;
  agent_name?: string;
  message?: string;
  summary?: string;
  error?: string;
}

export default function AgentActivityPage() {
  const [recentRuns, setRecentRuns] = useState<AgentRunItem[]>([]);
  const [latestReview, setLatestReview] = useState<ReviewDetailResponse | null>(null);
  const [activeRunningReview, setActiveRunningReview] = useState<ReviewSummaryItem | null>(null);
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [liveMessages, setLiveMessages] = useState<Record<string, string>>({});
  const [wsConnected, setWsConnected] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [statusNotice, setStatusNotice] = useState("");
  const [error, setError] = useState("");

  const loadData = useCallback(async () => {
    try {
      const [runsRes, revsRes] = await Promise.all([
        apiFetch<{ runs: AgentRunItem[] }>("/api/agents/runs?limit=30"),
        apiFetch<{ reviews: ReviewSummaryItem[] }>("/api/reviews"),
      ]);
      setRecentRuns(runsRes.runs);
      const running =
        revsRes.reviews.find(
          (r) => r.review_status === "running" || r.review_status === "queued"
        ) || null;
      setActiveRunningReview(running);
      const targetId = running?.id || revsRes.reviews[0]?.id;
      if (targetId) {
        const detail = await apiFetch<ReviewDetailResponse>(`/api/reviews/${targetId}`);
        setLatestReview(detail);
      } else {
        setLatestReview(null);
      }
    } catch {
      // handled cleanly by empty state
    }
  }, []);

  useEffect(() => {
    void loadData();
    return connectResilientWebSocket("/ws/activity", {
      onOpen: () => setWsConnected(true),
      onClose: () => setWsConnected(false),
      onMessage: (evt) => {
        try {
          const data = JSON.parse(evt.data) as LiveEvent;
          setLiveEvents((prev) => [data, ...prev].slice(0, 40));
          if (data.agent_name && (data.message || data.summary || data.error)) {
            setLiveMessages((prev) => ({
              ...prev,
              [data.agent_name!]: data.message || data.summary || data.error || "",
            }));
          }
          if (
            data.event_type === "review_completed" ||
            data.event_type === "review_started" ||
            data.event_type === "review_stopped" ||
            data.event_type === "review_failed" ||
            data.event_type === "agent_started" ||
            data.event_type === "agent_completed"
          ) {
            void loadData();
          }
        } catch {
          // ignore non-json ping
        }
      },
    });
  }, [loadData]);

  const isOperationRunning =
    Boolean(activeRunningReview) ||
    latestReview?.review.review_status === "running" ||
    latestReview?.review.review_status === "queued";

  const isStoppedTask =
    !isOperationRunning && latestReview?.review.review_status === "stopped";

  useEffect(() => {
    if (!isOperationRunning) return;
    const timer = setInterval(() => {
      void loadData();
    }, 2500);
    return () => clearInterval(timer);
  }, [isOperationRunning, loadData]);

  const handleStopOperation = async () => {
    const targetId = activeRunningReview?.id || latestReview?.review.id;
    if (!targetId) return;
    setStopping(true);
    setError("");
    setStatusNotice("");
    try {
      await apiFetch(`/api/reviews/${targetId}/stop`, { method: "POST" });
      setStatusNotice("Operation stopped — remaining LLM calls aborted.");
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed stopping operation");
    } finally {
      setStopping(false);
    }
  };

  const handleRerunStopped = async () => {
    const targetId = latestReview?.review.id;
    if (!targetId) return;
    setStopping(true);
    setError("");
    setStatusNotice("");
    try {
      await apiFetch(`/api/reviews/${targetId}/rerun`, { method: "POST" });
      setLiveMessages({});
      setStatusNotice("Re-running review with all 6 agents.");
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed re-running review");
    } finally {
      setStopping(false);
    }
  };

  const handleLeaveStoppedTask = async () => {
    const targetId = latestReview?.review.id;
    if (!targetId) return;
    setStopping(true);
    setError("");
    setStatusNotice("");
    try {
      await apiFetch(`/api/reviews/${targetId}`, { method: "DELETE" });
      setLiveMessages({});
      setStatusNotice("Left stopped task.");
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed leaving stopped task");
    } finally {
      setStopping(false);
    }
  };

  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">Agent Activity</h1>
          {latestReview && (
            <Link
              href={`/reviews/${latestReview.review.id}`}
              className="font-mono text-xs text-muted-foreground hover:text-foreground hover:underline"
            >
              {latestReview.review.repository_name} ({latestReview.review.target_commit.slice(0, 8)}) →
            </Link>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {isOperationRunning && (
            <button
              type="button"
              disabled={stopping}
              onClick={handleStopOperation}
              className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/12 px-3 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-500/20 disabled:opacity-50 dark:text-rose-300"
            >
              <Square className="h-3.5 w-3.5" aria-hidden="true" />
              {stopping ? "Stopping..." : "Stop Operation"}
            </button>
          )}
          <div className="flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 font-mono text-[11px]">
            <Radio
              className={`h-3.5 w-3.5 ${
                wsConnected ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"
              }`}
              aria-hidden="true"
            />
            <span>{wsConnected ? "Live" : "Connecting"}</span>
          </div>
        </div>
      </header>

      {statusNotice && (
        <div
          aria-live="polite"
          role="status"
          className="rounded-xl border border-border bg-card p-3 text-xs text-foreground"
        >
          {statusNotice}
        </div>
      )}
      {error && (
        <div
          role="alert"
          className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300"
        >
          {error}
        </div>
      )}

      {isStoppedTask && (
        <section
          aria-label="Stopped task options"
          className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border bg-card px-4 py-3"
        >
          <div className="flex items-center gap-2.5 text-xs">
            <Square className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
            <span className="font-semibold">Stopped</span>
            <span className="text-muted-foreground">
              This operation was stopped before completion.
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={stopping}
              onClick={handleRerunStopped}
              className="inline-flex min-h-9 items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              Re-run
            </button>
            <button
              type="button"
              disabled={stopping}
              onClick={handleLeaveStoppedTask}
              className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-border bg-muted px-3 py-1.5 text-xs font-medium text-foreground hover:border-foreground/40 disabled:opacity-50"
            >
              <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
              Leave Task
            </button>
          </div>
        </section>
      )}

      {/* Borderless Expressive 6-Orb Pipeline */}
      <AgentPipelineGraph
        agentRuns={latestReview?.agent_runs || []}
        liveMessages={liveMessages}
        reviewStatus={latestReview?.review.review_status || "idle"}
      />

      {liveEvents.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5">
          <h2 className="mb-3 text-sm font-semibold">Live Stream</h2>
          <ul className="rb-scroll max-h-56 space-y-1.5 font-mono text-xs">
            {liveEvents.map((ev, i) => (
              <li
                key={`${ev.timestamp}-${i}`}
                className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 py-1.5 last:border-b-0"
              >
                <span>
                  <strong className="text-foreground">{ev.event_type}</strong>
                  {ev.agent_name ? ` [${ev.agent_name}]` : ""} —{" "}
                  <span className="text-muted-foreground">
                    {ev.message || ev.summary || ev.error || ev.review_id.slice(0, 8)}
                  </span>
                </span>
                <span className="text-muted-foreground">
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Recorded Executions Table */}
      <section className="rounded-xl border border-border bg-card p-5">
        <h2 className="mb-4 text-base font-semibold">Execution History</h2>
        {recentRuns.length === 0 ? (
          <p className="text-sm text-muted-foreground">No executions recorded yet.</p>
        ) : (
          <div tabIndex={0} role="region" aria-labelledby="agent-runs-cap" className="table-wrapper">
            <table className="rb-table rb-table--responsive text-left text-sm">
              <caption id="agent-runs-cap" className="visually-hidden">
                Historical execution log for all six agents
              </caption>
              <thead>
                <tr className="border-b border-border font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th scope="col" className="px-3 py-2">Agent</th>
                  <th scope="col" className="px-3 py-2">Repository</th>
                  <th scope="col" className="px-3 py-2">Model</th>
                  <th scope="col" className="px-3 py-2">Status</th>
                  <th scope="col" className="px-3 py-2">Latency</th>
                  <th scope="col" className="px-3 py-2">Summary</th>
                </tr>
              </thead>
              <tbody>
                {recentRuns.map((r) => (
                  <tr key={r.id} className="border-b border-border last:border-b-0">
                    <th scope="row" className="px-3 py-2.5 font-medium">{r.agent_label}</th>
                    <td data-label="Repository" className="px-3 py-2.5 text-xs">{r.repository_name}</td>
                    <td data-label="Model" className="px-3 py-2.5 font-mono text-xs">{r.model_used}</td>
                    <td data-label="Status" className="px-3 py-2.5"><AgentStatusBadge status={r.status} /></td>
                    <td data-label="Latency" className="px-3 py-2.5 font-mono text-xs">{r.duration_ms} ms</td>
                    <td data-label="Summary" className="max-w-md truncate px-3 py-2.5 text-xs text-muted-foreground">
                      {r.error_message || r.summary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
