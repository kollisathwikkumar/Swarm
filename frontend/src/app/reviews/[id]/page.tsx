"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Editor, { DiffEditor, type OnMount } from "@monaco-editor/react";
import {
  Check,
  Download,
  FileCode2,
  GitCommit,
  Github,
  LogOut,
  RefreshCw,
  ShieldCheck,
  Square,
  Wrench,
  X,
} from "lucide-react";
import { apiFetch, connectResilientWebSocket, getApiBase, getStoredToken } from "@/lib/api";
import { useResolvedTheme } from "@/lib/theme";
import type {
  AgentRunItem,
  FindingItem,
  PatchSuggestionItem,
  ReviewDetailResponse,
} from "@/lib/types";
import { AgentPipelineGraph } from "@/components/AgentPipelineGraph";
import {
  RecommendationBadge,
  SeverityBadge,
  VerificationBadge,
} from "@/components/StatusBadges";

function guessLanguage(path: string): string {
  if (path.endsWith(".py")) return "python";
  if (path.endsWith(".ts") || path.endsWith(".tsx")) return "typescript";
  if (path.endsWith(".js") || path.endsWith(".jsx")) return "javascript";
  if (path.endsWith(".json")) return "json";
  if (path.endsWith(".yml") || path.endsWith(".yaml")) return "yaml";
  if (path.endsWith(".md")) return "markdown";
  return "plaintext";
}

export default function ConsolidatedCodeReviewPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const reviewId = params.id;
  const { resolved } = useResolvedTheme();

  const [detail, setDetail] = useState<ReviewDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [statusNotice, setStatusNotice] = useState("");
  const [activeTab, setActiveTab] = useState<"review" | "agents" | "patches">("review");

  const [selectedFile, setSelectedFile] = useState<string>("");
  const [viewMode, setViewMode] = useState<"source" | "patch">("source");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);
  const [liveMessages, setLiveMessages] = useState<Record<string, string>>({});
  const [liveRuns, setLiveRuns] = useState<AgentRunItem[]>([]);
  const [busyAction, setBusyAction] = useState(false);

  const editorRef = useRef<Parameters<OnMount>[0] | null>(null);
  const decorationsRef = useRef<string[]>([]);
  const selectedFileRef = useRef<string>("");
  const initialTabResolvedRef = useRef(false);

  const loadDetail = useCallback(async () => {
    try {
      const data = await apiFetch<ReviewDetailResponse>(`/api/reviews/${reviewId}`);
      setDetail(data);
      setLiveRuns(data.agent_runs);
      if (!selectedFileRef.current && data.code_change.changed_files.length > 0) {
        const firstPath = data.code_change.changed_files[0].path;
        selectedFileRef.current = firstPath;
        setSelectedFile(firstPath);
      }
      if (!initialTabResolvedRef.current) {
        initialTabResolvedRef.current = true;
        if (data.review.review_status === "running" || data.review.review_status === "queued") {
          setActiveTab("agents");
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed loading review");
    } finally {
      setLoading(false);
    }
  }, [reviewId]);

  useEffect(() => {
    void loadDetail();
  }, [loadDetail]);

  useEffect(() => {
    const st = detail?.review.review_status;
    if (st !== "queued" && st !== "running") return;
    const timer = setInterval(() => {
      void loadDetail();
    }, 3000);
    return () => clearInterval(timer);
  }, [detail?.review.review_status, loadDetail]);

  useEffect(() => {
    if (!reviewId) return;
    return connectResilientWebSocket(`/ws/reviews/${reviewId}`, {
      onMessage: (evt) => {
        try {
          const msg = JSON.parse(evt.data) as {
            event_type: string;
            agent_name?: string;
            status?: string;
            message?: string;
            summary?: string;
            error?: string;
            duration_ms?: number;
          };

          if (msg.agent_name) {
            setLiveMessages((prev) => ({
              ...prev,
              [msg.agent_name!]: msg.message || msg.summary || msg.error || "Running...",
            }));
            setLiveRuns((prev) =>
              prev.map((run) => {
                if (run.agent_name !== msg.agent_name) return run;
                if (msg.event_type === "agent_started" || msg.event_type === "fan_in_started") {
                  return { ...run, status: "running" };
                }
                if (
                  msg.event_type === "agent_completed" ||
                  msg.event_type === "reviewer_manager_completed" ||
                  msg.event_type === "fix_suggestion_completed"
                ) {
                  return {
                    ...run,
                    status: msg.status || "completed",
                    summary: msg.summary || run.summary,
                    duration_ms: msg.duration_ms ?? run.duration_ms,
                  };
                }
                if (msg.event_type === "agent_failed") {
                  return {
                    ...run,
                    status: msg.status || "failed",
                    error_message: msg.error || run.error_message,
                    duration_ms: msg.duration_ms ?? run.duration_ms,
                  };
                }
                return run;
              })
            );
          }

          if (
            msg.event_type === "review_completed" ||
            msg.event_type === "review_failed" ||
            msg.event_type === "review_stopped"
          ) {
            void loadDetail();
            if (msg.event_type === "review_completed") {
              setActiveTab("review");
            }
          }
        } catch {
          // ignore
        }
      },
    });
  }, [reviewId, loadDetail]);

  useEffect(() => {
    const ed = editorRef.current;
    if (!ed || !highlightedLine || viewMode !== "source") return;
    ed.revealLineInCenter(highlightedLine);
    ed.setPosition({ lineNumber: highlightedLine, column: 1 });
    decorationsRef.current = ed.deltaDecorations(decorationsRef.current, [
      {
        range: {
          startLineNumber: highlightedLine,
          startColumn: 1,
          endLineNumber: highlightedLine,
          endColumn: 1,
        },
        options: {
          isWholeLine: true,
          className: "bg-rose-500/20",
        },
      },
    ]);
  }, [highlightedLine, selectedFile, viewMode]);

  const jumpToFinding = (f: FindingItem) => {
    if (f.file_path) {
      setSelectedFile(f.file_path);
      selectedFileRef.current = f.file_path;
      const hasSnap = Boolean(detail?.code_change.file_snapshots?.[f.file_path]);
      setViewMode(hasSnap ? "source" : "patch");
    }
    setHighlightedLine(f.line_number || 1);
  };

  const filteredFindings = useMemo(() => {
    if (!detail) return [];
    return detail.findings.filter((f) =>
      severityFilter === "ALL" ? true : f.severity === severityFilter
    );
  }, [detail, severityFilter]);

  const activeFileItem = detail?.code_change.changed_files.find((f) => f.path === selectedFile);
  const activeSnapshot = selectedFile ? detail?.code_change.file_snapshots?.[selectedFile] : undefined;
  const editorValue =
    viewMode === "source" && activeSnapshot
      ? activeSnapshot
      : activeFileItem?.patch || detail?.code_change.diff_text || "";

  const handleRerun = async () => {
    setBusyAction(true);
    setError("");
    try {
      const res = await apiFetch<{ review_id: string }>(`/api/reviews/${reviewId}/rerun`, {
        method: "POST",
      });
      router.push(`/reviews/${res.review_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Re-run failed");
      setBusyAction(false);
    }
  };

  const handleStopReview = async () => {
    setBusyAction(true);
    setError("");
    setStatusNotice("");
    try {
      await apiFetch(`/api/reviews/${reviewId}/stop`, { method: "POST" });
      setStatusNotice("Operation stopped — remaining LLM calls aborted.");
      await loadDetail();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Stop failed");
    } finally {
      setBusyAction(false);
    }
  };

  const handleLeaveTask = async () => {
    setBusyAction(true);
    setError("");
    setStatusNotice("");
    try {
      await apiFetch(`/api/reviews/${reviewId}`, { method: "DELETE" });
      router.push("/agents");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed leaving task");
      setBusyAction(false);
    }
  };

  const handlePublishGitHub = async () => {
    setBusyAction(true);
    setError("");
    setStatusNotice("");
    try {
      const res = await apiFetch<{ inline_comments_posted?: number }>(
        `/api/github/reviews/${reviewId}/publish`,
        {
          method: "POST",
          body: JSON.stringify({ include_inline_comments: true, include_commit_status: true }),
        }
      );
      setStatusNotice(
        `Published review to GitHub (${res.inline_comments_posted ?? 0} inline comment(s) posted).`
      );
      await loadDetail();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed publishing to GitHub");
    } finally {
      setBusyAction(false);
    }
  };

  const handleDownloadReport = async (format: "markdown" | "json") => {
    const token = getStoredToken();
    const resp = await fetch(
      `${getApiBase()}/api/reviews/${reviewId}/report?format=${format}`,
      { headers: token ? { Authorization: `Bearer ${token}` } : {} }
    );
    if (!resp.ok) {
      setError("Report artifact is not available yet.");
      return;
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `review-${reviewId.slice(0, 8)}.${format === "json" ? "json" : "md"}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePatchDecision = async (
    patch: PatchSuggestionItem,
    action: "approve" | "reject" | "apply_local" | "publish_github_suggestion" | "commit_to_github_branch"
  ) => {
    setBusyAction(true);
    setError("");
    setStatusNotice("");
    try {
      await apiFetch(`/api/patches/${patch.id}/decision`, {
        method: "POST",
        body: JSON.stringify({ action }),
      });
      setStatusNotice(`Patch "${patch.title}" updated (${action}).`);
      await loadDetail();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Patch action failed");
    } finally {
      setBusyAction(false);
    }
  };

  if (loading) {
    return <div className="p-6 font-mono text-xs text-muted-foreground">Loading consolidated review...</div>;
  }
  if (!detail) {
    return (
      <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-6 text-sm text-rose-700 dark:text-rose-300">
        {error || "Review not found."}
      </div>
    );
  }

  const { review, code_change, findings, patch_suggestions } = detail;
  const reviewerRun = detail.agent_runs.find((r) => r.agent_name === "reviewer_manager");
  const rejectedFps =
    ((reviewerRun?.tool_results as { rejected_false_positives?: Array<{ title: string; file_path: string; reason: string }> })
      ?.rejected_false_positives) || [];

  return (
    <div className="space-y-5">
      {/* Top Review Header */}
      <header className="flex flex-wrap items-start justify-between gap-4 rounded-xl border border-border bg-card p-5">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">
              {review.repository_name}
              {code_change.pr_number ? ` · PR #${code_change.pr_number}` : ""}
            </h1>
            <RecommendationBadge recommendation={review.recommendation} />
            <span className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">
              {review.review_status}
            </span>
          </div>
            <p className="flex flex-wrap items-center gap-2 font-mono text-xs text-muted-foreground">
              <GitCommit className="h-3.5 w-3.5" aria-hidden="true" />
              <span>base: {review.base_commit.slice(0, 12)}</span>
              <span>→</span>
              <span>target: {review.target_commit.slice(0, 12)}</span>
              {code_change.pr_title && <span className="font-sans">· {code_change.pr_title}</span>}
            </p>
            {review.recommendation_reason && (
              <p className="text-xs text-muted-foreground">{review.recommendation_reason}</p>
            )}
          </div>

          <div className="flex flex-wrap gap-2">
            {(review.review_status === "running" || review.review_status === "queued") && (
              <button
                type="button"
                disabled={busyAction}
                onClick={handleStopReview}
                className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/12 px-3 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-500/20 disabled:opacity-50 dark:text-rose-300"
              >
                <Square className="h-3.5 w-3.5" aria-hidden="true" />
                Stop Operation
              </button>
            )}
            {review.review_status === "stopped" && (
              <button
                type="button"
                disabled={busyAction}
                onClick={handleLeaveTask}
                className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-border bg-muted px-3 py-1.5 text-xs font-medium hover:border-foreground/40 disabled:opacity-50"
              >
                <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
                Leave Task
              </button>
            )}
            <button
              type="button"
              disabled={busyAction}
              onClick={handleRerun}
              className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-border bg-muted px-3 py-1.5 text-xs font-medium hover:border-foreground/40"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              Re-run Review
            </button>
            <button
              type="button"
              onClick={() => handleDownloadReport("markdown")}
              className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-border bg-muted px-3 py-1.5 text-xs font-medium hover:border-foreground/40"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              Report (.md)
            </button>
            {review.source_type === "github" && (
              <button
                type="button"
                disabled={busyAction || review.review_status !== "completed"}
                onClick={handlePublishGitHub}
                className="inline-flex min-h-10 items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
              >
                <Github className="h-3.5 w-3.5" aria-hidden="true" />
                {review.github_published_at ? "Re-publish to GitHub" : "Publish to GitHub"}
              </button>
            )}
          </div>
        </header>

      {statusNotice && (
        <div
          aria-live="polite"
          role="status"
          className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-700 dark:text-emerald-300"
        >
          {statusNotice}
        </div>
      )}
      {error && (
        <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300">
          {error}
        </div>
      )}

      {/* Tabs */}
      <div
        role="tablist"
        aria-label="Review sections"
        className="flex gap-1 overflow-x-auto border-b border-border"
      >
        {[
          { key: "review", label: `Code Review (${findings.length} findings)` },
          { key: "agents", label: "6-Agent Execution & Tools" },
          { key: "patches", label: `Fix Suggestions (${patch_suggestions.length})` },
        ].map((tab) => (
          <button
            key={tab.key}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.key}
            onClick={() => setActiveTab(tab.key as typeof activeTab)}
            className={`relative shrink-0 px-4 py-2.5 text-sm font-medium transition ${
              activeTab === tab.key ? "text-foreground font-semibold" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {tab.label}
            {activeTab === tab.key && (
              <span className="absolute inset-x-0 bottom-0 h-0.5 bg-foreground" aria-hidden="true" />
            )}
          </button>
        ))}
      </div>

      {/* Tab 1: Three-Column Consolidated Code Review */}
      {activeTab === "review" && (
        <div className="space-y-4">
          {rejectedFps.length > 0 && (
            <div className="rounded-xl border border-emerald-500/35 bg-emerald-500/10 p-3.5 text-xs">
              <p className="font-semibold text-emerald-800 dark:text-emerald-300">
                Adversarial Verifier filtered {rejectedFps.length} contradicted false positive(s) before final report:
              </p>
              <ul className="mt-1.5 list-inside list-disc space-y-0.5 text-emerald-900/90 dark:text-emerald-200/90">
                {rejectedFps.slice(0, 5).map((item, idx) => (
                  <li key={idx}>
                    <code>{item.title}</code> ({item.file_path || "repo"}) — {item.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="grid gap-4 lg:grid-cols-12">
            {/* Left Panel: Changed Files */}
            <aside
              aria-label="Changed files"
              className="flex flex-col rounded-xl border border-border bg-card p-3 lg:col-span-3"
            >
              <h2 className="mb-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Changed Files ({code_change.changed_files.length})
              </h2>
              <ul className="rb-scroll max-h-96 space-y-1">
                {code_change.changed_files.map((cf) => {
                  const count = findings.filter((f) => f.file_path === cf.path).length;
                  const isActive = cf.path === selectedFile;
                  return (
                    <li key={cf.path}>
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedFile(cf.path);
                          selectedFileRef.current = cf.path;
                          setHighlightedLine(null);
                        }}
                        className={`flex w-full items-center justify-between gap-2 rounded-lg px-2.5 py-2 text-left font-mono text-[11px] transition ${
                          isActive
                            ? "bg-primary font-semibold text-primary-foreground"
                            : "text-muted-foreground hover:bg-muted hover:text-foreground"
                        }`}
                      >
                        <span className="flex min-w-0 items-center gap-1.5">
                          <FileCode2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                          <span className="truncate">{cf.path}</span>
                        </span>
                        <span className="shrink-0">
                          +{cf.additions}/-{cf.deletions}
                          {count > 0 ? ` (${count})` : ""}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>

              {review.diff_summary && (
                <div className="mt-4 border-t border-border pt-3">
                  <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Diff Agent Summary
                  </h3>
                  <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">
                    {review.diff_summary}
                  </p>
                </div>
              )}
            </aside>

            {/* Center Panel: Monaco Code / Diff Viewer */}
            <section
              aria-label="Code diff and source viewer"
              className="flex min-w-0 flex-col overflow-hidden rounded-xl border border-border bg-card lg:col-span-5"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border bg-muted px-3 py-2">
                <span className="truncate font-mono text-xs font-semibold">
                  {selectedFile || "Unified Diff"}
                  {highlightedLine ? ` : line ${highlightedLine}` : ""}
                </span>
                <div className="flex gap-1">
                  <button
                    type="button"
                    disabled={!activeSnapshot}
                    onClick={() => setViewMode("source")}
                    className={`rounded px-2.5 py-1 font-mono text-[11px] font-medium ${
                      viewMode === "source" && activeSnapshot
                        ? "bg-primary text-primary-foreground"
                        : "border border-border bg-card text-muted-foreground"
                    } disabled:opacity-40`}
                  >
                    Source
                  </button>
                  <button
                    type="button"
                    onClick={() => setViewMode("patch")}
                    className={`rounded px-2.5 py-1 font-mono text-[11px] font-medium ${
                      viewMode === "patch" || !activeSnapshot
                        ? "bg-primary text-primary-foreground"
                        : "border border-border bg-card text-muted-foreground"
                    }`}
                  >
                    Diff Patch
                  </button>
                </div>
              </div>
              <div className="h-[34rem] w-full">
                <Editor
                  height="100%"
                  theme={resolved === "dark" ? "vs-dark" : "light"}
                  language={viewMode === "source" && activeSnapshot ? guessLanguage(selectedFile) : "diff"}
                  value={editorValue}
                  onMount={(editor) => {
                    editorRef.current = editor;
                  }}
                  options={{
                    readOnly: true,
                    minimap: { enabled: false },
                    fontSize: 12,
                    scrollBeyondLastLine: false,
                    wordWrap: "on",
                  }}
                />
              </div>
            </section>

            {/* Right Panel: Findings Inspector */}
            <section
              aria-label="Consolidated findings"
              className="flex flex-col rounded-xl border border-border bg-card p-3 lg:col-span-4"
            >
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <h2 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Findings ({filteredFindings.length})
                </h2>
                <select
                  aria-label="Filter findings by severity"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="rounded border border-border bg-muted px-2 py-1 font-mono text-xs"
                >
                  <option value="ALL">All Severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              {filteredFindings.length === 0 ? (
                <div className="rounded-lg border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
                  No findings match this filter.
                </div>
              ) : (
                <ul className="rb-scroll max-h-[32rem] space-y-2.5 pr-1">
                  {filteredFindings.map((f) => {
                    const hasPatch = patch_suggestions.some((p) => p.finding_id === f.id);
                    return (
                      <li key={f.id}>
                        <button
                          type="button"
                          onClick={() => jumpToFinding(f)}
                          className="w-full rounded-xl border border-border bg-muted/60 p-3 text-left transition hover:border-foreground/50"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-1.5">
                            <SeverityBadge severity={f.severity} />
                            <VerificationBadge status={f.verification_status} />
                          </div>
                          <p className="mt-2 text-sm font-semibold">{f.title}</p>
                          <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                            {f.file_path || "repository"}
                            {f.line_number ? `:${f.line_number}` : ""}
                          </p>
                          {f.evidence && (
                            <pre className="mt-2 overflow-x-auto rounded border border-border bg-background p-2 font-mono text-[11px]">
                              {f.evidence}
                            </pre>
                          )}
                          <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                            {f.recommendation}
                          </p>
                          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] text-muted-foreground">
                            <span>
                              Sources:{" "}
                              {(f.deduplicated_sources?.length
                                ? f.deduplicated_sources
                                : [f.agent]
                              ).join(", ")}
                            </span>
                            {hasPatch && (
                              <span
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setActiveTab("patches");
                                }}
                                className="inline-flex items-center gap-1 font-semibold text-foreground hover:underline"
                              >
                                <Wrench className="h-3 w-3" aria-hidden="true" />
                                View Fix Patch
                              </span>
                            )}
                          </div>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>
          </div>
        </div>
      )}

      {/* Tab 2: Live 6-Agent Orbs & Tool Outputs */}
      {activeTab === "agents" && (
        <div className="space-y-6">
          <AgentPipelineGraph
            agentRuns={liveRuns}
            liveMessages={liveMessages}
            reviewStatus={review.review_status}
          />

          <section className="rounded-xl border border-border bg-card p-5">
            <h2 className="mb-3 text-base font-semibold">Tool Telemetry</h2>
            <div className="grid gap-4 md:grid-cols-2">
              {detail.agent_runs.map((run) => (
                <div key={run.id} className="rounded-lg border border-border bg-muted/60 p-3">
                  <p className="font-mono text-xs font-semibold">{run.agent_label}</p>
                  <pre className="rb-scroll mt-2 max-h-56 font-mono text-[11px] text-muted-foreground">
                    {JSON.stringify(run.tool_results || {}, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          </section>
        </div>
      )}

      {/* Tab 3: Fix Suggestions (Monaco DiffEditor + Honest Verification Output) */}
      {activeTab === "patches" && (
        <div className="space-y-4">
          {patch_suggestions.length === 0 ? (
            <div className="rounded-xl border border-border bg-card p-8 text-center text-sm text-muted-foreground">
              No fix suggestions generated for this review.
            </div>
          ) : (
            patch_suggestions.map((patch) => (
              <article key={patch.id} className="space-y-4 rounded-xl border border-border bg-card p-5">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h2 className="text-base font-semibold">{patch.title}</h2>
                    <p className="font-mono text-xs text-muted-foreground">{patch.file_path}</p>
                    <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                      {patch.explanation}
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1 rounded px-2.5 py-1 font-mono text-[11px] font-semibold ${
                        patch.applicability_verified
                          ? "bg-emerald-500/12 text-emerald-700 dark:text-emerald-300"
                          : "bg-amber-500/12 text-amber-800 dark:text-amber-300"
                      }`}
                    >
                      <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                      {patch.validation_output ||
                        (patch.applicability_verified
                          ? "git apply --check + Syntax: Verified"
                          : "Needs verification")}
                    </span>
                    <span className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">
                      {patch.approval_status}
                    </span>
                  </div>
                </div>

                  <div className="h-80 overflow-hidden rounded-lg border border-border">
                    <DiffEditor
                      height="100%"
                      theme={resolved === "dark" ? "vs-dark" : "light"}
                      language={guessLanguage(patch.file_path)}
                      original={patch.original_code}
                      modified={patch.proposed_code}
                      options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12 }}
                    />
                  </div>

                  <div className="flex flex-wrap items-center justify-end gap-2">
                    <button
                      type="button"
                      disabled={busyAction}
                      onClick={() => handlePatchDecision(patch, "reject")}
                      className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-rose-700 hover:bg-rose-500/10 dark:text-rose-300"
                    >
                      <X className="h-3.5 w-3.5" aria-hidden="true" />
                      Reject
                    </button>
                    <button
                      type="button"
                      disabled={busyAction}
                      onClick={() => handlePatchDecision(patch, "approve")}
                      className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-semibold text-emerald-700 hover:bg-emerald-500/10 dark:text-emerald-300"
                    >
                      <Check className="h-3.5 w-3.5" aria-hidden="true" />
                      Approve Patch
                    </button>
                    {review.source_type === "local" && (
                      <button
                        type="button"
                        disabled={busyAction || !patch.applicability_verified}
                        onClick={() => handlePatchDecision(patch, "apply_local")}
                        className="inline-flex min-h-10 items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground disabled:opacity-50"
                      >
                        Approve &amp; Apply Locally
                      </button>
                    )}
                    {review.source_type === "github" && code_change.pr_number && (
                      <>
                        <button
                          type="button"
                          disabled={busyAction}
                          onClick={() => handlePatchDecision(patch, "publish_github_suggestion")}
                          className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-semibold hover:bg-muted"
                        >
                          Post PR Suggestion Comment
                        </button>
                        <button
                          type="button"
                          disabled={busyAction}
                          onClick={() => handlePatchDecision(patch, "commit_to_github_branch")}
                          className="inline-flex min-h-10 items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground"
                        >
                          Approve &amp; Commit to GitHub Branch
                        </button>
                      </>
                    )}
                  </div>
                </article>
            ))
          )}
        </div>
      )}
    </div>
  );
}
