"use client";

import React, { Suspense, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { GitPullRequest, Play, RefreshCw, Square } from "lucide-react";
import { apiFetch, connectResilientWebSocket } from "@/lib/api";
import type { ChangedFileItem, RepositoryItem, ReviewSummaryItem } from "@/lib/types";

interface PullRequestOption {
  number: number;
  title: string;
  author: string;
  base_branch: string;
  head_branch: string;
  base_commit: string;
  head_commit: string;
}

interface BranchOption {
  name: string;
  commit_sha: string;
}

interface CommitOption {
  sha: string;
  message: string;
  author: string;
  date?: string | null;
}

function SubmitReviewContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const preselectedRepo = searchParams.get("repo") || "";
  const preselectedPr = searchParams.get("pr") || "";
  const preselectedCommit = searchParams.get("commit") || "";

  const [repos, setRepos] = useState<RepositoryItem[]>([]);
  const [selectedRepoId, setSelectedRepoId] = useState(preselectedRepo);
  const [githubMode, setGithubMode] = useState<"pr" | "commit" | "compare">(
    preselectedCommit ? "commit" : "pr"
  );
  const [localMode, setLocalMode] = useState<"working_tree" | "staged" | "unstaged" | "commits">(
    "working_tree"
  );

  const [pulls, setPulls] = useState<PullRequestOption[]>([]);
  const [branches, setBranches] = useState<BranchOption[]>([]);
  const [commits, setCommits] = useState<CommitOption[]>([]);
  const [selectedPr, setSelectedPr] = useState<string>(preselectedPr);
  const [selectedCommitSha, setSelectedCommitSha] = useState<string>(preselectedCommit);
  const [baseRef, setBaseRef] = useState("");
  const [targetRef, setTargetRef] = useState("");

  const [previewDiff, setPreviewDiff] = useState("");
  const [previewFiles, setPreviewFiles] = useState<ChangedFileItem[]>([]);
  const [previewCommits, setPreviewCommits] = useState<{ base: string; target: string }>({
    base: "",
    target: "",
  });

  const [activeReviews, setActiveReviews] = useState<ReviewSummaryItem[]>([]);
  const [loadingContext, setLoadingContext] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [statusNotice, setStatusNotice] = useState("");
  const [error, setError] = useState("");

  const opAbortRef = useRef<AbortController | null>(null);
  const launchedReviewIdRef = useRef<string | null>(null);

  const loadActiveReviews = useCallback(async () => {
    try {
      const res = await apiFetch<{ reviews: ReviewSummaryItem[] }>("/api/reviews");
      setActiveReviews(
        res.reviews.filter(
          (r) => r.review_status === "running" || r.review_status === "queued"
        )
      );
    } catch {
      // ignore background poll errors
    }
  }, []);

  useEffect(() => {
    void apiFetch<{ repositories: RepositoryItem[] }>("/api/repositories").then((res) => {
      setRepos(res.repositories);
      if (res.repositories.length > 0) {
        setSelectedRepoId((cur) => cur || res.repositories[0].id);
      }
    });
  }, []);

  useEffect(() => {
    void loadActiveReviews();
    return connectResilientWebSocket("/ws/activity", {
      onMessage: (evt) => {
        try {
          const msg = JSON.parse(evt.data) as { event_type?: string };
          if (
            msg.event_type === "review_started" ||
            msg.event_type === "review_completed" ||
            msg.event_type === "review_stopped" ||
            msg.event_type === "review_failed"
          ) {
            void loadActiveReviews();
          }
        } catch {
          // ignore non-json ping
        }
      },
    });
  }, [loadActiveReviews]);

  useEffect(() => {
    if (activeReviews.length === 0) return;
    const timer = setInterval(() => {
      void loadActiveReviews();
    }, 2500);
    return () => clearInterval(timer);
  }, [activeReviews.length, loadActiveReviews]);

  const selectedRepo = repos.find((r) => r.id === selectedRepoId) || null;

  useEffect(() => {
    if (!selectedRepo) return;
    setError("");
    setPreviewDiff("");
    setPreviewFiles([]);
    const ac = new AbortController();

    async function loadRepoRefs() {
      setLoadingContext(true);
      try {
        if (selectedRepo!.source_type === "github") {
          const [prRes, brRes, cmRes] = await Promise.all([
            apiFetch<{ pulls: PullRequestOption[] }>(`/api/github/repos/${selectedRepo!.id}/pulls`, {
              signal: ac.signal,
            }),
            apiFetch<{ branches: BranchOption[] }>(`/api/github/repos/${selectedRepo!.id}/branches`, {
              signal: ac.signal,
            }),
            apiFetch<{ commits: CommitOption[] }>(`/api/github/repos/${selectedRepo!.id}/commits`, {
              signal: ac.signal,
            }),
          ]);
          setPulls(prRes.pulls);
          setBranches(brRes.branches);
          setCommits(cmRes.commits);

          if (preselectedPr) {
            setSelectedPr(preselectedPr);
            setGithubMode("pr");
          } else if (preselectedCommit) {
            setSelectedCommitSha(preselectedCommit);
            setGithubMode("commit");
          } else if (prRes.pulls.length > 0) {
            setSelectedPr(String(prRes.pulls[0].number));
            setGithubMode("pr");
          } else if (cmRes.commits.length > 0) {
            setSelectedCommitSha(cmRes.commits[0].sha);
            setGithubMode("commit");
          } else {
            setGithubMode("compare");
          }

          if (cmRes.commits.length > 0 && !selectedCommitSha) {
            setSelectedCommitSha(cmRes.commits[0].sha);
          }
          if (brRes.branches.length > 0) {
            setBaseRef(selectedRepo!.default_branch || brRes.branches[0].name);
            setTargetRef(brRes.branches[Math.min(1, brRes.branches.length - 1)].name);
          }
        } else {
          const insp = await apiFetch<{
            branches: string[];
            base_commit: string;
            target_commit: string;
            diff_text: string;
            changed_files: ChangedFileItem[];
          }>(`/api/repositories/${selectedRepo!.id}/local-inspect?mode=${localMode}`, {
            signal: ac.signal,
          });
          setBranches(insp.branches.map((b) => ({ name: b, commit_sha: "" })));
          setPreviewDiff(insp.diff_text);
          setPreviewFiles(insp.changed_files);
          setPreviewCommits({ base: insp.base_commit, target: insp.target_commit });
          if (localMode === "commits") {
            setBaseRef("HEAD~1");
            setTargetRef("HEAD");
          }
        }
      } catch (err) {
        if ((err as { name?: string })?.name === "AbortError") return;
        setError(err instanceof Error ? err.message : "Failed inspecting repository");
      } finally {
        setLoadingContext(false);
      }
    }
    void loadRepoRefs();
    return () => ac.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedRepo, localMode, preselectedPr, preselectedCommit]);

  const loadPreview = async () => {
    if (!selectedRepo) return;
    opAbortRef.current?.abort();
    const ac = new AbortController();
    opAbortRef.current = ac;
    setLoadingContext(true);
    setError("");
    setStatusNotice("");
    try {
      if (selectedRepo.source_type === "github") {
        if (githubMode === "pr" && selectedPr) {
          const res = await apiFetch<{
            base_commit: string;
            target_commit: string;
            diff_text: string;
            changed_files: ChangedFileItem[];
          }>(`/api/github/repos/${selectedRepo.id}/pulls/${selectedPr}/diff`, {
            signal: ac.signal,
          });
          setPreviewDiff(res.diff_text);
          setPreviewFiles(res.changed_files);
          setPreviewCommits({ base: res.base_commit, target: res.target_commit });
        } else if (githubMode === "commit" && selectedCommitSha) {
          const res = await apiFetch<{
            base_commit: string;
            target_commit: string;
            diff_text: string;
            changed_files: ChangedFileItem[];
          }>(`/api/github/repos/${selectedRepo.id}/commits/${selectedCommitSha}/diff`, {
            signal: ac.signal,
          });
          setPreviewDiff(res.diff_text);
          setPreviewFiles(res.changed_files);
          setPreviewCommits({ base: res.base_commit, target: res.target_commit });
        } else if (baseRef && targetRef) {
          const res = await apiFetch<{
            base_commit: string;
            target_commit: string;
            diff_text: string;
            changed_files: ChangedFileItem[];
          }>(
            `/api/github/repos/${selectedRepo.id}/compare?base=${encodeURIComponent(
              baseRef
            )}&head=${encodeURIComponent(targetRef)}`,
            { signal: ac.signal }
          );
          setPreviewDiff(res.diff_text);
          setPreviewFiles(res.changed_files);
          setPreviewCommits({ base: res.base_commit, target: res.target_commit });
        }
      } else {
        const q = new URLSearchParams({ mode: localMode });
        if (localMode === "commits") {
          q.set("base_ref", baseRef || "HEAD~1");
          q.set("target_ref", targetRef || "HEAD");
        }
        const res = await apiFetch<{
          base_commit: string;
          target_commit: string;
          diff_text: string;
          changed_files: ChangedFileItem[];
        }>(`/api/repositories/${selectedRepo.id}/local-inspect?${q.toString()}`, {
          signal: ac.signal,
        });
        setPreviewDiff(res.diff_text);
        setPreviewFiles(res.changed_files);
        setPreviewCommits({ base: res.base_commit, target: res.target_commit });
      }
    } catch (err) {
      if ((err as { name?: string })?.name === "AbortError") {
        setStatusNotice("Diff preview operation stopped.");
        return;
      }
      setError(err instanceof Error ? err.message : "Failed loading diff preview");
    } finally {
      setLoadingContext(false);
    }
  };

  const handleSubmitReview = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedRepo) return;
    opAbortRef.current?.abort();
    const ac = new AbortController();
    opAbortRef.current = ac;
    launchedReviewIdRef.current = null;
    setSubmitting(true);
    setError("");
    setStatusNotice("");
    try {
      const body: Record<string, unknown> = { repository_id: selectedRepo.id };
      if (selectedRepo.source_type === "github") {
        if (githubMode === "pr") {
          if (!selectedPr) throw new Error("Select a Pull Request first");
          body.pr_number = Number(selectedPr);
        } else if (githubMode === "commit") {
          if (!selectedCommitSha) throw new Error("Select or paste a Commit SHA first");
          body.commit_sha = selectedCommitSha;
        } else {
          body.base_ref = baseRef;
          body.target_ref = targetRef;
        }
      } else {
        body.local_mode = localMode;
        if (localMode === "commits") {
          body.base_ref = baseRef || "HEAD~1";
          body.target_ref = targetRef || "HEAD";
        }
      }

      const res = await apiFetch<{ review_id: string }>("/api/reviews", {
        method: "POST",
        body: JSON.stringify(body),
        signal: ac.signal,
      });
      launchedReviewIdRef.current = res.review_id;
      if (ac.signal.aborted) {
        await apiFetch(`/api/reviews/${res.review_id}/stop`, { method: "POST" }).catch(() => undefined);
        return;
      }
      router.push(`/reviews/${res.review_id}`);
    } catch (err) {
      if ((err as { name?: string })?.name === "AbortError") {
        setStatusNotice("Operation stopped — no tokens consumed.");
        setSubmitting(false);
        return;
      }
      setError(err instanceof Error ? err.message : "Failed submitting review");
      setSubmitting(false);
    }
  };

  const handleStopOperation = async (targetReviewId?: string) => {
    setStopping(true);
    setError("");
    setStatusNotice("");
    opAbortRef.current?.abort();
    setLoadingContext(false);
    setSubmitting(false);

    const rid = targetReviewId || launchedReviewIdRef.current || activeReviews[0]?.id;
    try {
      if (rid) {
        await apiFetch(`/api/reviews/${rid}/stop`, { method: "POST" });
        setStatusNotice("Operation stopped — remaining LLM calls aborted.");
        await loadActiveReviews();
      } else {
        setStatusNotice("Operation stopped.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed stopping operation");
    } finally {
      setStopping(false);
    }
  };

  const hasOperationRunning = loadingContext || submitting || activeReviews.length > 0;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <h1 className="text-2xl font-semibold tracking-tight">Submit Review</h1>
        {hasOperationRunning && (
          <button
            type="button"
            disabled={stopping}
            onClick={() => void handleStopOperation()}
            className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/12 px-3 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-500/20 disabled:opacity-50 dark:text-rose-300"
          >
            <Square className="h-3.5 w-3.5" aria-hidden="true" />
            {stopping ? "Stopping..." : "Stop Operation"}
          </button>
        )}
      </header>

      {statusNotice && (
        <div
          aria-live="polite"
          role="status"
          className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-800 dark:text-amber-300"
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

      <form onSubmit={handleSubmitReview} className="space-y-5 rounded-xl border border-border bg-card p-5">
        <div>
          <label
            htmlFor="repo-select"
            className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-muted-foreground"
          >
            Repository
          </label>
          <select
            id="repo-select"
            value={selectedRepoId}
            onChange={(e) => setSelectedRepoId(e.target.value)}
            className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 text-sm"
          >
            {repos.length === 0 && <option value="">No repositories connected</option>}
            {repos.map((r) => (
              <option key={r.id} value={r.id}>
                {r.full_name} ({r.source_type.toUpperCase()})
              </option>
            ))}
          </select>
        </div>

        {selectedRepo?.source_type === "github" && (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {[
                { key: "pr", label: `Pull Request (${pulls.length} open)` },
                { key: "commit", label: `Specific Commit (${commits.length})` },
                { key: "compare", label: "Compare Branches / Commits" },
              ].map((m) => (
                <button
                  key={m.key}
                  type="button"
                  onClick={() => setGithubMode(m.key as typeof githubMode)}
                  className={`rounded-lg px-3.5 py-2 font-mono text-xs font-semibold transition ${
                    githubMode === m.key
                      ? "bg-primary text-primary-foreground"
                      : "border border-border bg-muted text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>

            {githubMode === "pr" ? (
              <div>
                <label htmlFor="pr-select" className="mb-1.5 block text-xs font-semibold">
                  Open Pull Request
                </label>
                <select
                  id="pr-select"
                  value={selectedPr}
                  onChange={(e) => setSelectedPr(e.target.value)}
                  className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 text-sm"
                >
                  {pulls.length === 0 && <option value="">No open Pull Requests found</option>}
                  {pulls.map((pr) => (
                    <option key={pr.number} value={pr.number}>
                      #{pr.number} — {pr.title} ({pr.head_branch} → {pr.base_branch})
                    </option>
                  ))}
                </select>
              </div>
            ) : githubMode === "commit" ? (
              <div>
                <label htmlFor="commit-select" className="mb-1.5 block text-xs font-semibold">
                  Commit to Review
                </label>
                <select
                  id="commit-select"
                  value={selectedCommitSha}
                  onChange={(e) => setSelectedCommitSha(e.target.value)}
                  className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-xs"
                >
                  {commits.length === 0 && <option value="">No commits loaded</option>}
                  {commits.map((c) => (
                    <option key={c.sha} value={c.sha}>
                      {c.sha.slice(0, 10)} — {c.message} ({c.author})
                    </option>
                  ))}
                </select>
              </div>
            ) : (
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <label htmlFor="base-ref" className="mb-1.5 block text-xs font-semibold">
                    Base Branch / Commit SHA
                  </label>
                  <input
                    id="base-ref"
                    list="branch-list"
                    value={baseRef}
                    onChange={(e) => setBaseRef(e.target.value)}
                    className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-sm"
                  />
                </div>
                <div>
                  <label htmlFor="target-ref" className="mb-1.5 block text-xs font-semibold">
                    Target Branch / Commit SHA
                  </label>
                  <input
                    id="target-ref"
                    list="branch-list"
                    value={targetRef}
                    onChange={(e) => setTargetRef(e.target.value)}
                    className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-sm"
                  />
                </div>
                <datalist id="branch-list">
                  {branches.map((b) => (
                    <option key={b.name} value={b.name} />
                  ))}
                </datalist>
              </div>
            )}
          </div>
        )}

        {selectedRepo?.source_type === "local" && (
          <div className="space-y-4">
            <div>
              <label htmlFor="local-mode" className="mb-1.5 block text-xs font-semibold">
                Local Change Source
              </label>
              <select
                id="local-mode"
                value={localMode}
                onChange={(e) => setLocalMode(e.target.value as typeof localMode)}
                className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 text-sm"
              >
                <option value="working_tree">All Uncommitted Changes (Staged + Unstaged + Untracked)</option>
                <option value="staged">Staged Changes Only (git diff --cached)</option>
                <option value="unstaged">Unstaged Changes Only (git diff)</option>
                <option value="commits">Commit / Branch Range (base..target)</option>
              </select>
            </div>
            {localMode === "commits" && (
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <label htmlFor="local-base" className="mb-1.5 block text-xs font-semibold">
                    Base Ref
                  </label>
                  <input
                    id="local-base"
                    value={baseRef}
                    onChange={(e) => setBaseRef(e.target.value)}
                    placeholder="HEAD~1"
                    className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-sm"
                  />
                </div>
                <div>
                  <label htmlFor="local-target" className="mb-1.5 block text-xs font-semibold">
                    Target Ref
                  </label>
                  <input
                    id="local-target"
                    value={targetRef}
                    onChange={(e) => setTargetRef(e.target.value)}
                    placeholder="HEAD"
                    className="min-h-11 w-full rounded-lg border border-border bg-muted px-3 py-2 font-mono text-sm"
                  />
                </div>
              </div>
            )}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={loadPreview}
            disabled={!selectedRepo || loadingContext}
            className="inline-flex min-h-11 items-center gap-2 rounded-lg border border-border bg-muted px-4 py-2 text-xs font-medium hover:border-foreground/40"
          >
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            {loadingContext ? "Loading Diff..." : "Preview Diff"}
          </button>
          <button
            type="submit"
            disabled={!selectedRepo || submitting}
            className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-primary px-5 py-2 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            <Play className="h-4 w-4" aria-hidden="true" />
            {submitting ? "Launching Review..." : "Run Multi-Agent Review"}
          </button>
          {(loadingContext || submitting) && (
            <button
              type="button"
              disabled={stopping}
              onClick={() => void handleStopOperation()}
              className="inline-flex min-h-11 items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/12 px-4 py-2 text-xs font-semibold text-rose-700 hover:bg-rose-500/20 disabled:opacity-50 dark:text-rose-300"
            >
              <Square className="h-3.5 w-3.5" aria-hidden="true" />
              Stop Operation
            </button>
          )}
        </div>
      </form>

      {activeReviews.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-4">
          <p className="mb-2.5 font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            Active Reviews ({activeReviews.length})
          </p>
          <ul className="space-y-2">
            {activeReviews.map((rev) => (
              <li
                key={rev.id}
                className="flex flex-wrap items-center justify-between gap-3 border-b border-border/60 py-2 last:border-b-0"
              >
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-semibold">{rev.repository_name}</span>
                  <span className="font-mono text-muted-foreground">
                    ({rev.pr_number ? `PR #${rev.pr_number}` : rev.target_commit.slice(0, 8)})
                  </span>
                  <span className="font-mono text-[11px] text-sky-600 dark:text-sky-400">
                    {rev.review_status}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Link
                    href={`/reviews/${rev.id}`}
                    className="font-mono text-xs font-semibold hover:underline"
                  >
                    Open →
                  </Link>
                  <button
                    type="button"
                    disabled={stopping}
                    onClick={() => void handleStopOperation(rev.id)}
                    className="inline-flex min-h-8 items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/12 px-3 py-1 text-xs font-semibold text-rose-700 hover:bg-rose-500/20 disabled:opacity-50 dark:text-rose-300"
                  >
                    <Square className="h-3 w-3" aria-hidden="true" />
                    Stop Operation
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {previewFiles.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <GitPullRequest className="h-4 w-4" aria-hidden="true" />
              Diff Preview ({previewFiles.length} file(s))
            </h2>
            {previewCommits.base && (
              <span className="font-mono text-xs text-muted-foreground">
                {previewCommits.base.slice(0, 10)} → {previewCommits.target.slice(0, 10)}
              </span>
            )}
          </div>
          <pre className="rb-scroll max-h-96 rounded-lg border border-border bg-background p-3 font-mono text-xs">
            {previewDiff}
          </pre>
        </section>
      )}
    </div>
  );
}

export default function SubmitReviewPage() {
  return (
    <Suspense fallback={<div className="p-4 font-mono text-xs text-muted-foreground">Loading...</div>}>
      <SubmitReviewContent />
    </Suspense>
  );
}
