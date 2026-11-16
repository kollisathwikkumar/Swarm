"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Github, Wrench } from "lucide-react";
import { apiFetch, commitAllPatchesToGithub } from "@/lib/api";
import { PatchCard } from "@/components/PatchCard";
import type { PatchSuggestionItem } from "@/lib/types";

export default function FixSuggestionsPage() {
  const [patches, setPatches] = useState<PatchSuggestionItem[]>([]);
  const [filter, setFilter] = useState("ALL");
  const [repoFilter, setRepoFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const q = filter !== "ALL" ? `?approval_status=${filter}` : "";
      const res = await apiFetch<{ patches: PatchSuggestionItem[] }>(`/api/patches${q}`);
      setPatches(res.patches);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed loading fix suggestions");
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (
    patch: PatchSuggestionItem,
    action: "approve" | "reject" | "apply_local" | "commit_to_github_branch"
  ) => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await apiFetch(`/api/patches/${patch.id}/decision`, {
        method: "POST",
        body: JSON.stringify({ action }),
      });
      setNotice(`Patch "${patch.title}" updated (${action.replace(/_/g, " ")}).`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  const repoNames = Array.from(new Set(patches.map((p) => p.repository_name).filter(Boolean)));

  const displayedPatches = patches.filter((p) => {
    if (repoFilter !== "ALL" && p.repository_name !== repoFilter) return false;
    return true;
  });

  const committableGithubPatches = displayedPatches.filter(
    (p) =>
      p.source_type === "github" &&
      p.applicability_verified &&
      (p.approval_status === "pending_approval" || p.approval_status === "approved")
  );

  const actAllGithub = async () => {
    if (committableGithubPatches.length === 0) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const { noticeMsg, errorMsg } = await commitAllPatchesToGithub({
        patch_ids: committableGithubPatches.map((p) => p.id),
      });
      if (noticeMsg) setNotice(noticeMsg);
      if (errorMsg) setError(errorMsg);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Batch commit to GitHub failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Fix Suggestions &amp; Resolution Paths</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            Sandbox-verified AST patches, step-by-step resolution paths for AI agents, and deterministic regression test proofs.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {committableGithubPatches.length > 0 && (
            <button
              type="button"
              disabled={busy}
              onClick={actAllGithub}
              className="inline-flex min-h-10 items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              <Github className="h-3.5 w-3.5" aria-hidden="true" />
              Approve &amp; Commit All to GitHub ({committableGithubPatches.length})
            </button>
          )}

          {repoNames.length > 1 && (
            <select
              aria-label="Filter fix suggestions by repository"
              value={repoFilter}
              onChange={(e) => setRepoFilter(e.target.value)}
              className="min-h-10 rounded-lg border border-border bg-card px-3 py-1.5 font-mono text-xs"
            >
              <option value="ALL">All Repositories ({repoNames.length})</option>
              {repoNames.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          )}

          <select
            aria-label="Filter fix suggestions by status"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="min-h-10 rounded-lg border border-border bg-card px-3 py-1.5 font-mono text-xs"
          >
            <option value="ALL">All Statuses ({displayedPatches.length})</option>
            <option value="pending_approval">Pending Approval</option>
            <option value="approved">Approved</option>
            <option value="applied">Applied</option>
            <option value="rejected">Rejected</option>
          </select>
        </div>
      </header>

      {notice && (
        <div
          aria-live="polite"
          role="status"
          className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-700 dark:text-emerald-300"
        >
          {notice}
        </div>
      )}
      {error && (
        <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300">
          {error}
        </div>
      )}

      {loading ? (
        <p className="font-mono text-xs text-muted-foreground">Loading verified patch suggestions...</p>
      ) : displayedPatches.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border bg-card p-10 text-center">
          <Wrench className="mx-auto mb-2 h-6 w-6 text-muted-foreground" aria-hidden="true" />
          <p className="text-sm font-medium">No fix suggestions match your filter</p>
          <p className="mt-1 text-xs text-muted-foreground">
            Try switching repositories or resetting the status filter.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {displayedPatches.map((patch) => (
            <PatchCard
              key={patch.id}
              patch={patch}
              busy={busy}
              onDecision={act}
              showReviewLink={true}
            />
          ))}
        </div>
      )}
    </div>
  );
}
