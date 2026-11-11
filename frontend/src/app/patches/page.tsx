"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { DiffEditor } from "@monaco-editor/react";
import { Check, Github, ShieldCheck, Wrench, X } from "lucide-react";
import { apiFetch, commitAllPatchesToGithub } from "@/lib/api";
import { useResolvedTheme } from "@/lib/theme";
import type { PatchSuggestionItem } from "@/lib/types";

export default function FixSuggestionsPage() {
  const { resolved } = useResolvedTheme();
  const [patches, setPatches] = useState<PatchSuggestionItem[]>([]);
  const [filter, setFilter] = useState("ALL");
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
      setNotice(`Patch "${patch.title}" updated (${action}).`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  const committableGithubPatches = patches.filter(
    (p) =>
      p.source_type === "github" &&
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
        <h1 className="text-2xl font-semibold tracking-tight">Fix Suggestions</h1>
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
          <select
            aria-label="Filter fix suggestions by status"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="min-h-10 rounded-lg border border-border bg-card px-3 py-1.5 font-mono text-xs"
          >
            <option value="ALL">All Statuses</option>
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
        <p className="font-mono text-xs text-muted-foreground">Loading patches...</p>
      ) : patches.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border bg-card p-10 text-center">
          <Wrench className="mx-auto mb-2 h-6 w-6 text-muted-foreground" aria-hidden="true" />
          <p className="text-sm font-medium">No fix suggestions available yet</p>
          <p className="mt-1 text-xs text-muted-foreground">
            When the Fix-Suggestion Agent proposes syntax-verified patches for actionable findings, they appear here.
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          {patches.map((patch) => (
            <article key={patch.id} className="space-y-4 rounded-xl border border-border bg-card p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-base font-semibold">{patch.title}</h2>
                    <span className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">
                      {patch.approval_status}
                    </span>
                  </div>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">
                      {patch.repository_name} · {patch.file_path}
                    </p>
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
                        (patch.applicability_verified ? "Patch Validated" : "Needs Manual Check")}
                    </span>
                    <Link href={`/reviews/${patch.review_id}`} className="font-mono text-xs font-semibold hover:underline">
                      View Review →
                    </Link>
                  </div>
                </div>

                <div className="h-72 overflow-hidden rounded-lg border border-border">
                  <DiffEditor
                    height="100%"
                    theme={resolved === "dark" ? "vs-dark" : "light"}
                    language={patch.file_path.endsWith(".py") ? "python" : "typescript"}
                    original={patch.original_code}
                    modified={patch.proposed_code}
                    options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12 }}
                  />
                </div>

                <div className="flex flex-wrap justify-end gap-2">
                  <button
                    type="button"
                    disabled={busy || patch.approval_status === "applied"}
                    onClick={() => act(patch, "reject")}
                    className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-rose-700 hover:bg-rose-500/10 disabled:opacity-50 dark:text-rose-300"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                    Reject
                  </button>
                  <button
                    type="button"
                    disabled={busy || patch.approval_status === "approved" || patch.approval_status === "applied"}
                    onClick={() => act(patch, "approve")}
                    className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-semibold text-emerald-700 hover:bg-emerald-500/10 disabled:opacity-50 dark:text-emerald-300"
                  >
                    <Check className="h-3.5 w-3.5" aria-hidden="true" />
                    Approve
                  </button>
                  {patch.source_type === "local" && (
                    <button
                      type="button"
                      disabled={busy || !patch.applicability_verified || patch.approval_status === "applied"}
                      onClick={() => act(patch, "apply_local")}
                      className="inline-flex min-h-10 items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground disabled:opacity-50"
                    >
                      {patch.approval_status === "applied" ? "Applied Locally" : "Approve & Apply Locally"}
                    </button>
                  )}
                  {patch.source_type === "github" && (
                    <button
                      type="button"
                      disabled={busy || patch.approval_status === "applied" || patch.approval_status === "rejected"}
                      onClick={() => act(patch, "commit_to_github_branch")}
                      className="inline-flex min-h-10 items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground disabled:opacity-50"
                    >
                      {patch.approval_status === "applied" ? "Committed to GitHub" : "Approve & Commit to GitHub"}
                    </button>
                  )}
                </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
