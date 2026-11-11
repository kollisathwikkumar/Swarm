"use client";

import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { History } from "lucide-react";
import { apiFetch } from "@/lib/api";
import type { ReviewSummaryItem } from "@/lib/types";
import { RecommendationBadge } from "@/components/StatusBadges";

export default function ReviewHistoryPage() {
  const [reviews, setReviews] = useState<ReviewSummaryItem[]>([]);
  const [recFilter, setRecFilter] = useState("ALL");
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void apiFetch<{ reviews: ReviewSummaryItem[] }>("/api/reviews")
      .then((res) => setReviews(res.reviews))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    return reviews.filter((r) => {
      if (recFilter !== "ALL" && r.recommendation !== recFilter) return false;
      if (!q) return true;
      return (
        r.repository_name.toLowerCase().includes(q) ||
        r.target_commit.toLowerCase().includes(q) ||
        (r.pr_title || "").toLowerCase().includes(q) ||
        r.triggered_by.toLowerCase().includes(q)
      );
    });
  }, [reviews, recFilter, searchTerm]);

  return (
    <div className="space-y-6">
      <header className="border-b border-border pb-4">
        <h1 className="text-2xl font-semibold tracking-tight">Review History</h1>
      </header>

      <search>
        <form
            onSubmit={(e) => e.preventDefault()}
            className="flex flex-wrap items-end gap-3 rounded-xl border border-border bg-card p-4"
          >
            <div className="min-w-60 flex-1">
              <label htmlFor="history-search" className="mb-1 block font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                Search repository, PR title, or commit SHA
              </label>
              <input
                id="history-search"
                type="search"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="e.g. TraceMindXSwitch or commit SHA..."
                className="min-h-10 w-full rounded-lg border border-border bg-muted px-3 py-1.5 font-mono text-xs"
              />
            </div>
            <div>
              <label htmlFor="history-rec-filter" className="mb-1 block font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                Recommendation
              </label>
              <select
                id="history-rec-filter"
                value={recFilter}
                onChange={(e) => setRecFilter(e.target.value)}
                className="min-h-10 rounded-lg border border-border bg-muted px-3 py-1.5 text-xs font-medium"
              >
                <option value="ALL">All Decisions</option>
                <option value="Approve">Approve</option>
                <option value="Request Changes">Request Changes</option>
                <option value="Incomplete">Incomplete</option>
                <option value="Pending">Pending</option>
              </select>
            </div>
          </form>
        </search>

      <section className="rounded-xl border border-border bg-card p-5">
          {loading ? (
            <p className="font-mono text-xs text-muted-foreground">Loading review history...</p>
          ) : filtered.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border p-10 text-center">
              <History className="mx-auto mb-2 h-6 w-6 text-muted-foreground" aria-hidden="true" />
              <p className="text-sm font-medium">No matching reviews found</p>
            </div>
          ) : (
            <div tabIndex={0} role="region" aria-labelledby="history-cap" className="table-wrapper">
              <table className="rb-table rb-table--responsive text-left text-sm">
                <caption id="history-cap" className="visually-hidden">
                  Historical code reviews
                </caption>
                <thead>
                  <tr className="border-b border-border font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                    <th scope="col" className="px-3 py-2">Repository</th>
                    <th scope="col" className="px-3 py-2">Commits / PR</th>
                    <th scope="col" className="px-3 py-2">Trigger</th>
                    <th scope="col" className="px-3 py-2">Recommendation</th>
                    <th scope="col" className="px-3 py-2">Findings</th>
                    <th scope="col" className="px-3 py-2">GitHub Sync</th>
                    <th scope="col" className="px-3 py-2">Started</th>
                    <th scope="col" className="px-3 py-2">Report</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((rev) => (
                    <tr key={rev.id} className="border-b border-border last:border-b-0">
                      <th scope="row" className="px-3 py-3 font-medium">
                        {rev.repository_name}
                      </th>
                      <td data-label="Commits / PR" className="px-3 py-3 font-mono text-xs">
                        {rev.pr_number ? `PR #${rev.pr_number} · ` : ""}
                        {rev.base_commit.slice(0, 8)} → {rev.target_commit.slice(0, 8)}
                      </td>
                      <td data-label="Trigger" className="px-3 py-3 font-mono text-[11px] text-muted-foreground">
                        {rev.triggered_by}
                      </td>
                      <td data-label="Recommendation" className="px-3 py-3">
                        <RecommendationBadge recommendation={rev.recommendation} />
                      </td>
                      <td data-label="Findings" className="px-3 py-3 font-mono text-xs">
                        {rev.findings_count ?? 0}
                      </td>
                      <td data-label="GitHub Sync" className="px-3 py-3 font-mono text-xs text-muted-foreground">
                        {rev.github_published_at ? "Published" : rev.source_type === "github" ? "Not published" : "Local"}
                      </td>
                      <td data-label="Started" className="px-3 py-3 text-xs text-muted-foreground">
                        {rev.started_at ? new Date(rev.started_at).toLocaleString() : "—"}
                      </td>
                      <td data-label="Report" className="px-3 py-3">
                        <Link href={`/reviews/${rev.id}`} className="font-mono text-xs font-semibold hover:underline">
                          Inspect →
                        </Link>
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
