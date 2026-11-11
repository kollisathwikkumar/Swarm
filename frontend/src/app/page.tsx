"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowRight,
  FolderGit2,
  GitPullRequest,
  KeyRound,
  Sparkles,
} from "lucide-react";
import { apiFetch } from "@/lib/api";
import type {
  AgentLLMConfigItem,
  AnalyticsSummary,
  RepositoryItem,
  ReviewSummaryItem,
} from "@/lib/types";
import { RecommendationBadge } from "@/components/StatusBadges";
import { LiveOrb } from "@/components/ui/live-orb";
import { AGENT_ORB_PALETTES } from "@/components/AgentPipelineGraph";

export default function DashboardPage() {
  const [analytics, setAnalytics] = useState<AnalyticsSummary | null>(null);
  const [reviews, setReviews] = useState<ReviewSummaryItem[]>([]);
  const [repos, setRepos] = useState<RepositoryItem[]>([]);
  const [llmConfigs, setLlmConfigs] = useState<AgentLLMConfigItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [anRes, revRes, repoRes, llmRes] = await Promise.all([
          apiFetch<AnalyticsSummary>("/api/analytics/summary"),
          apiFetch<{ reviews: ReviewSummaryItem[] }>("/api/reviews"),
          apiFetch<{ repositories: RepositoryItem[] }>("/api/repositories"),
          apiFetch<{ agents: AgentLLMConfigItem[] }>("/api/settings/llm-agents"),
        ]);
        if (!active) return;
        setAnalytics(anRes);
        setReviews(revRes.reviews);
        setRepos(repoRes.repositories);
        setLlmConfigs(llmRes.agents);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Failed loading dashboard");
      } finally {
        if (active) setLoading(false);
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, []);

  const configuredKeysCount = llmConfigs.filter((a) => a.has_api_key).length;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <div className="flex flex-wrap gap-2">
          <Link
            href="/repositories"
            className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-border bg-card px-3.5 py-2 text-xs font-medium hover:border-foreground/40"
          >
            <FolderGit2 className="h-4 w-4" aria-hidden="true" />
            Repositories
          </Link>
          <Link
            href="/reviews/submit"
            className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground hover:opacity-90"
          >
            <GitPullRequest className="h-4 w-4" aria-hidden="true" />
            Submit Review
          </Link>
        </div>
      </header>

      {error && (
        <div
          role="alert"
          className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-700 dark:text-rose-300"
        >
          {error}
        </div>
      )}

      {!loading && (configuredKeysCount < 6 || repos.length === 0) && (
        <section
          aria-label="Setup checklist"
          className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1 text-xs">
              <p className="flex items-center gap-2 text-sm font-semibold text-amber-800 dark:text-amber-300">
                <AlertTriangle className="h-4 w-4" aria-hidden="true" />
                Setup Required
              </p>
              {configuredKeysCount < 6 && (
                <p>
                  {configuredKeysCount}/6 agents have API keys configured in{" "}
                  <Link href="/settings" className="underline">
                    Settings
                  </Link>
                  .
                </p>
              )}
              {repos.length === 0 && (
                <p>
                  No repositories connected yet.{" "}
                  <Link href="/repositories" className="underline">
                    Connect a repository
                  </Link>
                  .
                </p>
              )}
            </div>
            <Link
              href={configuredKeysCount < 6 ? "/settings" : "/repositories"}
              className="inline-flex min-h-10 items-center gap-1.5 rounded-lg bg-amber-500 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-amber-400"
            >
              <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
              {configuredKeysCount < 6 ? "Add Keys" : "Connect Repo"}
            </Link>
          </div>
        </section>
      )}

      {/* KPI Summary */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-border bg-card p-5">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            Repositories
          </p>
          <p className="mt-2 text-3xl font-semibold tracking-tight">
            {analytics?.totals.repositories ?? 0}
          </p>
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            Reviews
          </p>
          <p className="mt-2 text-3xl font-semibold tracking-tight">
            {analytics?.totals.reviews ?? 0}
          </p>
          <p className="mt-1 font-mono text-[11px] text-muted-foreground">
            {analytics?.totals.approved_reviews ?? 0} Approve ·{" "}
            {analytics?.totals.request_changes_reviews ?? 0} Changes Req.
          </p>
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            Findings
          </p>
          <p className="mt-2 text-3xl font-semibold tracking-tight">
            {analytics?.totals.findings ?? 0}
          </p>
          <p className="mt-1 font-mono text-[11px] text-muted-foreground">
            {analytics?.severity_breakdown?.Critical ?? 0} Critical ·{" "}
            {analytics?.severity_breakdown?.High ?? 0} High
          </p>
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            API Keys
          </p>
          <p className="mt-2 text-3xl font-semibold tracking-tight">{configuredKeysCount} / 6</p>
          <p className="mt-1 font-mono text-[11px] text-muted-foreground">
            {analytics?.totals.patches ?? 0} Patches
          </p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Recent Reviews */}
        <section className="rounded-xl border border-border bg-card p-5 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-base font-semibold">Recent Reviews</h2>
            <Link
              href="/history"
              className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground hover:underline"
            >
              View all <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
          </div>

          {reviews.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border p-8 text-center">
              <Sparkles className="mx-auto mb-2 h-6 w-6 text-muted-foreground" aria-hidden="true" />
              <p className="text-sm font-medium">No reviews yet</p>
              <Link
                href="/reviews/submit"
                className="mt-4 inline-flex min-h-10 items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground"
              >
                Start a Review
              </Link>
            </div>
          ) : (
            <div tabIndex={0} role="region" aria-labelledby="recent-reviews-cap" className="table-wrapper">
              <table className="rb-table rb-table--responsive text-left text-sm">
                <caption id="recent-reviews-cap" className="visually-hidden">
                  Recent automated code reviews
                </caption>
                <thead>
                  <tr className="border-b border-border font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                    <th scope="col" className="px-3 py-2">Repository</th>
                    <th scope="col" className="px-3 py-2">Target</th>
                    <th scope="col" className="px-3 py-2">Decision</th>
                    <th scope="col" className="px-3 py-2">Findings</th>
                    <th scope="col" className="px-3 py-2">Report</th>
                  </tr>
                </thead>
                <tbody>
                  {reviews.slice(0, 6).map((rev) => (
                    <tr key={rev.id} className="border-b border-border last:border-b-0">
                      <th scope="row" className="px-3 py-3 font-medium">
                        {rev.repository_name}
                      </th>
                      <td data-label="Target" className="px-3 py-3 font-mono text-xs text-muted-foreground">
                        {rev.pr_number ? `PR #${rev.pr_number}` : rev.target_commit.slice(0, 10)}
                      </td>
                      <td data-label="Decision" className="px-3 py-3">
                        <RecommendationBadge recommendation={rev.recommendation} />
                      </td>
                      <td data-label="Findings" className="px-3 py-3 font-mono text-xs">
                        {rev.findings_count ?? 0}
                      </td>
                      <td data-label="Report" className="px-3 py-3">
                        <Link href={`/reviews/${rev.id}`} className="font-mono text-xs font-semibold hover:underline">
                          Open →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Expressive 6-Agent Orbs (Borderless, zero unnecessary boxes) */}
        <section className="rounded-xl border border-border bg-card p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-base font-semibold">Agents</h2>
            <Link
              href="/agents"
              className="font-mono text-xs text-muted-foreground hover:text-foreground hover:underline"
            >
              Activity →
            </Link>
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-6 pt-1 sm:grid-cols-3 lg:grid-cols-2">
            {llmConfigs.map((agent) => (
              <div key={agent.agent_name} className="flex flex-col items-center text-center">
                <LiveOrb
                  size={56}
                  variant={agent.has_api_key ? "webgl" : undefined}
                  expression={agent.has_api_key ? "completed" : "alert"}
                  colors={AGENT_ORB_PALETTES[agent.agent_name]}
                  blink={!agent.has_api_key}
                />
                <p className="mt-2 text-xs font-semibold">{agent.label}</p>
                <p className="font-mono text-[10px] text-muted-foreground">{agent.model}</p>
                <p
                  className={`mt-0.5 font-mono text-[10px] font-medium ${
                    agent.has_api_key
                      ? "text-emerald-600 dark:text-emerald-400"
                      : "text-amber-600 dark:text-amber-400"
                  }`}
                >
                  {agent.has_api_key ? "Ready" : "No Key"}
                </p>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
