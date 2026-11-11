"use client";

import React from "react";
import Link from "next/link";
import { LiveOrb } from "@/components/ui/live-orb";
import { AGENT_ORB_PALETTES } from "@/components/AgentPipelineGraph";

const LLM_PIPELINE = [
  {
    key: "diff_agent",
    name: "1. Diff Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-flash",
    inputs:
      "Commit diff + base-vs-target AST diff (semantic rename vs algorithm/permission edit, API contract & config impact) + STAIR caller/dependency slices (3,000-token cap).",
    output:
      "Explains behavioral impact, API drift, and downstream consumer risk anchored to exact symbols, callers, and line numbers.",
  },
  {
    key: "style_agent",
    name: "2. Style Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-flash",
    inputs:
      "Cached Ruff, ESLint & Pylint (when installed), AST deep-nesting/long-function/coupling/dead-code checks, repo naming conventions, and STAIR slices (2,000-token cap).",
    output:
      "Surfaces exact linter/dead-code hits deterministically and skips the LLM call whenever lints are clean/unambiguous (saving tokens).",
  },
  {
    key: "security_agent",
    name: "3. Security Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-v4-pro",
    inputs:
      "Cached Semgrep, Bandit, Gitleaks, OSV-Scanner, deterministic taint/data-flow/authz/crypto analyzer, optional CodeQL/Trivy + STAIR slices (5,000-token cap, +30% High Risk).",
    output:
      "Traces source-to-sink exploitability across trust boundaries while skipping deep LLM scans on clean/low-risk non-code changes.",
  },
  {
    key: "test_coverage_agent",
    name: "4. Test-Coverage Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-flash",
    inputs:
      "Change-impact selective Pytest/Vitest runner, failure triage (code vs env/dep), Coverage.py lines, test-import map, and Hypothesis/Mutmut candidate detector (3,500-token cap).",
    output:
      "Isolates failing/untested changed symbols without falsely claiming tests ran when only static code inspection occurred.",
  },
  {
    key: "reviewer_manager",
    name: "5. Reviewer Manager",
    phase: "Fan-In + EvidenceGuard",
    model: "deepseek-v4-pro",
    inputs:
      "All 4 specialist outputs + immutable EV-NNN EvidenceStore + capability/permission enforcement + cross-agent contradiction detector + STAIR slices (3,000-token cap).",
    output:
      "Blocks fabricated Verified tags & unauthorized test-execution claims, calibrates confidence separately, normalizes severity, and computes the deterministic verdict.",
  },
  {
    key: "fix_suggestion_agent",
    name: "6. Fix-Suggestion Agent",
    phase: "Isolated Patch Sandbox",
    model: "deepseek-v4-pro",
    inputs:
      "Strictly EvidenceGuard-Verified defects (EV-NNN backed) + stale-hash conflict guard + STAIR context (4,000-token cap) + regression test hints.",
    output:
      "Generates minimal patches validated in an isolated temp copy via git apply --check, AST/Node syntax, optional mypy/tsc type-checks, security+taint rescan, and targeted tests.",
  },
];

export default function ArchitectureGuidePage() {
  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">How the Models Work</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Before Fan-Out starts, Swarm builds a STAIR hierarchical code/dependency index and classifies diff risk in
            the Central Review Planner. LLMs never self-certify findings — EvidenceGuard verifies every tool citation
            and source line independently.
          </p>
        </div>
        <Link
          href="/reviews/submit"
          className="inline-flex min-h-10 items-center rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground hover:opacity-90"
        >
          Run Review
        </Link>
      </header>

      {/* Borderless 6-Orb Lineup */}
      <section aria-label="Six DeepSeek Agents" className="grid grid-cols-2 gap-6 py-2 sm:grid-cols-3 lg:grid-cols-6">
        {LLM_PIPELINE.map((item) => (
          <div key={item.key} className="flex flex-col items-center text-center">
            <LiveOrb
              size={68}
              variant="webgl"
              expression="completed"
              colors={AGENT_ORB_PALETTES[item.key]}
              blink={false}
            />
            <p className="mt-2 text-xs font-semibold">{item.name.replace(/^\d+\.\s*/, "")}</p>
            <p className="font-mono text-[10px] text-muted-foreground">{item.model}</p>
          </div>
        ))}
      </section>

      {/* Clear Model-by-Model LLM Breakdown */}
      <section className="rounded-xl border border-border bg-card p-5">
        <h2 className="mb-4 text-base font-semibold">What Each LLM Receives &amp; Enforces</h2>
        <div tabIndex={0} role="region" aria-labelledby="llm-spec-cap" className="table-wrapper">
          <table className="rb-table rb-table--responsive text-left text-sm">
            <caption id="llm-spec-cap" className="visually-hidden">
              Inputs and outputs for all six DeepSeek agents
            </caption>
            <thead>
              <tr className="border-b border-border font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                <th scope="col" className="px-3 py-2">Agent &amp; Model</th>
                <th scope="col" className="px-3 py-2">Grounded Context Passed to LLM</th>
                <th scope="col" className="px-3 py-2">Decision &amp; Safeguard</th>
              </tr>
            </thead>
            <tbody>
              {LLM_PIPELINE.map((row) => (
                <tr key={row.key} className="border-b border-border last:border-b-0">
                  <th scope="row" className="px-3 py-3 align-top font-semibold">
                    <span className="block">{row.name}</span>
                    <span className="mt-0.5 block font-mono text-[11px] font-normal text-muted-foreground">
                      {row.model} · {row.phase}
                    </span>
                  </th>
                  <td data-label="Inputs" className="px-3 py-3 align-top text-xs leading-relaxed text-muted-foreground">
                    {row.inputs}
                  </td>
                  <td data-label="Output" className="px-3 py-3 align-top text-xs leading-relaxed text-foreground">
                    {row.output}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Deterministic Decision Rules */}
      <section className="rounded-xl border border-border bg-card p-5">
        <h2 className="mb-3 text-base font-semibold">Deterministic Decision Policy Matrix</h2>
        <ul className="space-y-2 text-xs">
          <li className="flex items-center justify-between gap-4 border-b border-border/60 py-2">
            <span>
              <strong>Priority 1:</strong> User clicked Stop Operation, or a mandatory agent/scanner timed out, failed, or lacked an API key
            </span>
            <strong className="shrink-0 font-mono text-amber-600 dark:text-amber-400">Incomplete</strong>
          </li>
          <li className="flex items-center justify-between gap-4 border-b border-border/60 py-2">
            <span>
              <strong>Priority 2:</strong> <code>require_tests_pass</code> is enabled and test execution reported <code>failed &gt; 0</code>
            </span>
            <strong className="shrink-0 font-mono text-rose-600 dark:text-rose-400">Request Changes</strong>
          </li>
          <li className="flex items-center justify-between gap-4 border-b border-border/60 py-2">
            <span>
              <strong>Priority 3:</strong> At least one Verified <code>Critical</code> (<code>block_on_critical=true</code>) or <code>High</code> (<code>block_on_high=true</code>) finding exists
            </span>
            <strong className="shrink-0 font-mono text-rose-600 dark:text-rose-400">Request Changes</strong>
          </li>
          <li className="flex items-center justify-between gap-4 py-2">
            <span>
              <strong>Priority 4:</strong> All mandatory checks completed cleanly with zero verified blockers
            </span>
            <strong className="shrink-0 font-mono text-emerald-600 dark:text-emerald-400">Approve</strong>
          </li>
        </ul>
      </section>
    </div>
  );
}
