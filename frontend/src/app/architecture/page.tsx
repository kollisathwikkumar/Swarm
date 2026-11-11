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
      "Commit diff + STAIR hierarchical symbol/dependency slices (3,000-token budget) + AST changed-symbol & defensive-guard facts.",
    output:
      "Explains behavioral impact, semantic diffs, and API contract drift anchored to exact symbols, callers, and line numbers.",
  },
  {
    key: "style_agent",
    name: "2. Style Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-flash",
    inputs:
      "Incremental cached Ruff lints, Python AST complexity, Node TS syntax parse results, duplicate blocks, and STAIR complexity slices (2,000-token budget).",
    output:
      "Surfaces broken syntax, high-complexity modules, duplication, and local refactoring fixes with honest confidence scores.",
  },
  {
    key: "security_agent",
    name: "3. Security Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-v4-pro",
    inputs:
      "Cached Semgrep, Bandit, Gitleaks, OSV-Scanner CVEs, SSRF/auth guards + STAIR caller/callee & guard slices (5,000-token budget, +30% on High Risk).",
    output:
      "Audits source-to-sink paths and auth boundaries without falsely flagging guards implemented elsewhere in the module or test fixtures.",
  },
  {
    key: "test_coverage_agent",
    name: "4. Test-Coverage Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-flash",
    inputs:
      "Pytest/Vitest execution results, Coverage.py lines, Cross-File Test-Import Map, and STAIR linked test/symbol slices (3,500-token budget).",
    output:
      "Reports real test failures or untested changed symbols rather than guessing coverage from filenames alone.",
  },
  {
    key: "reviewer_manager",
    name: "5. Reviewer Manager",
    phase: "Fan-In + EvidenceGuard",
    model: "deepseek-v4-pro",
    inputs:
      "All 4 specialist outputs + independent EvidenceGuard Store (EV-NNN provenance IDs) + STAIR verification slices (3,000-token budget, +30% on High Risk).",
    output:
      "Blocks LLM self-certified Verified tags, enforces exact (file, tool/rule, line) attribution, rejects contradicted claims, and computes the verdict.",
  },
  {
    key: "fix_suggestion_agent",
    name: "6. Fix-Suggestion Agent",
    phase: "Patch Validation",
    model: "deepseek-v4-pro",
    inputs:
      "Strictly EvidenceGuard-Verified defects (EV-NNN backed) + STAIR caller/dependency context (4,000-token budget) + covering test contracts.",
    output:
      "Generates minimal unified diffs verified by git apply --check, syntax parsers, and security-guard regression checks. Human approval is always required.",
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
