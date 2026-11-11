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
      "Commit diff + prioritized complete files (up to 600 lines each) + extracted symbol/guard index (URL validation, auth parsing, DB locks).",
    output:
      "Explains behavioral impact across files and flags logical bugs or edge-case regressions anchored to exact line numbers.",
  },
  {
    key: "style_agent",
    name: "2. Style Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-flash",
    inputs:
      "Ruff lints, Python AST complexity, Node TS syntax parse results, repeated dynamic imports, and detected >=6-line duplicate blocks.",
    output:
      "Surfaces broken syntax, high-complexity modules, duplication, and maintainability defects backed by deterministic tool hits.",
  },
  {
    key: "security_agent",
    name: "3. Security Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-v4-pro",
    inputs:
      "Semgrep, Bandit, Gitleaks (tagging test-file fixtures cleanly), OSV-Scanner CVEs, deterministic auth/SSRF guards, and complete security-critical files.",
    output:
      "Identifies exploitable vulnerabilities, credential leaks, and SSRF gaps without misclassifying mock test strings as production leaks.",
  },
  {
    key: "test_coverage_agent",
    name: "4. Test-Coverage Agent",
    phase: "Fan-Out (Parallel)",
    model: "deepseek-flash",
    inputs:
      "Pytest/Vitest execution results, Coverage.py lines, and the Cross-File Test-Import Map (direct and indirect test imports + skipIf flags).",
    output:
      "Reports real test failures or untested modules rather than guessing coverage from filenames alone.",
  },
  {
    key: "reviewer_manager",
    name: "5. Reviewer Manager",
    phase: "Fan-In Verification",
    model: "deepseek-v4-pro",
    inputs:
      "All 4 specialist outputs merged alongside a ground-truth index of actual disk files, line counts, syntax/SAST hits, and test-import maps.",
    output:
      "Deduplicates findings, blocks LLM-invented Verified tags, rejects contradicted false positives into rejected_false_positives, and computes the final verdict.",
  },
  {
    key: "fix_suggestion_agent",
    name: "6. Fix-Suggestion Agent",
    phase: "Patch Synthesis",
    model: "deepseek-v4-pro",
    inputs:
      "Top actionable finding + full edit window (up to 500 lines) + test assertions imported from covering unit tests.",
    output:
      "Generates a unified diff verified by git apply --check and Python/Node syntax parsers (with automatic 1-shot self-repair on error). Human approval is always required.",
  },
];

export default function ArchitectureGuidePage() {
  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">How the Models Work</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Deterministic scanners and AST parsers read full repository files first so DeepSeek Flash and V4 Pro
            never guess from truncated diffs. Every finding and patch is verified against disk evidence before output.
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
