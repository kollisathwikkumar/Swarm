# Swarm — Project Architecture & Capabilities Summary

## 1. Overview

**Swarm** is a multi-agent **Automated Code Review Platform** built with **Next.js 15**, **FastAPI**, and **Microsoft Agent Framework** (`WorkflowBuilder`). Instead of passing a truncated diff into a single LLM prompt, Swarm executes pre-Fan-Out indexing and risk planning, runs deterministic static, taint, style, security, and test engines, fans out across **4 parallel specialist agents**, enforces LLM-independent verification inside **`EvidenceGuard` + Reviewer Manager (Fan-In)**, and validates patches inside an isolated temporary workspace copy before awaiting human approval.

---

## 2. Real-World Safeguards Implemented

| Review Pitfall | How Swarm Resolves It |
|---|---|
| Missing context from truncated diffs | STAIR 4-level `StructureIndex` + `STAIRContextBuilder` delivers changed symbols, callers, callees, imports, `implemented_guards`, and linked tests within strict per-agent token budgets. |
| Self-certified `Verified` tags & invented tool names | `EvidenceGuard` builds an immutable `EV-NNN` `EvidenceStore` and promotes `"Verified"` only on exact `(file_path, tool/rule, line ±3)` matches. |
| Agents claiming tests ran from code reading | `AgentCapabilities` (`permissions.py`) + `enforce_agent_permissions` strip test-execution assertions when no verified `pytest`/`vitest` execution telemetry exists. |
| False "no tests found" on helper modules | Cross-file test-import mapping (`test_tools.py`) traces direct, indirect, and mocked-only imports across Python and TS/JS suites. |
| Docs-only PRs failing or wasting tokens | `ReviewPlanner` classifies docs-only changes `low` risk (`skipped_by_plan`), while Style & Security agents apply deterministic token-saver LLM skips and incremental `ReviewCache`. |
| Broken AI-suggested patches | `FixSuggestionAgentExecutor` strictly gates patches via `is_patch_eligible`, detects source SHA conflicts, and validates in an isolated temp copy via `git apply --check`, AST/Node syntax checks, security + taint rescan, optional `mypy`/`tsc`, and targeted `pytest`. |
| Slow runs burning tokens after stop | `Stop Operation` closes tracked `AsyncOpenAI` clients, cancels the workflow task, and kills child subprocesses. |

---

## 3. The Six Sub-Agents

| Agent | Execution Stage | Default Model | Core Engines & Token Budget | Responsibility & Permissions |
|---|---|---|---|---|
| **Diff Agent** | Fan-Out (Parallel) | `deepseek-flash` | `git diff`, `diff-ast-engine` (base vs. target AST, API contracts, config impact), STAIR slices (`3,000` / `1,200` tokens) | Summarizes semantic diffs & blast radius; read-only, cannot propose patches or claim test runs. |
| **Style Agent** | Fan-Out (Parallel) | `deepseek-flash` | Cached `ruff`, optional `eslint`/`pylint`, AST complexity/nesting/coupling/dead-code/naming, Node TS syntax check (`2,000` tokens) | Reports exact lint/dead-code violations; skips LLM completely when lints are clean/unambiguous. |
| **Security Agent** | Fan-Out (Parallel) | `deepseek-v4-pro` | Cached `semgrep`, `bandit`, `gitleaks`, `osv-scanner`, `security-guard`, `security-taint` (SQLi/CMDi/path/authz/crypto), optional `codeql`/`trivy` (`5,000` / `6,500` tokens) | Traces exploitability across trust boundaries; skips deep LLM scan on clean low-risk/docs diffs. |
| **Test-Coverage Agent** | Fan-Out (Parallel) | `deepseek-flash` | Impact-graph selective `pytest`/`vitest`, `coverage.py`, `test-mapper`, failure triage (`code` vs `env`/`dep`), `Hypothesis`/`Mutmut` detector (`3,500` tokens) | Executes impacted tests cleanly without falsifying coverage or mutation execution. |
| **Reviewer Manager** | Fan-In Barrier | `deepseek-v4-pro` | `EvidenceStore` (`EV-NNN`), `enforce_agent_permissions`, contradiction detector, severity normalizer, policy engine (`3,000` / `3,900` tokens) | Blocks fabricated tags, calibrates confidence separately from `Verified`, computes policy recommendation. |
| **Fix-Suggestion Agent** | Patch Sandbox | `deepseek-v4-pro` | `is_patch_eligible` gate, SHA conflict guard, isolated temp sandbox (`git apply --check`, syntax, security+taint rescan, optional `mypy`/`tsc`, targeted tests) (`4,000` tokens) | Only agent allowed to propose diffs (never auto-commits); strictly gated to `Verified` `EV-NNN` defects. |

---

## 4. GitHub Integration, Local Companion & Hardening

- **GitHub Sync & Explorer**: Supports 1-click `gh` CLI connect, PAT, OAuth Web Flow, OAuth Device Flow, rate-limit mirror fallback (`_mirrors/`), HMAC webhooks + 90s background PR poller, Markdown/inline PR publishing, and single or batch **Approve & Commit All to GitHub**.
- **Local Companion (`local-companion/`)**: Binds to `127.0.0.1:8765`, requires 30-minute rotating `X-Pairing-Token` (`hmac.compare_digest`), validates loopback/HTTPS backend targets, and strips `.env`/keys before extracting diffs.
- **Git, Secret & Process Isolation**: `validate_git_ref` blocks flag injection, `resolve_within_dir` confines reads inside sandboxes, Fernet encrypts keys/tokens at rest (`260,000`-iteration PBKDF2 passwords), `0o500` `GIT_ASKPASS` avoids URL tokens, and `sanitized_subprocess_env()` strips secrets from scanner subprocesses.
