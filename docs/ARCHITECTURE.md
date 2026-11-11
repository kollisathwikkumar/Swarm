# Swarm Architecture Overview

## 1. Five-Layer System Architecture

1. **Frontend (`frontend/`)**: Next.js 15.3+ + React 19.1 + TypeScript 5.8 + Tailwind CSS v4 + Monaco Editor & DiffEditor + resilient WebSockets + interactive UI primitives (`LiquidNavbar`, GLSL/CSS `LiveOrb`, `GlassFolder`).
   - 11 App Router routes: Dashboard (`/`), Repositories (`/repositories`), Codebase Explorer (`/repositories/[id]`), Submit Review (`/reviews/submit`), Agent Activity (`/agents`), Consolidated Code Review (`/reviews/[id]`), Fix Suggestions (`/patches`), Review History (`/history`), Analytics (`/analytics`), Project Guide (`/architecture`), and Settings (`/settings`).
2. **Backend Control Plane (`backend/app/api/`, `backend/app/services/`)**: FastAPI + async SQLAlchemy + Pydantic Settings + Fernet secret encryption + PBKDF2/JWT authentication + active cancellation registry (`cancellation.py`) + 90s GitHub PR poller (`github_sync.py`).
3. **Intelligence, Planning & Caching (`backend/app/intelligence/`, `backend/app/planning/`, `backend/app/cache/`)**:
   - **STAIR Code & Dependency Intelligence**: `build_structure_index` (`Repository -> Package -> Module -> Symbol` up to 180 files / 250 symbols per module, caller/callee/import/test edges, full-file defensive guards) + `retrieve_relevant_context` + token-budgeted `build_agent_context`.
   - **Central ReviewPlanner**: Deterministic diff risk scorer (`high` / `medium` / `low` / `docs_only`), skill selector, and selective scanner gating (`skipped_by_plan` on docs-only edits).
   - **Incremental `ReviewCache`**: Content-addressed JSON cache (`sha256(content_hash|tool_version|configuration_hash|commit_context)`) under `<WORKSPACE_DIR>/_cache/<namespace>/`.
4. **Orchestration, Verification & Scanners (`backend/app/orchestration/`, `backend/app/agents/`, `backend/app/skills/`, `backend/app/verification/`, `backend/app/scanners/`)**:
   - **Microsoft Agent Framework** (`WorkflowBuilder` Fan-Out / Fan-In) + `OpenAIChatCompletionClient` per agent.
   - **Capability & Permission Registry (`permissions.py`)**: Explicit `AgentCapabilities` separation of skills, allowed/optional engines, patch permissions, and execution-claim guards (`enforce_agent_permissions`).
   - **Independent `EvidenceGuard` (`evidence_guard.py`)**: Immutable `EV-NNN` `EvidenceStore`, exact `(file_path, tool/rule, line ±3)` provenance matching, `confidence` vs `Verified` separation, cross-agent contradiction detector, and strict `is_patch_eligible` patch gating.
   - **Deterministic Engines**: `git diff`, `diff_engines.py` (AST diff & API contracts), `ruff`, `ast-complexity`, `dead-code-analyzer`, `duplicate-detector`, `node` JS/TS syntax validator, `semgrep`, `bandit`, `gitleaks`, `osv-scanner`, `security-guard`, `security_taint.py` (taint/authz/crypto), `pytest`, `coverage.py`, `test_tools.py` (selective impact test runner & failure triage), plus optional `eslint`, `pylint`, `codeql`, `trivy`, `mypy`, `tsc`, `hypothesis`, `mutmut`, `tree_sitter`, `vitest`.
5. **Persistence Layer (`backend/app/models/tables.py`, `backend/app/database/session.py`)**:
   - 11 async SQLAlchemy tables compatible with SQLite WAL (zero-Docker default, with idempotent `init_db()` migration) and PostgreSQL + Redis + Celery:
     `users`, `connected_accounts`, `repositories`, `code_changes`, `reviews`, `agent_runs`, `findings` (including `evidence_ids` & `confidence`), `review_artifacts`, `patch_suggestions`, `review_policies`, and `agent_llm_configs`.

## 2. Decision Policy Matrix (Reviewer Manager)

| Priority | Condition | Final Recommendation |
|---|---|---|
| 1 | Review stopped by user or mandatory agent/scanner incomplete or missing API key | `Incomplete` |
| 2 | Mandatory test suite failed (`failed > 0`) | `Request Changes` |
| 3 | `Verified` `Critical` (`block_on_critical=true`) or `High` (`block_on_high=true`) finding | `Request Changes` |
| 4 | No blocking findings and all mandatory checks passed | `Approve` |
