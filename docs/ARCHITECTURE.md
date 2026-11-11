# Swarm Architecture Overview

## 1. Five-Layer System Architecture

1. **Frontend (`frontend/`)**: Next.js 15 + React 19 + TypeScript + Tailwind CSS v4 + Monaco Editor (`@monaco-editor/react`) + resilient WebSockets + interactive WebGL UI (`LiquidNavbar`, `LiveOrb`, `GlassFolder`).
   - 11 App Router routes: Dashboard (`/`), Repositories (`/repositories`), Codebase Explorer (`/repositories/[id]`), Submit Review (`/reviews/submit`), Agent Activity (`/agents`), Consolidated Code Review (`/reviews/[id]`), Fix Suggestions (`/patches`), Review History (`/history`), Analytics (`/analytics`), Project Guide (`/architecture`), and Settings (`/settings`).
2. **Backend (`backend/app/`)**: FastAPI + async SQLAlchemy + Pydantic Settings + Fernet secret encryption + JWT authentication + active cancellation registry (`cancellation.py`).
3. **Multi-Agent Orchestration (`backend/app/orchestration/`, `backend/app/agents/`)**:
   - Implemented with **Microsoft Agent Framework** (`agent-framework-core` `WorkflowBuilder`, `Executor`, `@handler`, `add_fan_out_edges`, `add_fan_in_edges`, `add_edge`, `WorkflowContext`) and `agent-framework-openai` (`OpenAIChatCompletionClient` pointed at DeepSeek OpenAI-compatible API `https://api.deepseek.com/v1`).
   - Each of the 6 agents supports independent `model`, `base_url`, `api_key`, and `temperature` configuration.
   - Explicit cancellation checkpoints and live HTTP client tracking immediately abort in-flight LLM calls and kill subprocesses when a user stops an operation.
4. **Accuracy & Deterministic Analysis Engines (`backend/app/scanners/`)**:
   - Tools: `git`, `semgrep`, `gitleaks`, `bandit`, `osv-scanner`, `ruff`, `pytest`, `coverage`, `node` (`--experimental-vm-modules` JS/TS syntax validator).
   - Accuracy engines (`code_engines.py`): Security-prioritized file ranking (`prioritize_repo_files`), explicit `[COMPLETE FILE]` / `[PARTIAL FILE]` context headers, polyglot defensive-guard extraction (`extract_polyglot_file_facts`), synthetic test-fixture detection (`is_test_fixture_hit`), and cross-file test-import mapping (`test_tools.py`).
   - Executed inside an isolated Git sandbox pinned to exact `base_commit` / `target_commit` SHAs (`git_workspace.py`), stripped of secrets and automatically cleaned up in a `finally:` block.
5. **Data & Persistence Layer (`backend/app/models/tables.py`)**:
   - SQLAlchemy async models compatible with both local SQLite (`sqlite+aiosqlite`) and production PostgreSQL (`postgresql+asyncpg`):
     `users`, `connected_accounts`, `repositories`, `code_changes`, `reviews`, `agent_runs`, `findings`, `review_artifacts`, `patch_suggestions`, `review_policies`, and `agent_llm_configs`.

## 2. Decision Policy Matrix (Reviewer Manager)

| Priority | Condition | Final Recommendation |
|---|---|---|
| 1 | Review stopped by user or mandatory agent/scanner incomplete or missing API key | `Incomplete` |
| 2 | Mandatory test suite failed (`failed > 0`) | `Request Changes` |
| 3 | Verified `Critical` or `High` blocking finding | `Request Changes` |
| 4 | No blocking findings and all mandatory checks passed | `Approve` |
