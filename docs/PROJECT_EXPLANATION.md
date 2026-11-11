# Swarm — Complete Project Explanation & Architecture

## 1. What Is Swarm?

**Swarm** is a multi-agent **Automated Code Review Platform** that audits software changes before developers merge them.

Instead of relying on a single LLM prompt over a partial diff, Swarm splits every review across **six specialized AI agents** orchestrated with **Microsoft Agent Framework** (`WorkflowBuilder`) using a **Fan-Out / Fan-In** architecture, anchored in **deterministic static analysis, security scanners, syntax parsers, and test runners**:

> Developer submits code (GitHub PR, GitHub Commit, Branch Comparison, Full Codebase Audit, or Local Git Diff)  
> → **4 Analysis Agents run concurrently (Fan-Out)**  
> → **Reviewer Manager (Fan-In)** verifies file/line existence on disk, strips false positives, blocks unbacked claims, and decides `Approve` / `Request Changes` / `Incomplete`  
> → **Fix-Suggestion Agent** proposes minimal `git apply --check` + AST/Node syntax-validated patches (with automatic 1-shot self-repair)  
> → Developer reviews findings side-by-side in Monaco Editor and explicitly approves, applies locally, or commits fixes back to GitHub.

---

## 2. Real-World Problems & Swarm Engineering Safeguards

| Review Pitfall | How Swarm Solves It |
|---|---|
| Manual PR reviews bottleneck engineering teams | Parallel 4-agent Fan-Out analysis across diff, style, security & tests |
| LLMs hallucinate "missing validation" when viewing truncated diffs | Complete line-numbered files + `[COMPLETE FILE]` headers + `extract_polyglot_file_facts` guard index |
| False "no tests found" alerts on helper modules | Cross-file test-import mapping (`test_tools.py`) traces direct & indirect imports + Vitest/Pytest discovery |
| Mock fixture tokens in tests flagged as Critical leaks | Gitleaks + `is_test_fixture_hit` downgrades obvious synthetic test fixtures cleanly |
| Unverified LLM guesses block builds | Reviewer Manager blocks LLM-invented `Verified` tags unless backed by a real tool hit and disk evidence |
| Broken patches suggested by AI | `difflib` + `git apply --check` + Python `ast.parse` / Node VM syntax check + 1-shot self-repair |
| Stopping slow runs still drains tokens | Instant `Stop Operation` closes `AsyncOpenAI` clients, cancels tasks, kills subprocesses, and adds Re-run / Leave Task controls |

---

## 3. Five-Layer Architecture

1. **Frontend (`frontend/`)**: Next.js 15, React 19, TypeScript, Tailwind CSS v4, Monaco Editor, WebSockets, and interactive WebGL components (`LiquidNavbar`, `LiveOrb`, `GlassFolder`).
2. **Backend (`backend/app/`)**: FastAPI REST routers, real-time WebSockets (`/ws/reviews/{id}`, `/ws/activity`), isolated Git sandbox manager, active cancellation registry, and Fernet secret encryption.
3. **Multi-Agent Orchestration (`backend/app/orchestration/`, `backend/app/agents/`)**:
   - Microsoft Agent Framework `WorkflowBuilder` (`add_fan_out_edges`, `add_fan_in_edges`, `add_edge`, `WorkflowContext`).
   - DeepSeek OpenAI-compatible client (`OpenAIChatCompletionClient`) with bounded HTTP & `asyncio.wait_for` timeouts (`70s–95s`).
4. **Deterministic Analysis & Accuracy Engines (`backend/app/scanners/`)**:
   - **Semgrep**, **Gitleaks**, **Bandit**, **OSV-Scanner**, **Ruff**, **Pytest**, **Coverage.py**, **Node syntax VM parser**, and **Git**.
5. **Persistence Layer (`backend/app/models/tables.py`)**:
   - SQLAlchemy async models supporting zero-Docker local **SQLite** or **PostgreSQL + Redis + Celery** (`docker-compose.yml`).

---

## 4. The Six Sub-Agents

| Agent | Execution Stage | Default DeepSeek Model | Deterministic Tools | Responsibility |
|---|---|---|---|---|
| **Diff Agent** | Fan-Out (Parallel) | `deepseek-flash` | `git diff`, Polyglot Symbol & Guard Extractor | Summarizes code changes, affected files, and line-grounded behavioral risks. |
| **Style Agent** | Fan-Out (Parallel) | `deepseek-flash` | `ruff`, Python AST complexity, Node JS/TS syntax parser, 6-line duplicate detector | Detects syntax breaks, complexity spikes, dynamic imports, duplication, and style defects. |
| **Security Agent** | Fan-Out (Parallel) | `deepseek-v4-pro` | `semgrep`, `bandit`, `gitleaks`, `osv-scanner`, SSRF/Auth guards | Identifies exploitable vulnerabilities, credential leaks, and vulnerable dependencies. |
| **Test-Coverage Agent** | Fan-Out (Parallel) | `deepseek-flash` | `pytest`, `coverage.py`, Vitest/Pytest test-import mapper | Executes tests cleanly and traces direct/indirect test coverage gaps. |
| **Reviewer Manager** | Fan-In Barrier | `deepseek-v4-pro` | Disk line verifier, Deterministic index, Policy Engine | Deduplicates findings, isolates `rejected_false_positives`, enforces evidence checks, and outputs decision. |
| **Fix-Suggestion Agent** | Patch Synthesis | `deepseek-v4-pro` | `difflib`, `git apply --check`, AST/Node syntax checker, Test contract extractor | Proposes minimal fixes verified cleanly against syntax & git apply; always human-gated. |

---

## 5. GitHub Sync, Local Companion & Security Controls

- **GitHub Sync & Built-In Explorer**: Supports 1-click GitHub CLI (`gh`) auth, PATs, GitHub OAuth, full-tree repository exploration with local Git mirror fallback when REST rate-limited, webhook auto-reviews (`X-Hub-Signature-256` verified), and PR inline comment publishing.
- **Local Companion (`local-companion/`)**: Binds strictly to `127.0.0.1:8765`, validates rotating 30-minute pairing tokens (`hmac.compare_digest`), validates local backend targets against SSRF, enforces root confinement, and excludes `.env` and key files before extracting diffs.
- **Git & Path Hardening**: Strict Git ref validation rejects CLI flag injection (`--...`), path containment blocks `..` escapes/symlinks, and scanner subprocesses run under a sanitized environment stripping application secrets.
