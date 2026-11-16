from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agent_framework import Executor, WorkflowBuilder, WorkflowContext, handler

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))
sys.path.insert(0, str(REPO_ROOT / "local-companion"))

from repository_reader import is_sensitive_path, validate_repo_path

from app.agents.fix_suggestion_agent import _compute_unified_diff
from app.agents.reviewer_manager import (
    _deterministic_deduplicate,
    _evaluate_review_policy,
    _is_harness_noise,
)
from app.integrations.github_client import GitHubClient, parse_github_repo_input
from app.orchestration.shared_state import AgentExecutionOutput, ReviewState
from app.scanners.code_engines import (
    extract_polyglot_file_facts,
    is_test_fixture_hit,
    prioritize_repo_files,
    run_deterministic_code_guards,
    verify_code_syntax,
)
from app.scanners.git_diff_tool import parse_unified_diff
from app.scanners.security_tools import run_bandit, run_gitleaks, run_semgrep
from app.scanners.style_tools import run_style_scanners
from app.scanners.test_tools import build_test_coverage_map, run_test_and_coverage
from app.services.crypto import decrypt_secret, encrypt_secret, hash_password, verify_password
from app.services.git_workspace import verify_patch_applicability


async def _arun_git(*args: str, cwd: Path) -> None:
    await asyncio.to_thread(
        subprocess.run,
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


async def _arun_git_out(*args: str, cwd: Path) -> str:
    res = await asyncio.to_thread(
        subprocess.run,
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout


def test_password_and_secret_crypto():
    h = hash_password("SecurePass123!")
    assert verify_password("SecurePass123!", h)
    assert not verify_password("WrongPass", h)

    secret = "sk-deepseek-test-key-123456789"
    enc = encrypt_secret(secret)
    assert enc != secret
    assert decrypt_secret(enc) == secret


def test_parse_unified_diff_lines():
    diff = """diff --git a/auth/login.py b/auth/login.py
index 1111111..2222222 100644
--- a/auth/login.py
+++ b/auth/login.py
@@ -10,2 +10,4 @@ def login(user):
     conn = get_db()
+    query = f"SELECT * FROM users WHERE name = '{user}'"
+    return conn.execute(query).fetchone()
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    assert files[0].path == "auth/login.py"
    assert files[0].additions == 2
    assert files[0].changed_lines == [11, 12]


@pytest.mark.asyncio
async def test_real_security_style_and_test_scanners(tmp_path: Path):
    # Create a real mini git repo with real SQLi, secret, style issue, and failing/passing tests
    await _arun_git("init", cwd=tmp_path)
    vuln_file = tmp_path / "login.py"
    vuln_file.write_text(
        'import sqlite3\n'
        'API_KEY = "sk_live_TEST_SECRET_VALUE_9876543210ABCDEF"\n'
        'def find_user(name):\n'
        '    conn = sqlite3.connect(":memory:")\n'
        '    return conn.execute(f"SELECT * FROM users WHERE name = {name}")\n',
        encoding="utf-8",
    )
    test_file = tmp_path / "test_login.py"
    test_file.write_text(
        "from login import find_user\n"
        "def test_placeholder():\n"
        "    assert callable(find_user)\n",
        encoding="utf-8",
    )

    semgrep_res = await run_semgrep(tmp_path, ["login.py"])
    assert semgrep_res["status"] == "completed"
    assert any("sql" in f["rule_id"].lower() or "credential" in f["rule_id"].lower() for f in semgrep_res["findings"])

    bandit_res = await run_bandit(tmp_path, ["login.py"])
    assert bandit_res["status"] == "completed"
    assert len(bandit_res["findings"]) >= 1

    gitleaks_res = await run_gitleaks(tmp_path)
    assert gitleaks_res["status"] == "completed"

    style_res = await run_style_scanners(tmp_path, ["login.py"])
    assert style_res["ruff"]["status"] == "completed"

    test_res = await run_test_and_coverage(tmp_path, ["login.py"], enable_execution=True)
    assert test_res["status"] == "completed"
    assert test_res["passed"] == 1
    assert test_res["failed"] == 0
    assert test_res["total_coverage_percent"] is not None


@pytest.mark.asyncio
async def test_unified_diff_and_git_apply_check(tmp_path: Path):
    await _arun_git("init", cwd=tmp_path)
    target = tmp_path / "app.py"
    original = "def add(a, b):\n    return a - b\n"
    proposed = "def add(a, b):\n    return a + b\n"
    target.write_text(original, encoding="utf-8")

    diff = _compute_unified_diff("app.py", original, proposed)
    ok, msg = await verify_patch_applicability(tmp_path, "app.py", diff)
    assert ok, msg


def test_reviewer_manager_deduplication_and_policy_matrix(tmp_path: Path):
    raw = [
        {
            "agent": "Security Agent",
            "category": "security",
            "severity": "High",
            "title": "SQL Injection",
            "file_path": "auth/login.py",
            "line_number": 24,
            "tool_name": "bandit",
            "verification_status": "Verified",
        },
        {
            "agent": "Security Agent",
            "category": "security",
            "severity": "Critical",
            "title": "SQL Injection via f-string",
            "file_path": "auth/login.py",
            "line_number": 24,
            "tool_name": "semgrep",
            "verification_status": "Verified",
        },
    ]
    dedup = _deterministic_deduplicate(raw)
    assert len(dedup) == 1
    assert dedup[0]["severity"] == "Critical"
    assert len(dedup[0]["deduplicated_sources"]) == 2

    state = ReviewState(
        review_id="r1",
        repository_id="repo1",
        repository_name="org/repo",
        source_type="local",
        base_commit="abc",
        target_commit="def",
        workspace_dir=tmp_path,
        diff_text="",
        changed_files=[],
        policy={
            "block_on_critical": True,
            "block_on_high": True,
            "require_tests_pass": True,
            "require_all_mandatory_scans": True,
        },
        agent_configs={},
    )
    ok_agents = [
        AgentExecutionOutput("diff_agent", "Diff Agent", "deepseek-flash", "completed", "ok"),
        AgentExecutionOutput("style_agent", "Style Agent", "deepseek-flash", "completed", "ok"),
        AgentExecutionOutput("security_agent", "Security Agent", "deepseek-v4-pro", "completed", "ok"),
        AgentExecutionOutput(
            "test_coverage_agent",
            "Test-Coverage Agent",
            "deepseek-flash",
            "completed",
            "ok",
            tool_results={"failed": 0},
        ),
        AgentExecutionOutput("reviewer_manager", "Reviewer Manager", "deepseek-v4-pro", "completed", "ok"),
    ]
    rec, _, _ = _evaluate_review_policy(state, dedup, ok_agents)
    assert rec == "Request Changes"

    rec_clean, _, _ = _evaluate_review_policy(state, [], ok_agents)
    assert rec_clean == "Approve"

    incomplete_agents = [
        AgentExecutionOutput("diff_agent", "Diff Agent", "deepseek-flash", "incomplete", "missing key")
    ] + ok_agents[1:]
    rec_inc, _, _ = _evaluate_review_policy(state, [], incomplete_agents)
    assert rec_inc == "Incomplete"


def test_github_webhook_hmac_verification():
    secret = "whsec_test_123"
    body = json.dumps({"action": "opened"}).encode("utf-8")
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert GitHubClient.verify_webhook_signature(body, sig, secret)
    assert not GitHubClient.verify_webhook_signature(body, "sha256=bad", secret)


def test_parse_github_repo_input_formats():
    assert parse_github_repo_input("kollisathwikkumar/TraceMindXSwitch")["full_name"] == "kollisathwikkumar/TraceMindXSwitch"
    assert parse_github_repo_input("https://github.com/kollisathwikkumar/TraceMindXSwitch")["full_name"] == "kollisathwikkumar/TraceMindXSwitch"
    assert parse_github_repo_input("https://github.com/kollisathwikkumar/TraceMindXSwitch.git")["full_name"] == "kollisathwikkumar/TraceMindXSwitch"
    assert parse_github_repo_input("git@github.com:kollisathwikkumar/TraceMindXSwitch.git")["full_name"] == "kollisathwikkumar/TraceMindXSwitch"
    pr = parse_github_repo_input("https://github.com/kollisathwikkumar/TraceMindXSwitch/pull/14")
    assert pr["full_name"] == "kollisathwikkumar/TraceMindXSwitch"
    assert pr["pr_number"] == 14
    cm = parse_github_repo_input("https://github.com/kollisathwikkumar/TraceMindXSwitch/commit/abc1234")
    assert cm["commit_sha"] == "abc1234"


def test_local_companion_security_controls(tmp_path: Path):
    assert is_sensitive_path(".env")
    assert is_sensitive_path("config/.env.production")
    assert is_sensitive_path("certs/private.key")
    assert is_sensitive_path(".git/config")
    assert not is_sensitive_path("src/login.py")

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / ".git").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".git").mkdir()

    assert validate_repo_path(str(allowed), allowed_root=allowed) == allowed.resolve()
    with pytest.raises(PermissionError):
        validate_repo_path(str(outside), allowed_root=allowed)


@pytest.mark.asyncio
async def test_api_end_to_end_zero_fake_data_and_missing_key_incomplete(tmp_path: Path, monkeypatch):
    import asyncio

    from httpx import ASGITransport, AsyncClient
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    # Point database & workspace to isolated tmp_path
    db_file = tmp_path / "test_rb.db"
    test_engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}", connect_args={"check_same_thread": False})
    test_session_maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    import app.database.session as db_sess
    import app.orchestration.coordinator as coord_mod
    from app.database.session import Base, get_db
    from app.main import app

    monkeypatch.setattr(db_sess, "engine", test_engine)
    monkeypatch.setattr(db_sess, "async_session_maker", test_session_maker)
    monkeypatch.setattr(coord_mod, "async_session_maker", test_session_maker)
    monkeypatch.setenv("WORKSPACE_DIR", str(tmp_path / "ws"))
    monkeypatch.setenv("DEEPSEEK_API_KEY", "")
    monkeypatch.setenv("DIFF_AGENT_API_KEY", "")
    monkeypatch.setenv("STYLE_AGENT_API_KEY", "")
    monkeypatch.setenv("SECURITY_AGENT_API_KEY", "")
    monkeypatch.setenv("TEST_COVERAGE_AGENT_API_KEY", "")
    monkeypatch.setenv("REVIEWER_MANAGER_API_KEY", "")
    monkeypatch.setenv("FIX_SUGGESTION_AGENT_API_KEY", "")

    from app.config import get_settings
    get_settings.cache_clear()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async def override_get_db():
        async with test_session_maker() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    # Build a real local Git repo with an initial commit and an uncommitted vulnerable change
    repo_dir = tmp_path / "sample_repo"
    repo_dir.mkdir()
    await _arun_git("init", cwd=repo_dir)
    await _arun_git("config", "user.email", "dev@example.com", cwd=repo_dir)
    await _arun_git("config", "user.name", "Dev", cwd=repo_dir)
    (repo_dir / "app.py").write_text("def greet(name: str) -> str:\n    return f'hi {name}'\n", encoding="utf-8")
    (repo_dir / "test_app.py").write_text("from app import greet\ndef test_greet():\n    assert greet('a') == 'hi a'\n", encoding="utf-8")
    await _arun_git("add", ".", cwd=repo_dir)
    await _arun_git("commit", "-m", "init", cwd=repo_dir)

    # Introduce a real SQL injection in working tree
    (repo_dir / "app.py").write_text(
        "import sqlite3\n"
        "def get_user(uid):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    return conn.execute(f'SELECT * FROM users WHERE id = {uid}')\n",
        encoding="utf-8",
    )

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Direct workspace access without Sign In / Auth headers
            an = (await client.get("/api/analytics/summary")).json()
            assert an["totals"]["reviews"] == 0
            assert an["totals"]["findings"] == 0

            # Connect local repo
            conn_resp = await client.post(
                "/api/repositories/local",
                json={"local_path": str(repo_dir), "name": "sample_repo"},
            )
            assert conn_resp.status_code == 200
            repo_id = conn_resp.json()["repository"]["id"]

            # Verify codebase tree & file endpoints (and sensitive .env block)
            (repo_dir / ".env").write_text("SECRET=1234", encoding="utf-8")
            tree_resp = await client.get(f"/api/repositories/{repo_id}/tree")
            assert tree_resp.status_code == 200
            paths = [item["path"] for item in tree_resp.json()["items"]]
            assert "app.py" in paths
            assert ".env" not in paths

            file_resp = await client.get(f"/api/repositories/{repo_id}/file?path=app.py")
            assert file_resp.status_code == 200
            assert "SELECT * FROM users" in file_resp.json()["content"]

            env_resp = await client.get(f"/api/repositories/{repo_id}/file?path=.env")
            assert env_resp.status_code == 403

            # Submit review (no DeepSeek API key set -> real scanners run, LLM step reports Incomplete honestly)
            sub_resp = await client.post(
                "/api/reviews",
                json={"repository_id": repo_id, "local_mode": "working_tree"},
            )
            assert sub_resp.status_code == 201
            review_id = sub_resp.json()["review_id"]

            detail = None
            for _ in range(40):
                await asyncio.sleep(0.25)
                det_resp = await client.get(f"/api/reviews/{review_id}")
                detail = det_resp.json()
                if detail["review"]["review_status"] in ("completed", "failed"):
                    break

            assert detail is not None
            assert detail["review"]["review_status"] == "completed"
            assert detail["review"]["recommendation"] in ("Request Changes", "Incomplete")
            assert len(detail["agent_runs"]) == 6
            # Real deterministic security scanners still detected SQLi!
            assert any(f["tool_name"] in ("bandit", "semgrep") for f in detail["findings"])
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
        await test_engine.dispose()




@pytest.mark.asyncio
async def test_accuracy_engines_syntax_guards_and_test_mapper(tmp_path: Path):
    # 1. Polyglot syntax validator catches broken JS/TS regexes and accepts valid TypeScript
    valid_ts = "export function ok(v: string): string { return v.replace(/-----BEGIN PRIVATE KEY-----[\\s\\S]*?/gi, 'x'); }\n"
    broken_ts = "export function bad(v: string): string { return v.replace(/-----BEGIN PRIVATE KEY-----/[\\s\\S]*?/gi, 'x'); }\n"
    ok_valid, msg_valid = await verify_code_syntax("redaction.ts", valid_ts, tmp_path)
    assert ok_valid, msg_valid
    ok_broken, msg_broken = await verify_code_syntax("redaction.ts", broken_ts, tmp_path)
    assert not ok_broken
    assert "SyntaxError" in msg_broken or "Expected" in msg_broken

    # 2. Deterministic code guards detect Basic/Digest redaction bypass & SSRF missing private-IP check
    (tmp_path / "ai").mkdir()
    (tmp_path / "ai" / "redaction.ts").write_text(
        "export function redactOutboundText(value: string): string {\n"
        "  return value.replace(/\\b(auth(?:orization)?|api_key)\\b\\s*[:=]\\s*[^\\s,;]+/gi, '$1=[REDACTED]');\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "ai" / "gateway.ts").write_text(
        "export function validateEndpoint(v: string): string {\n"
        "  const url = new URL(v);\n"
        "  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('HTTPS required');\n"
        "  return url.toString();\n"
        "}\n"
        "export function checkCitations(ids: Set<string>, cited: string[]): void {\n"
        "  if (cited.some((id) => !ids.has(id))) throw new Error('bad id');\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "audit").mkdir()
    (tmp_path / "audit" / "git-dirty-state.ts").write_text("export const dirty = true;\n", encoding="utf-8")
    (tmp_path / "audit" / "git-revision.test.ts").write_text(
        "import { it, expect } from 'vitest';\n"
        "import { dirty } from './git-dirty-state';\n"
        "it('checks dirty state', () => { expect(dirty).toBe(true); });\n",
        encoding="utf-8",
    )
    (tmp_path / "brain").mkdir()
    (tmp_path / "brain" / "binding.ts").write_text("export const getPolicy = () => null;\n", encoding="utf-8")
    (tmp_path / "ai" / "gateway.test.ts").write_text(
        "import { vi, it, expect } from 'vitest';\n"
        "vi.mock('../brain/binding', () => ({ getPolicy: vi.fn() }));\n"
        "import { redactOutboundText } from './redaction';\n"
        "it('redacts secret fixtures', () => {\n"
        "  const s = 'api_key=\"secret-api-key-123456\"';\n"
        "  expect(redactOutboundText(s)).toContain('[REDACTED]');\n"
        "});\n",
        encoding="utf-8",
    )

    changed = [
        "ai/gateway.test.ts",
        "ai/redaction.ts",
        "ai/gateway.ts",
        "audit/git-dirty-state.ts",
        "brain/binding.ts",
    ]
    ordered = prioritize_repo_files(changed)
    assert ordered.index("ai/redaction.ts") < ordered.index("ai/gateway.test.ts")

    facts = extract_polyglot_file_facts(tmp_path, ["ai/gateway.ts"])
    assert "url_parsing" in facts["ai/gateway.ts"]["implemented_guards_in_full_file"]
    assert "https_enforcement" in facts["ai/gateway.ts"]["implemented_guards_in_full_file"]

    guards = await run_deterministic_code_guards(tmp_path, changed)
    rule_ids = {f["rule_id"] for f in guards["findings"]}
    assert "AUTH-SCHEME-REDACTION-BYPASS" in rule_ids
    assert "SSRF-MISSING-PRIVATE-IP-FILTER" in rule_ids

    # 3. Cross-file test-import mapper sees indirect tests vs mocked-only modules
    tmap = build_test_coverage_map(tmp_path, changed)
    src_map = tmap["source_file_test_map"]
    assert src_map["audit/git-dirty-state.ts"]["has_any_unmocked_test"] is True
    assert "audit/git-revision.test.ts" in src_map["audit/git-dirty-state.ts"]["indirect_importing_tests"]
    assert "ai/gateway.test.ts" in src_map["ai/redaction.ts"]["indirect_importing_tests"]
    assert src_map["brain/binding.ts"]["coverage_status"] == "mocked_only_untested"

    # 4. Test fixture secret classifier & harness noise rejection work deterministically
    assert is_test_fixture_hit(tmp_path, "ai/gateway.test.ts", 5, 'api_key="REDACTED"') is True
    assert _is_harness_noise(
        {"title": "Test-runner mismatch: zero tests executed", "evidence": "No Python test files discovered"},
        {"test_runner": "static_js_ts_inspection"},
    ) is not None


@pytest.mark.asyncio
async def test_stop_review_cancellation_prevents_wasted_tokens(tmp_path: Path, monkeypatch):
    import asyncio

    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    db_file = tmp_path / "test_stop.db"
    test_engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}", connect_args={"check_same_thread": False})
    test_session_maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    import app.database.session as db_sess
    import app.orchestration.coordinator as coord_mod
    from app.agents.llm_factory import run_structured_agent
    from app.database.session import Base, get_db
    from app.main import app
    from app.models.tables import AgentRun, CodeChange, Repository, Review, User
    from app.orchestration.cancellation import (
        ReviewCancelledError,
        cancel_review_execution,
        clear_review_cancelled,
        register_review_task,
        review_id_var,
    )
    from app.orchestration.shared_state import AgentExecutionConfig

    monkeypatch.setattr(db_sess, "engine", test_engine)
    monkeypatch.setattr(db_sess, "async_session_maker", test_session_maker)
    monkeypatch.setattr(coord_mod, "async_session_maker", test_session_maker)

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async def override_get_db():
        async with test_session_maker() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    review_id = ""

    try:
        # 1. Seed a running review with 1 completed agent and 1 active/running agent
        async with test_session_maker() as db:
            user = User(email="workspace@reviewboard.local", name="Dev", password_hash="x")
            db.add(user)
            await db.flush()
            repo = Repository(user_id=user.id, name="repo", owner="org", full_name="org/repo", source_type="local")
            db.add(repo)
            await db.flush()
            cc = CodeChange(
                repository_id=repo.id,
                source_mode="local_diff",
                base_branch="main",
                target_branch="working_tree",
                base_commit="11111111",
                target_commit="22222222",
                diff_text="diff --git a/a.py b/a.py\n+x=1\n",
            )
            db.add(cc)
            await db.flush()
            rev = Review(
                repository_id=repo.id,
                code_change_id=cc.id,
                triggered_by="test",
                base_commit="11111111",
                target_commit="22222222",
                review_status="running",
                recommendation="Pending",
            )
            db.add(rev)
            await db.flush()
            db.add(
                AgentRun(
                    review_id=rev.id,
                    agent_name="diff_agent",
                    agent_label="Diff Agent",
                    model_used="deepseek-flash",
                    status="completed",
                )
            )
            db.add(
                AgentRun(
                    review_id=rev.id,
                    agent_name="security_agent",
                    agent_label="Security Agent",
                    model_used="deepseek-v4-pro",
                    status="running",
                )
            )
            await db.commit()
            review_id = rev.id

        # Simulate active background review task that awaits cancellation
        started = asyncio.Event()
        cancelled_observed = asyncio.Event()

        async def _fake_running_job():
            tok = review_id_var.set(review_id)
            try:
                started.set()
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled_observed.set()
                raise
            finally:
                review_id_var.reset(tok)

        bg_task = asyncio.create_task(_fake_running_job())
        register_review_task(review_id, bg_task)
        await started.wait()

        # 2. Stop endpoint cancels background task & marks running runs stopped (preserving completed)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post(f"/api/reviews/{review_id}/stop")
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "stopped"
            assert data["stopped"] is True

            missing = await client.post("/api/reviews/nonexistent-id/stop")
            assert missing.status_code == 404

        await asyncio.wait_for(cancelled_observed.wait(), timeout=2.0)

        # 3. Attempting an LLM call under a cancelled review aborts BEFORE spending tokens
        tok = review_id_var.set(review_id)
        try:
            with pytest.raises(ReviewCancelledError):
                await run_structured_agent(
                    AgentExecutionConfig(
                        agent_name="reviewer_manager",
                        label="Reviewer Manager",
                        model="deepseek-v4-pro",
                        base_url="https://api.deepseek.com",
                        api_key="sk-test-never-called",
                    ),
                    system_prompt="sys",
                    user_prompt="usr",
                )
        finally:
            review_id_var.reset(tok)

        # Verify DB state updated cleanly
        async with test_session_maker() as db:
            rev_row = (await db.execute(select(Review).where(Review.id == review_id))).scalar_one()
            assert rev_row.review_status == "stopped"
            assert rev_row.recommendation == "Incomplete"
            runs = {
                r.agent_name: r.status
                for r in (await db.execute(select(AgentRun).where(AgentRun.review_id == review_id))).scalars().all()
            }
            assert runs["diff_agent"] == "completed"
            assert runs["security_agent"] == "stopped"

        # 4. Leave Task deletes stopped review & cascaded rows cleanly
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            del_res = await client.delete(f"/api/reviews/{review_id}")
            assert del_res.status_code == 200
            assert del_res.json()["deleted"] is True
            check_res = await client.get(f"/api/reviews/{review_id}")
            assert check_res.status_code == 404
    finally:
        await cancel_review_execution(review_id)
        clear_review_cancelled(review_id)
        app.dependency_overrides.clear()
        await test_engine.dispose()




def test_audit_hardening_git_refs_paths_urls_and_patch_assembly(tmp_path: Path):
    from pydantic import ValidationError

    from app.agents.fix_suggestion_agent import _assemble_corrected_file
    from app.api.settings import UpdateAgentLLMConfigRequest
    from app.services.git_workspace import is_excluded_path, resolve_within_dir, validate_git_ref

    # 1. Git flag injection & traversal guards
    assert validate_git_ref("main") == "main"
    assert validate_git_ref("feature/v1.2_fix") == "feature/v1.2_fix"
    for bad_ref in ("--upload-pack=id", "-c", "main..evil", "HEAD@{0}", "ref with space", ""):
        with pytest.raises(ValueError):
            validate_git_ref(bad_ref)

    assert is_excluded_path("../etc/passwd") is True
    assert is_excluded_path(".git/config") is True
    assert resolve_within_dir(tmp_path, "../escape.py") is None
    assert resolve_within_dir(tmp_path, "src/app.py") == (tmp_path / "src" / "app.py").resolve()

    # 2. HTTP scheme validation on settings base_url
    valid_cfg = UpdateAgentLLMConfigRequest(model="deepseek-flash", base_url="https://api.deepseek.com")
    assert valid_cfg.base_url == "https://api.deepseek.com"
    with pytest.raises(ValidationError):
        UpdateAgentLLMConfigRequest(model="deepseek-flash", base_url="file:///etc/passwd")

    # 3. _assemble_corrected_file preserves surrounding lines cleanly across window ranges
    lines = ["line1\n", "line2\n", "line3\n", "line4\n"]
    assembled = _assemble_corrected_file(lines, window_start=2, window_end=3, total_lines=4, snippet="fixed2\nfixed3")
    assert assembled == "line1\nfixed2\nfixed3\nline4\n"


@pytest.mark.asyncio
async def test_batch_commit_all_patches_to_github(tmp_path: Path, monkeypatch):
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    from app.database.session import Base, get_db
    from app.integrations.github_client import GitHubClient
    from app.main import app
    from app.models.tables import CodeChange, PatchSuggestion, Repository, Review, User

    db_url = f"sqlite+aiosqlite:///{tmp_path / 'batch_patches.db'}"
    test_engine = create_async_engine(db_url, echo=False)
    test_session_maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_maker() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    async def fake_resolve_token(_user_id: str, _db: AsyncSession) -> str:
        return "ghp_test_token_1234567890"

    async def fake_get_file_content(self, owner: str, repo: str, path: str, ref: str) -> tuple[str, str]:
        if path == "src/stale.py":
            return "upstream modified content\n", "sha_stale"
        return f"orig {path}\n", f"sha_{path}"

    committed_calls: list[dict] = []

    async def fake_commit_file_update(
        self, owner: str, repo: str, *, path: str, branch: str, message: str, new_content: str, file_sha: str
    ) -> dict:
        committed_calls.append({"path": path, "branch": branch, "message": message})
        return {"commit": {"sha": f"commit_sha_{len(committed_calls)}"}}

    monkeypatch.setattr("app.api.patches.resolve_github_token", fake_resolve_token)
    monkeypatch.setattr(GitHubClient, "get_file_content", fake_get_file_content)
    monkeypatch.setattr(GitHubClient, "commit_file_update", fake_commit_file_update)

    try:
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        base_t = datetime.now(UTC)
        async with test_session_maker() as db:
            user = User(email="workspace@reviewboard.local", name="Dev", password_hash="x")
            db.add(user)
            await db.flush()
            repo = Repository(
                user_id=user.id,
                source_type="github",
                full_name="owner/demo",
                owner="owner",
                name="demo",
                default_branch="main",
            )
            db.add(repo)
            await db.flush()
            cc = CodeChange(
                repository_id=repo.id,
                source_mode="github_commit",
                base_branch="abc12345",
                target_branch="def67890",
                base_commit="abc12345" * 5,
                target_commit="def67890" * 5,
                diff_text="diff",
            )
            db.add(cc)
            await db.flush()
            rev = Review(
                repository_id=repo.id,
                code_change_id=cc.id,
                base_commit=cc.base_commit,
                target_commit=cc.target_commit,
                review_status="completed",
                recommendation="Request Changes",
            )
            db.add(rev)
            await db.flush()

            p_newer = PatchSuggestion(
                review_id=rev.id,
                file_path="src/a.py",
                title="Fix A (newest)",
                original_code="orig src/a.py\n",
                proposed_code="fixed src/a.py\n",
                unified_diff="diff",
                explanation="fix",
                applicability_verified=True,
                approval_status="pending_approval",
                created_at=base_t + timedelta(seconds=10),
            )
            p_older_same_file = PatchSuggestion(
                review_id=rev.id,
                file_path="src/a.py",
                title="Fix A (older duplicate)",
                original_code="orig src/a.py\n",
                proposed_code="older fixed src/a.py\n",
                unified_diff="diff",
                explanation="old fix",
                applicability_verified=True,
                approval_status="approved",
                created_at=base_t + timedelta(seconds=1),
            )
            p_approved_b = PatchSuggestion(
                review_id=rev.id,
                file_path="src/b.py",
                title="Fix B",
                original_code="orig src/b.py\n",
                proposed_code="fixed src/b.py\n",
                unified_diff="diff",
                explanation="fix b",
                applicability_verified=True,
                approval_status="approved",
                created_at=base_t + timedelta(seconds=8),
            )
            p_stale = PatchSuggestion(
                review_id=rev.id,
                file_path="src/stale.py",
                title="Fix Stale",
                original_code="orig src/stale.py\n",
                proposed_code="fixed src/stale.py\n",
                unified_diff="diff",
                explanation="stale",
                applicability_verified=True,
                approval_status="pending_approval",
                created_at=base_t + timedelta(seconds=5),
            )
            p_already_applied = PatchSuggestion(
                review_id=rev.id,
                file_path="src/done.py",
                title="Already Applied",
                original_code="orig src/done.py\n",
                proposed_code="fixed src/done.py\n",
                unified_diff="diff",
                explanation="done",
                applicability_verified=True,
                approval_status="applied",
                created_at=base_t + timedelta(seconds=9),
            )
            db.add_all([p_newer, p_older_same_file, p_approved_b, p_stale, p_already_applied])
            await db.commit()
            id_newer, id_b, id_stale = p_newer.id, p_approved_b.id, p_stale.id

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/api/patches/commit-all-github", json={})
            assert res.status_code == 200
            data = res.json()
            assert data["committed_count"] == 2
            assert data["skipped_count"] == 1
            assert data["failed_count"] == 1
            assert all(c["branch"] == "main" for c in data["committed"])
            assert {c["patch_id"] for c in data["committed"]} == {id_newer, id_b}
            assert data["errors"][0]["patch_id"] == id_stale

        async with test_session_maker() as db:
            rows = {
                p.id: p
                for p in (await db.execute(select(PatchSuggestion))).scalars().all()
            }
            assert rows[id_newer].approval_status == "applied"
            assert rows[id_b].approval_status == "applied"
            assert rows[id_stale].approval_status == "pending_approval"
    finally:
        app.dependency_overrides.clear()
        await test_engine.dispose()




def test_policy_matrix_six_agents_and_suggestion_hunk(tmp_path: Path):
    from app.api.patches import _extract_suggestion_hunk

    state = ReviewState(
        review_id="r-matrix",
        repository_id="repo-m",
        repository_name="org/repo",
        source_type="github",
        base_commit="abc",
        target_commit="def",
        workspace_dir=tmp_path,
        diff_text="",
        changed_files=[],
        policy={
            "block_on_critical": True,
            "block_on_high": True,
            "require_tests_pass": True,
            "require_all_mandatory_scans": True,
        },
        agent_configs={},
    )
    all_six_completed = [
        {"agent_name": "diff_agent", "agent_label": "Diff Agent", "status": "completed", "tool_results": {}},
        {"agent_name": "style_agent", "agent_label": "Style Agent", "status": "completed", "tool_results": {}},
        {"agent_name": "security_agent", "agent_label": "Security Agent", "status": "completed", "tool_results": {}},
        {
            "agent_name": "test_coverage_agent",
            "agent_label": "Test-Coverage Agent",
            "status": "completed",
            "tool_results": {"failed": 0},
        },
        {"agent_name": "reviewer_manager", "agent_label": "Reviewer Manager", "status": "completed", "tool_results": {}},
        {
            "agent_name": "fix_suggestion_agent",
            "agent_label": "Fix-Suggestion Agent",
            "status": "completed",
            "tool_results": {},
        },
    ]

    # Priority 4: All 6 completed cleanly, 0 blockers -> Approve
    rec_ok, _, _ = _evaluate_review_policy(state, [], all_six_completed)
    assert rec_ok == "Approve"

    # Priority 1: Stage-6 Fix-Suggestion Agent incomplete/failed -> Incomplete
    fix_failed = [*all_six_completed[:-1], {**all_six_completed[-1], "status": "incomplete"}]
    rec_fix_inc, reason_fix_inc, _ = _evaluate_review_policy(state, [], fix_failed)
    assert rec_fix_inc == "Incomplete"
    assert "Fix-Suggestion Agent" in reason_fix_inc

    # Priority 1: Stopped operation -> Incomplete regardless of findings
    stopped = [{**all_six_completed[0], "status": "stopped"}, *all_six_completed[1:]]
    rec_stop, reason_stop, _ = _evaluate_review_policy(state, [], stopped)
    assert rec_stop == "Incomplete"
    assert "Stopped by user" in reason_stop

    # Priority 2: Test suite failed -> Request Changes
    tests_failed = [
        *all_six_completed[:3],
        {**all_six_completed[3], "tool_results": {"failed": 2}},
        *all_six_completed[4:],
    ]
    rec_tests, reason_tests, _ = _evaluate_review_policy(state, [], tests_failed)
    assert rec_tests == "Request Changes"
    assert "2 failing test" in reason_tests

    # Bounded GitHub PR suggestion hunk replaces only changed lines instead of full file
    orig = "line1\nconst re = /abc/def/;\nline3\nline4\n"
    prop = "line1\nconst re = /abcdef/;\nline3\nline4\n"
    start_l, end_l, snippet = _extract_suggestion_hunk(orig, prop, fallback_line=2)
    assert start_l is None
    assert end_l == 2
    assert snippet == "const re = /abcdef/;"


@pytest.mark.asyncio
async def test_local_full_codebase_policy_clearing_and_repo_toggle(tmp_path: Path, monkeypatch):
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    import app.database.session as db_sess
    import app.orchestration.coordinator as coord_mod
    from app.config import get_settings
    from app.database.session import Base, get_db
    from app.main import app

    db_file = tmp_path / "test_full_local.db"
    test_engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}", connect_args={"check_same_thread": False})
    test_session_maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    monkeypatch.setattr(db_sess, "engine", test_engine)
    monkeypatch.setattr(db_sess, "async_session_maker", test_session_maker)
    monkeypatch.setattr(coord_mod, "async_session_maker", test_session_maker)
    monkeypatch.setenv("WORKSPACE_DIR", str(tmp_path / "ws"))
    get_settings.cache_clear()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async def override_get_db():
        async with test_session_maker() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    # Prevent background execution loop while still verifying seeded DB records
    launched: list[str] = []
    monkeypatch.setattr("app.api.reviews.launch_review_job", lambda rid: launched.append(rid))

    repo_dir = tmp_path / "local_proj"
    repo_dir.mkdir()
    await _arun_git("init", cwd=repo_dir)
    await _arun_git("config", "user.email", "dev@example.com", cwd=repo_dir)
    await _arun_git("config", "user.name", "Dev", cwd=repo_dir)
    (repo_dir / "main.py").write_text("def hello() -> str:\n    return 'ok'\n", encoding="utf-8")
    await _arun_git("add", ".", cwd=repo_dir)
    await _arun_git("commit", "-m", "initial", cwd=repo_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # 1. Verify policy excluded_paths can be cleared to empty list cleanly
            put_res = await client.put(
                "/api/settings/policy",
                json={
                    "block_on_critical": True,
                    "block_on_high": True,
                    "require_tests_pass": True,
                    "require_all_mandatory_scans": True,
                    "enable_test_execution": True,
                    "auto_publish_github_review": False,
                    "excluded_paths": [],
                },
            )
            assert put_res.status_code == 200
            pol_res = await client.get("/api/settings/policy")
            assert pol_res.json()["policy"]["excluded_paths"] == []

            # 2. Register clean local repo and toggle auto_review_webhooks
            conn_resp = await client.post(
                "/api/repositories/local",
                json={"local_path": str(repo_dir), "name": "local_proj"},
            )
            assert conn_resp.status_code == 200
            repo_id = conn_resp.json()["repository"]["id"]

            patch_res = await client.patch(
                f"/api/repositories/{repo_id}",
                json={"auto_review_webhooks": False},
            )
            assert patch_res.status_code == 200
            assert patch_res.json()["repository"]["auto_review_webhooks"] is False

            # 3. Full Codebase Audit on clean local repo succeeds even with zero dirty changes
            sub_res = await client.post(
                "/api/reviews",
                json={"repository_id": repo_id, "full_codebase": True},
            )
            assert sub_res.status_code == 201
            rev_id = sub_res.json()["review_id"]
            assert launched == [rev_id]

            detail = (await client.get(f"/api/reviews/{rev_id}")).json()
            assert detail["code_change"]["source_mode"] == "local_full_repo"
            assert "main.py" in detail["code_change"]["file_snapshots"]
            assert len(detail["agent_runs"]) == 6
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
        await test_engine.dispose()




@pytest.mark.asyncio
async def test_p0_evidence_guard_blocks_fabrication_and_gates_patches(tmp_path: Path):
    from app.agents.fix_suggestion_agent import _select_target_findings, _validate_patch_bundle
    from app.verification.evidence_guard import (
        build_evidence_store,
        is_patch_eligible,
        verify_finding_provenance,
    )

    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)
    target_file = src_dir / "auth.py"
    target_file.write_text(
        "def safe_header() -> str:\n"
        "    return 'ok'\n\n\n"
        "def run_unsafe(cmd: str):\n"
        "    import subprocess\n"
        "    # line 7\n"
        "    # line 8\n"
        "    # line 9\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )

    sec_out = AgentExecutionOutput(
        agent_name="security_agent",
        agent_label="Security Agent",
        model_used="deepseek-v4-pro",
        status="completed",
        summary="Bandit scan completed.",
        tool_results={
            "bandit": {
                "status": "completed",
                "findings": [
                    {
                        "tool": "bandit",
                        "rule_id": "B602",
                        "file_path": "src/auth.py",
                        "line_number": 10,
                        "severity": "High",
                        "evidence": "subprocess.run(cmd, shell=True)",
                        "title": "subprocess call with shell=True",
                    }
                ],
            }
        },
    )

    records, extras = build_evidence_store([sec_out], tmp_path, "deadbeef")
    assert len(records) == 1
    assert records[0].evidence_id == "EV-001"
    assert len(extras["evidence_store"]) == 1

    # 1. Fabricated tool claim pointing at unrelated line 2 cannot self-certify Verified
    fabricated_claim = {
        "agent": "Security Agent",
        "severity": "High",
        "title": "Fake bandit claim",
        "file_path": "src/auth.py",
        "line_number": 2,
        "tool_name": "bandit",
        "rule_id": "B602",
        "verification_status": "Verified",
        "confidence": 0.99,
    }
    res_fab, is_fab = verify_finding_provenance(fabricated_claim, records, tmp_path)
    assert is_fab is True
    assert res_fab["verification_status"] == "Needs Verification"
    assert res_fab["tool_name"] == "llm-review"
    assert res_fab["evidence_ids"] == []

    # 2. Missing file -> Unverified
    missing_claim = {
        "agent": "Security Agent",
        "severity": "High",
        "title": "Ghost file",
        "file_path": "src/nonexistent.py",
        "line_number": 5,
        "tool_name": "bandit",
    }
    res_miss, is_miss_fab = verify_finding_provenance(missing_claim, records, tmp_path)
    assert is_miss_fab is True
    assert res_miss["verification_status"] == "Unverified"
    assert res_miss["evidence_ids"] == []

    # 3. Real deterministic match -> Verified + EV-001 + confidence preserved
    real_claim = {
        "agent": "Security Agent",
        "severity": "High",
        "title": "subprocess call with shell=True",
        "file_path": "src/auth.py",
        "line_number": 10,
        "tool_name": "bandit",
        "rule_id": "B602",
        "verification_status": "Needs Verification",
        "confidence": 0.92,
    }
    res_real, is_real_fab = verify_finding_provenance(real_claim, records, tmp_path)
    assert is_real_fab is False
    assert res_real["verification_status"] == "Verified"
    assert res_real["evidence_ids"] == ["EV-001"]
    assert res_real["confidence"] == 0.92

    # 4. Patch selection strictly gates on Verified + non-empty evidence_ids
    verified_no_ev = {
        "severity": "High",
        "file_path": "src/auth.py",
        "verification_status": "Verified",
        "evidence_ids": [],
    }
    assert is_patch_eligible(verified_no_ev) is False
    assert is_patch_eligible(res_fab) is False
    assert is_patch_eligible(res_real) is True

    selected = _select_target_findings(tmp_path, [res_fab, verified_no_ev, res_real], max_patches=5)
    assert len(selected) == 1
    assert selected[0][1]["evidence_ids"] == ["EV-001"]

    # 5. Patch bundle security-guard recheck blocks patches introducing new High/Critical guard risks
    clean_file = tmp_path / "src" / "clean.ts"
    clean_file.write_text("export function runSafe(name: string): string {\n  return name.trim();\n}\n", encoding="utf-8")
    unsafe_proposed = "import { execSync } from 'node:child_process';\nexport function runSafe(name: string): string {\n  return String(execSync(`cat ${name}`));\n}\n"
    diff_bad = _compute_unified_diff("src/clean.ts", clean_file.read_text(encoding="utf-8"), unsafe_proposed)
    combined_ok, _apply_ok, _syntax_ok, val_msg = await _validate_patch_bundle(
        tmp_path, "src/clean.ts", unsafe_proposed, diff_bad
    )
    assert combined_ok is False
    assert "security/taint" in val_msg.lower()


def test_p1_stair_hierarchical_retrieval_finds_deep_symbol_and_caller(tmp_path: Path):
    from app.intelligence.context_builder import build_agent_context
    from app.intelligence.structure_indexer import build_structure_index

    pkg_dir = tmp_path / "pkg"
    tests_dir = tmp_path / "tests"
    pkg_dir.mkdir(parents=True)
    tests_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").write_text("", encoding="utf-8")

    # Build a >420-line module so linear truncation from line 1 would completely miss process_payment
    filler_lines = [
        f"def filler_helper_{i:03d}(x: int) -> int:\n    return x + {i}\n\n"
        for i in range(1, 135)
    ]
    deep_offset = sum(s.count("\n") for s in filler_lines) + 1
    deep_func = (
        "from pkg.auth_utils import verify_token\n\n"
        "def process_payment(token: str, amount: float) -> bool:\n"
        "    if not verify_token(token):\n"
        "        return False\n"
        "    return amount > 0\n"
    )
    (pkg_dir / "service.py").write_text("".join(filler_lines) + deep_func, encoding="utf-8")
    (pkg_dir / "auth_utils.py").write_text(
        "def verify_token(token: str) -> bool:\n    return len(token) > 10\n",
        encoding="utf-8",
    )
    (pkg_dir / "routes.py").write_text(
        "from pkg.service import process_payment\n\n"
        "def handle_checkout(token: str) -> bool:\n"
        "    return process_payment(token, 42.0)\n",
        encoding="utf-8",
    )
    (tests_dir / "test_service.py").write_text(
        "from pkg.service import process_payment\n\n"
        "def test_process_payment():\n"
        "    assert process_payment('valid-secret-token', 10.0) is True\n",
        encoding="utf-8",
    )

    changed_line = deep_offset + 3
    changed = [{"path": "pkg/service.py", "changed_lines": [changed_line], "additions": 2, "deletions": 0}]
    index = build_structure_index(tmp_path, changed)

    assert index["files_indexed"] >= 4
    assert "pkg/service.py::process_payment" in index["symbol_by_id"]

    ctx = build_agent_context(
        role="security_agent",
        workspace_dir=tmp_path,
        structure_index=index,
        changed_files=changed,
        token_budget=2500,
    )
    assert ctx["fallback_used"] is False
    assert ctx["token_estimate"] <= ctx["token_budget"]
    assert "process_payment" in ctx["context_text"]
    assert any(sl["file_path"] == "pkg/service.py" and sl["start_line"] > 350 for sl in ctx["selected_slices"])
    assert "verify_token" in ctx["context_text"] or "handle_checkout" in ctx["context_text"]


@pytest.mark.asyncio
async def test_p2_incremental_cache_contract_and_invalidation(tmp_path: Path):
    from app.cache.review_cache import ReviewCache, compute_cache_key, hash_config_dict
    from app.scanners.style_tools import run_style_scanners

    sample = tmp_path / "mod.py"
    sample.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    cache = ReviewCache(tmp_path / "_cache")
    cfg1 = hash_config_dict({"strict": True})
    cfg2 = hash_config_dict({"strict": False})

    # 1. Cold run misses and populates cache
    first = await run_style_scanners(
        tmp_path, ["mod.py"], cache=cache, commit_context="c1..c2", config_hash=cfg1
    )
    assert first["cache_hit"] is False
    assert cache.stats.writes == 1

    # 2. Identical inputs -> deterministic cache hit
    second = await run_style_scanners(
        tmp_path, ["mod.py"], cache=cache, commit_context="c1..c2", config_hash=cfg1
    )
    assert second["cache_hit"] is True
    assert cache.stats.hits >= 1

    # 3. File content change -> cache miss (invalidation)
    sample.write_text("import os\ndef add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    third = await run_style_scanners(
        tmp_path, ["mod.py"], cache=cache, commit_context="c1..c2", config_hash=cfg1
    )
    assert third["cache_hit"] is False

    # 4. Configuration hash change -> cache miss
    fourth = await run_style_scanners(
        tmp_path, ["mod.py"], cache=cache, commit_context="c1..c2", config_hash=cfg2
    )
    assert fourth["cache_hit"] is False

    # 5. Commit context change -> cache miss
    fifth = await run_style_scanners(
        tmp_path, ["mod.py"], cache=cache, commit_context="c2..c3", config_hash=cfg2
    )
    assert fifth["cache_hit"] is False

    # 6. Tool version bump changes key deterministically
    k1 = compute_cache_key(content_hash="abc", tool_version="v1", configuration_hash=cfg1, commit_context="c1")
    k2 = compute_cache_key(content_hash="abc", tool_version="v2", configuration_hash=cfg1, commit_context="c1")
    assert k1 != k2


@pytest.mark.asyncio
async def test_p3_central_review_planner_and_workflow_dispatch(tmp_path: Path):
    from app.config import AGENT_METADATA
    from app.orchestration.fanout_fanin import CoordinatorDispatcher
    from app.orchestration.shared_state import AgentExecutionConfig
    from app.planning.review_planner import build_review_plan
    from app.scanners.security_tools import run_security_scanners
    from app.scanners.style_tools import run_style_scanners
    from app.scanners.test_tools import run_test_and_coverage

    # 1. Docs-only diff -> low risk + selective skip_scanners (without Incomplete policy verdict)
    docs_plan = build_review_plan(
        changed_files=[{"path": "README.md", "additions": 12, "deletions": 2}],
        diff_text="+# Updated docs\n",
    )
    assert docs_plan["risk_tier"] == "low"
    assert docs_plan["docs_only"] is True
    assert docs_plan["agent_plans"]["security_agent"]["skip_scanners"] is True

    sec_skip = await run_security_scanners(
        tmp_path, ["README.md"], plan=docs_plan["agent_plans"]["security_agent"]
    )
    style_skip = await run_style_scanners(
        tmp_path, ["README.md"], plan=docs_plan["agent_plans"]["style_agent"]
    )
    test_skip = await run_test_and_coverage(
        tmp_path, ["README.md"], plan=docs_plan["agent_plans"]["test_coverage_agent"]
    )
    assert sec_skip["bandit"]["status"] == "skipped_by_plan"
    assert style_skip["ruff"]["status"] == "skipped_by_plan"
    assert test_skip["status"] == "skipped_by_plan"

    # 2. High-risk auth diff -> high tier + expanded security budget
    auth_plan = build_review_plan(
        changed_files=[{"path": "backend/auth/jwt_middleware.py", "additions": 35, "deletions": 8}],
        diff_text="+subprocess.run(cmd, shell=True)\n+jwt.decode(tok)\n",
    )
    assert auth_plan["risk_tier"] == "high"
    assert auth_plan["touches_auth_or_api"] is True
    assert auth_plan["agent_plans"]["security_agent"]["token_budget"] > 5000

    # 3. CoordinatorDispatcher populates STAIR structure_index, review_plan, and cache_stats
    (tmp_path / "README.md").write_text("# Swarm Guide\n", encoding="utf-8")
    events: list[tuple[str, str, dict[str, object]]] = []

    async def _emit(rid: str, ev: str, payload: dict[str, object]) -> None:
        events.append((rid, ev, payload))

    class _CaptureExecutor(Executor):
        def __init__(self) -> None:
            super().__init__(id="capture")

        @handler
        async def capture(self, state: ReviewState, ctx: WorkflowContext[ReviewState, ReviewState]) -> None:
            await ctx.yield_output(state)

    dispatcher = CoordinatorDispatcher(_emit)
    cap = _CaptureExecutor()
    wf = WorkflowBuilder(start_executor=dispatcher).add_edge(dispatcher, cap).build()

    configs = {
        k: AgentExecutionConfig(
            agent_name=k,
            label=m["label"],
            model=m["default_model"],
            base_url="https://api.deepseek.com",
            api_key="",
        )
        for k, m in AGENT_METADATA.items()
    }
    init_state = ReviewState(
        review_id="rev-p3-dispatch",
        repository_id="repo-1",
        repository_name="demo/docs",
        source_type="local",
        base_commit="HEAD~1",
        target_commit="HEAD",
        workspace_dir=tmp_path,
        diff_text="+# Swarm Guide\n",
        changed_files=[{"path": "README.md", "status": "modified", "additions": 1, "deletions": 0}],
        policy={},
        agent_configs=configs,
        cache_dir=tmp_path / "_cache",
    )
    out = (await wf.run(init_state)).get_outputs()[-1]
    assert out.structure_index["files_indexed"] >= 1
    assert out.review_plan["risk_tier"] == "low"
    assert "writes" in out.cache_stats
    assert any(ev == "fan_out_started" for _, ev, _ in events)


@pytest.mark.asyncio
async def test_p4_permissions_and_cross_agent_contradictions(tmp_path: Path):
    from app.skills.permissions import AGENT_CAPABILITY_REGISTRY
    from app.verification.evidence_guard import (
        EvidenceRecord,
        detect_cross_agent_contradictions,
        normalize_severity_with_criteria,
        verify_finding_provenance,
    )

    assert AGENT_CAPABILITY_REGISTRY["fix_suggestion_agent"].can_propose_patches is True
    for k, cap in AGENT_CAPABILITY_REGISTRY.items():
        assert cap.can_commit_directly is False
        assert cap.can_self_certify_verified is False
        if k != "fix_suggestion_agent":
            assert cap.can_propose_patches is False

    (tmp_path / "mod.py").write_text("def x():\n    return 1\n", encoding="utf-8")
    recs = [
        EvidenceRecord(
            evidence_id="EV-001",
            tool_name="pytest",
            rule_id="TEST-PASS",
            file_path="mod.py",
            line_number=1,
            end_line=2,
            commit_sha="HEAD",
            source_hash="abcd",
            snippet="ok",
            severity="Low",
        )
    ]

    # Diff Agent cannot verify test execution even if claiming tool/pass
    fake_test_claim = {
        "agent": "Diff Agent",
        "title": "Tests passed cleanly",
        "description": "I ran tests and verified all unit tests executed cleanly.",
        "file_path": "mod.py",
        "line_number": 1,
        "tool_name": "pytest",
        "verification_status": "Verified",
    }
    sanitized, flagged = verify_finding_provenance(
        fake_test_claim, recs, tmp_path, execution_telemetry={"runner": "pytest", "status": "completed"}
    )
    assert flagged is True
    assert sanitized["verification_status"] == "Needs Verification"
    assert sanitized["evidence_ids"] == []
    assert sanitized.get("permission_violations")

    # Test-Coverage Agent cannot verify runtime tests if runner was static_js_ts_inspection
    ts_fake_run = {
        "agent": "Test-Coverage Agent",
        "title": "Verified by test execution",
        "description": "Ran the tests and passed.",
        "file_path": "mod.py",
        "line_number": 1,
        "tool_name": "vitest",
        "verification_status": "Verified",
    }
    ts_san, ts_flag = verify_finding_provenance(
        ts_fake_run, recs, tmp_path, execution_telemetry={"runner": "static_js_ts_inspection", "status": "completed"}
    )
    assert ts_flag is True
    assert ts_san["verification_status"] == "Needs Verification"

    # Cross-agent contradiction & severity normalization
    contradictions = detect_cross_agent_contradictions(
        [
            {"agent": "Diff Agent", "file_path": "mod.py", "title": "Safe refactor"},
            {"agent": "Test-Coverage Agent", "file_path": "mod.py", "title": "Untested module - no tests found"},
        ],
        {"test_import_map": {"source_file_test_map": {"mod.py": {"has_any_unmocked_test": True, "coverage_status": "direct_tests_present"}}}},
    )
    assert len(contradictions) == 1
    assert normalize_severity_with_criteria({"rule_id": "TAINT-SQL-INJECTION", "severity": "Low"}) == "Critical"


@pytest.mark.asyncio
async def test_p4_diff_ast_semantic_api_contract_and_config_impact(tmp_path: Path):
    from app.intelligence.structure_indexer import build_structure_index
    from app.scanners.diff_engines import analyze_ast_and_contract_diff

    await _arun_git("init", cwd=tmp_path)
    await _arun_git("config", "user.email", "dev@example.com", cwd=tmp_path)
    await _arun_git("config", "user.name", "Dev", cwd=tmp_path)

    pkg = tmp_path / "src"
    pkg.mkdir()
    (pkg / "pure.py").write_text("def double_val(val: int) -> int:\n    res = val * 2\n    return res\n", encoding="utf-8")
    (pkg / "api.py").write_text("def compute_fee(amount: float) -> float:\n    return amount * 1.1\n", encoding="utf-8")
    (pkg / "caller.py").write_text("from src.api import compute_fee\ndef bill():\n    return compute_fee(10.0)\n", encoding="utf-8")
    await _arun_git("add", ".", cwd=tmp_path)
    await _arun_git("commit", "-m", "base", cwd=tmp_path)

    # Target edits: variable rename only in pure.py; API signature + env config change in api.py
    (pkg / "pure.py").write_text("def double_val(val: int) -> int:\n    out = val * 2\n    return out\n", encoding="utf-8")
    (pkg / "api.py").write_text(
        "import os\ndef compute_fee(amount: float, currency: str) -> float:\n"
        "    rate = float(os.getenv('FEE_RATE', '1.1'))\n    return amount * rate\n",
        encoding="utf-8",
    )

    changed = [
        {"path": "src/pure.py", "status": "modified", "changed_lines": [2, 3]},
        {"path": "src/api.py", "status": "modified", "changed_lines": [2, 3, 4]},
    ]
    index = build_structure_index(tmp_path, changed)
    ast_diff = await analyze_ast_and_contract_diff(
        tmp_path,
        base_commit="HEAD",
        target_commit="WORKING_TREE",
        changed_files=changed,
        structure_index=index,
    )
    assert ast_diff["semantic_counts"]["cosmetic_or_variable_renames"] >= 1
    assert ast_diff["semantic_counts"]["signature_or_contract_changes"] >= 1
    assert any(c["symbol"] == "compute_fee" for c in ast_diff["api_contract_changes"])
    assert any("os.getenv" in c["config_signals"] for c in ast_diff["config_and_dependency_impacts"])
    assert ast_diff["downstream_impact"]["src/api.py"]["blast_radius_count"] >= 1


@pytest.mark.asyncio
async def test_p4_style_dead_code_complexity_naming_and_token_saver(tmp_path: Path, monkeypatch):
    from app.agents.style_agent import StyleAgentExecutor
    from app.config import AGENT_METADATA
    from app.intelligence.structure_indexer import build_structure_index
    from app.orchestration.shared_state import AgentExecutionConfig
    from app.scanners.style_tools import run_style_scanners

    # Establish snake_case repo convention
    for idx in range(5):
        (tmp_path / f"util_{idx}.py").write_text(
            f"def snake_helper_{idx}(x: int) -> int:\n    return x + {idx}\n",
            encoding="utf-8",
        )

    many_imports = "\n".join(f"import mod_{i}" for i in range(16)) + "\n"
    long_body = "\n".join("    x += 1" for _ in range(62))
    (tmp_path / "legacy.py").write_text(
        many_imports
        + "def _unused_private():\n    return 1\n\n"
        + "def badCamelName(flag_a: bool, flag_b: bool, flag_c: bool, flag_d: bool) -> int:\n"
        + "    if flag_a:\n        if flag_b:\n            if flag_c:\n                if flag_d:\n                    return 42\n"
        + "    return 0\n    unreachable = 99\n\n"
        + f"def overly_long_fn(x: int) -> int:\n{long_body}\n    return x\n",
        encoding="utf-8",
    )

    changed = [{"path": "legacy.py", "status": "modified", "changed_lines": [18, 25]}]
    s_index = build_structure_index(tmp_path, changed)
    s_res = await run_style_scanners(tmp_path, ["legacy.py"], structure_index=s_index)
    ast_rules = {f["rule_id"] for f in s_res["ast_checks"]["findings"]}
    dead_rules = {f["rule_id"] for f in s_res["dead_code"]["findings"]}
    assert {"STYLE-HIGH-COUPLING", "STYLE-DEEP-NESTING", "STYLE-LONG-FUNCTION", "STYLE-NAMING-CONVENTION"} <= ast_rules
    assert {"DEAD-UNREACHABLE-CODE", "DEAD-UNUSED-PRIVATE-SYMBOL"} <= dead_rules

    # Verify Style Agent token-saver skips LLM when clean + API key present
    clean_ws = tmp_path / "clean_ws"
    clean_ws.mkdir()
    (clean_ws / "clean.py").write_text("def add_one(x: int) -> int:\n    return x + 1\n", encoding="utf-8")

    llm_calls = 0

    async def _fail_if_called(*_args, **_kwargs):
        nonlocal llm_calls
        llm_calls += 1
        return {"summary": "llm", "findings": []}

    monkeypatch.setattr("app.agents.style_agent.run_structured_agent", _fail_if_called)
    captured: list[AgentExecutionOutput] = []

    class _Sink(Executor):
        def __init__(self) -> None:
            super().__init__(id="sink")

        @handler
        async def take(self, msg: AgentExecutionOutput, ctx: WorkflowContext[AgentExecutionOutput]) -> None:
            captured.append(msg)

    async def _noop_emit(_rid: str, _ev: str, _pl: dict[str, object]) -> None:
        return None

    style_exec = StyleAgentExecutor(_noop_emit)
    sink = _Sink()
    wf = WorkflowBuilder(start_executor=style_exec).add_edge(style_exec, sink).build()
    configs = {
        k: AgentExecutionConfig(
            agent_name=k,
            label=m["label"],
            model=m["default_model"],
            base_url="https://api.deepseek.com",
            api_key="sk-test-key",
        )
        for k, m in AGENT_METADATA.items()
    }
    st = ReviewState(
        review_id="rev-style-saver",
        repository_id="r",
        repository_name="clean/repo",
        source_type="local",
        base_commit="HEAD~1",
        target_commit="HEAD",
        workspace_dir=clean_ws,
        diff_text="+def add_one(x: int) -> int: ...",
        changed_files=[{"path": "clean.py", "changed_lines": [1, 2]}],
        policy={},
        agent_configs=configs,
        cache_dir=clean_ws / "_cache",
    )
    await wf.run(st)
    assert llm_calls == 0
    assert captured and captured[0].status == "completed"
    assert captured[0].raw_output.get("llm_skipped_token_saver") is True


@pytest.mark.asyncio
async def test_p4_security_taint_authz_crypto_and_optional_scanners(tmp_path: Path):
    from app.intelligence.structure_indexer import build_structure_index
    from app.scanners.security_tools import run_security_scanners

    (tmp_path / "routes.py").write_text(
        "import hashlib\n"
        "import random\n"
        "import subprocess\n\n"
        "@router.post('/admin/run')\n"
        "def run_admin_action(cmd: str, fname: str, uid: str, conn):\n"
        "    tok = ''.join(random.choice('abcdef') for _ in range(8))\n"
        "    sig = hashlib.md5(tok.encode()).hexdigest()\n"
        "    conn.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
        "    data = open(fname).read()\n"
        "    return subprocess.run(cmd, shell=True), sig, data\n",
        encoding="utf-8",
    )
    s_idx = build_structure_index(tmp_path, [{"path": "routes.py", "changed_lines": [5, 9, 11]}])
    sec = await run_security_scanners(
        tmp_path,
        ["routes.py"],
        plan={"run_bandit": False, "run_semgrep": False, "run_gitleaks": False, "run_osv": False, "run_taint": True, "run_codeql": True, "run_trivy": True},
        structure_index=s_idx,
    )
    taint_rules = {f["rule_id"] for f in sec["taint_analysis"]["findings"]}
    assert {
        "AUTHZ-MISSING-ROUTE-GUARD",
        "CRYPTO-INSECURE-RANDOM",
        "CRYPTO-WEAK-HASH",
        "TAINT-SQL-INJECTION",
        "TAINT-PATH-TRAVERSAL",
        "TAINT-CMD-INJECTION",
    } <= taint_rules
    assert "api_endpoints" in sec["taint_analysis"]["threat_surfaces"]
    assert sec["codeql"]["status"] in ("optional_unavailable", "completed")
    assert sec["trivy"]["status"] in ("optional_unavailable", "completed")


@pytest.mark.asyncio
async def test_p4_test_impact_selection_triage_property_and_patch_sandbox(tmp_path: Path):
    from app.agents.fix_suggestion_agent import _validate_patch_bundle
    from app.intelligence.structure_indexer import build_structure_index
    from app.scanners.test_tools import run_test_and_coverage, triage_test_failure

    await _arun_git("init", cwd=tmp_path)
    await _arun_git("config", "user.email", "dev@example.com", cwd=tmp_path)
    await _arun_git("config", "user.name", "Dev", cwd=tmp_path)

    (tmp_path / "calc.py").write_text("def add_nums(a: int, b: int) -> int:\n    return a - b\n", encoding="utf-8")
    (tmp_path / "test_calc.py").write_text(
        "from calc import add_nums\ndef test_add_ok():\n    assert add_nums(5, 2) == 3\n",
        encoding="utf-8",
    )
    (tmp_path / "test_unrelated_fail.py").write_text(
        "def test_always_fails():\n    assert False\n",
        encoding="utf-8",
    )
    await _arun_git("add", ".", cwd=tmp_path)
    await _arun_git("commit", "-m", "init", cwd=tmp_path)

    # Impact-graph subset runs ONLY test_calc.py (skipping unrelated failing test!)
    idx = build_structure_index(tmp_path, [{"path": "calc.py", "changed_lines": [2]}])
    tres = await run_test_and_coverage(
        tmp_path,
        ["calc.py"],
        plan={"selective_test_mode": True},
        structure_index=idx,
    )
    assert tres["selection_mode"] == "impact_graph_subset"
    assert tres["selected_test_files"] == ["test_calc.py"]
    assert tres["passed"] == 1
    assert tres["failed"] == 0
    assert any(
        c["symbol"] == "add_nums" for c in tres["property_and_mutation"]["property_testing"]["candidates"]
    )
    assert tres["property_and_mutation"]["property_testing"]["executed"] is False

    # Failure triage categories
    assert triage_test_failure("ModuleNotFoundError: No module named 'foo'", 1)["category"] == "dependency_or_env_failure"
    assert triage_test_failure("FAILED test_x - AssertionError: 1 != 2", 1)["category"] == "code_assertion_failure"

    # Isolated patch validation: clean fix + valid regression test passes without touching workspace
    fixed_calc = "def add_nums(a: int, b: int) -> int:\n    return a + b\n"
    diff_fix = _compute_unified_diff("calc.py", (tmp_path / "calc.py").read_text(encoding="utf-8"), fixed_calc)
    reg_test_fail = "from calc import add_nums\ndef test_add_wrong():\n    assert add_nums(2, 3) == 999\n"
    bad_ok, _, _, bad_msg = await _validate_patch_bundle(
        tmp_path,
        "calc.py",
        fixed_calc,
        diff_fix,
        related_tests=[],
        regression_test_code=reg_test_fail,
    )
    assert bad_ok is False
    assert "targeted tests failed" in bad_msg.lower()

    reg_test_pass = "from calc import add_nums\ndef test_add_fixed():\n    assert add_nums(2, 3) == 5\n"
    good_ok, _, _, good_msg = await _validate_patch_bundle(
        tmp_path,
        "calc.py",
        fixed_calc,
        diff_fix,
        related_tests=[],
        regression_test_code=reg_test_pass,
    )
    assert good_ok is True
    assert "targeted tests passed" in good_msg.lower()
    # Original workspace remains completely clean (rollback safe!)
    assert "return a - b" in (tmp_path / "calc.py").read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_subagent_diff_token_saver_empty_tree_and_compact_telemetry(tmp_path: Path, monkeypatch):
    from app.agents.diff_agent import DiffAgentExecutor
    from app.config import AGENT_METADATA
    from app.orchestration.shared_state import AgentExecutionConfig

    await _arun_git("init", cwd=tmp_path)
    await _arun_git("config", "user.email", "dev@example.com", cwd=tmp_path)
    await _arun_git("config", "user.name", "Dev", cwd=tmp_path)

    mod = tmp_path / "mod.py"
    mod.write_text("def calc(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
    await _arun_git("add", ".", cwd=tmp_path)
    await _arun_git("commit", "-m", "initial commit", cwd=tmp_path)

    diff_patch = await _arun_git_out("show", "--format=", "HEAD", cwd=tmp_path)

    emitted: list[tuple[str, dict[str, object]]] = []

    async def _capture_emit(_rid: str, ev: str, pl: dict[str, object]) -> None:
        emitted.append((ev, pl))

    configs = {
        k: AgentExecutionConfig(
            agent_name=k,
            label=m["label"],
            model=m["default_model"],
            base_url="https://api.deepseek.com",
            api_key="sk-test-key",
        )
        for k, m in AGENT_METADATA.items()
    }

    async def _fake_diff_llm(*_args, **_kwargs):
        return {
            "summary": "Added calc helper.",
            "risk_tier": "medium",
            "key_focus_areas": ["mod.py"],
            "findings": [],
            "_token_usage": {"prompt_tokens": 90, "completion_tokens": 30, "total_tokens": 120},
        }

    monkeypatch.setattr("app.agents.diff_agent.run_structured_agent", _fake_diff_llm)

    class _StateSink(Executor):
        def __init__(self) -> None:
            super().__init__(id="state_sink")
            self.outputs: list[AgentExecutionOutput] = []

        @handler
        async def take(self, msg: AgentExecutionOutput, ctx: WorkflowContext[AgentExecutionOutput]) -> None:
            self.outputs.append(msg)

    diff_exec = DiffAgentExecutor(_capture_emit)
    sink = _StateSink()
    wf = WorkflowBuilder(start_executor=diff_exec).add_edge(diff_exec, sink).build()
    st_empty = ReviewState(
        review_id="rev-diff-empty-tree",
        repository_id="r1",
        repository_name="org/mod",
        source_type="local",
        base_commit="EMPTY_TREE",
        target_commit="HEAD",
        workspace_dir=tmp_path,
        diff_text=diff_patch,
        changed_files=[{"path": "mod.py", "status": "added", "changed_lines": [1, 2]}],
        policy={},
        agent_configs=configs,
        cache_dir=tmp_path / "_cache",
    )
    await wf.run(st_empty)
    assert sink.outputs
    tr_empty = sink.outputs[0].tool_results
    assert tr_empty["ast_diff"]["semantic_counts"]["added_symbols"] >= 1
    assert "polyglot_symbols" in tr_empty
    assert all("patch" not in f for f in tr_empty["files"])
    assert tr_empty.get("token_usage", {}).get("total_tokens") == 120
    completed_events = [pl for ev, pl in emitted if ev == "agent_completed"]
    assert completed_events and "tool_results" in completed_events[-1]

    # Pure doc-only edit triggers Diff Agent cosmetic token-saver without calling the LLM
    mod.write_text(
        'def calc(x: int) -> int:\n    """Increment by one."""\n    return x + 1\n',
        encoding="utf-8",
    )
    await _arun_git("add", ".", cwd=tmp_path)
    await _arun_git("commit", "-m", "docs docstring", cwd=tmp_path)
    cosmetic_patch = await _arun_git_out("diff", "HEAD~1", "HEAD", cwd=tmp_path)

    llm_calls = 0

    async def _fail_if_called(*_args, **_kwargs):
        nonlocal llm_calls
        llm_calls += 1
        return {"summary": "should not run", "risk_tier": "low", "findings": []}

    monkeypatch.setattr("app.agents.diff_agent.run_structured_agent", _fail_if_called)
    emitted.clear()
    diff_exec2 = DiffAgentExecutor(_capture_emit)
    sink2 = _StateSink()
    wf2 = WorkflowBuilder(start_executor=diff_exec2).add_edge(diff_exec2, sink2).build()
    st_cosmetic = ReviewState(
        review_id="rev-diff-cosmetic",
        repository_id="r1",
        repository_name="org/mod",
        source_type="local",
        base_commit="HEAD~1",
        target_commit="HEAD",
        workspace_dir=tmp_path,
        diff_text=cosmetic_patch,
        changed_files=[{"path": "mod.py", "status": "modified", "changed_lines": [2]}],
        policy={},
        agent_configs=configs,
        cache_dir=tmp_path / "_cache",
    )
    await wf2.run(st_cosmetic)
    assert llm_calls == 0
    assert sink2.outputs and sink2.outputs[0].tool_results["llm_skipped_token_saver"] is True


@pytest.mark.asyncio
async def test_subagent_reviewer_manager_token_saver_and_verified_retention(tmp_path: Path, monkeypatch):
    from app.agents.reviewer_manager import ReviewerManagerExecutor
    from app.config import AGENT_METADATA
    from app.orchestration.shared_state import AgentExecutionConfig
    from app.scanners.security_taint import run_taint_and_threat_analysis

    # 1. Router-level APIRouter(dependencies=[Depends(...)]) should not raise AUTHZ-MISSING-ROUTE-GUARD
    (tmp_path / "router_ok.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "def require_auth():\n    return True\n"
        "router = APIRouter(dependencies=[Depends(require_auth)])\n"
        "@router.post('/admin/sync')\n"
        "def sync_items():\n    return {'ok': True}\n",
        encoding="utf-8",
    )
    taint_ok = run_taint_and_threat_analysis(tmp_path, ["router_ok.py"])
    assert "AUTHZ-MISSING-ROUTE-GUARD" not in {f["rule_id"] for f in taint_ok["findings"]}

    configs = {
        k: AgentExecutionConfig(
            agent_name=k,
            label=m["label"],
            model=m["default_model"],
            base_url="https://api.deepseek.com",
            api_key="sk-test-key",
        )
        for k, m in AGENT_METADATA.items()
    }
    emitted: list[tuple[str, dict[str, object]]] = []

    async def _capture_emit(_rid: str, ev: str, pl: dict[str, object]) -> None:
        emitted.append((ev, pl))

    class _PassSink(Executor):
        def __init__(self) -> None:
            super().__init__(id="rm_sink")
            self.states: list[ReviewState] = []

        @handler
        async def take(self, msg: ReviewState, ctx: WorkflowContext[ReviewState]) -> None:
            self.states.append(msg)

    class _RmSeeder(Executor):
        def __init__(self, state: ReviewState, results: list[AgentExecutionOutput]) -> None:
            super().__init__(id="rm_seeder")
            self._state = state
            self._results = results

        @handler
        async def seed(self, _trigger: str, ctx: WorkflowContext[list[AgentExecutionOutput]]) -> None:
            ctx.set_state("review_state", self._state)
            await ctx.send_message(self._results)

    # 2. Clean low-risk / docs-only fan-out skips Reviewer Manager LLM cleanly
    llm_calls = 0

    async def _fail_if_called(*_args, **_kwargs):
        nonlocal llm_calls
        llm_calls += 1
        return {"recommendation": "Approve", "reason": "ok", "findings": []}

    monkeypatch.setattr("app.agents.reviewer_manager.run_structured_agent", _fail_if_called)

    (tmp_path / "README.md").write_text("# Docs\nClean readme.\n", encoding="utf-8")
    clean_outputs = [
        AgentExecutionOutput("diff_agent", "Diff Agent", "deepseek-flash", "completed", "ok", tool_results={"risk_tier": "low"}),
        AgentExecutionOutput("style_agent", "Style Agent", "deepseek-flash", "completed", "ok", tool_results={}),
        AgentExecutionOutput("security_agent", "Security Agent", "deepseek-v4-pro", "completed", "ok", tool_results={}),
        AgentExecutionOutput("test_coverage_agent", "Test-Coverage Agent", "deepseek-flash", "completed", "ok", tool_results={"passed": 2, "failed": 0}),
    ]
    st_clean = ReviewState(
        review_id="rev-rm-clean",
        repository_id="r1",
        repository_name="org/docs",
        source_type="local",
        base_commit="HEAD~1",
        target_commit="HEAD",
        workspace_dir=tmp_path,
        diff_text="diff --git a/README.md b/README.md\n+Clean readme.\n",
        changed_files=[{"path": "README.md", "changed_lines": [2]}],
        policy={},
        agent_configs=configs,
        review_plan={"risk_tier": "low", "docs_only": True},
        agent_results={r.agent_name: r.to_dict() for r in clean_outputs},
        cache_dir=tmp_path / "_cache",
    )
    seeder1 = _RmSeeder(st_clean, clean_outputs)
    rm_exec = ReviewerManagerExecutor(_capture_emit)
    rm_sink = _PassSink()
    wf = WorkflowBuilder(start_executor=seeder1).add_edge(seeder1, rm_exec).add_edge(rm_exec, rm_sink).build()
    await wf.run("go")
    assert llm_calls == 0
    assert rm_sink.states
    out_clean = rm_sink.states[0]
    rm_tr = out_clean.agent_results["reviewer_manager"]["tool_results"]
    assert rm_tr["llm_skipped_token_saver"] is True
    rm_events = [pl for ev, pl in emitted if ev == "reviewer_manager_completed"]
    assert rm_events and rm_events[-1].get("tool_results", {}).get("llm_skipped_token_saver") is True

    # 3. Verified EV-NNN finding retention even when Reviewer Manager LLM drops a finding
    app_py = tmp_path / "service.py"
    app_py.write_text(
        "import hashlib\nimport subprocess\n\n"
        "def run_it(cmd: str) -> bytes:\n"
        "    subprocess.run(cmd, shell=True)\n"
        "    return hashlib.md5(cmd.encode()).digest()\n",
        encoding="utf-8",
    )

    async def _truncated_rm_llm(*_args, **_kwargs):
        # LLM only returns 1 finding and drops EV-002 without explicitly rejecting it
        return {
            "recommendation": "Request Changes",
            "reason": "Command injection found",
            "findings": [
                {
                    "title": "Shell command injection",
                    "severity": "High",
                    "category": "security",
                    "file_path": "service.py",
                    "line_number": 5,
                    "tool_name": "bandit",
                    "rule_id": "B602",
                    "evidence_ids": ["EV-001"],
                    "evidence": "subprocess.run(cmd, shell=True)",
                    "description": "Unsafe shell=True call.",
                }
            ],
            "rejected_false_positives": [],
        }

    monkeypatch.setattr("app.agents.reviewer_manager.run_structured_agent", _truncated_rm_llm)
    retain_outputs = [
        AgentExecutionOutput("diff_agent", "Diff Agent", "deepseek-flash", "completed", "ok", tool_results={"risk_tier": "high"}),
        AgentExecutionOutput("style_agent", "Style Agent", "deepseek-flash", "completed", "ok", tool_results={}),
        AgentExecutionOutput(
            "security_agent",
            "Security Agent",
            "deepseek-v4-pro",
            "completed",
            "ok",
            tool_results={
                "bandit": {
                    "status": "completed",
                    "findings": [
                        {
                            "title": "Shell command injection",
                            "severity": "High",
                            "category": "security",
                            "file_path": "service.py",
                            "line_number": 5,
                            "tool_name": "bandit",
                            "rule_id": "B602",
                            "evidence": "subprocess.run(cmd, shell=True)",
                            "description": "Unsafe shell=True call.",
                        },
                        {
                            "title": "Weak MD5 hash",
                            "severity": "Medium",
                            "category": "security",
                            "file_path": "service.py",
                            "line_number": 6,
                            "tool_name": "bandit",
                            "rule_id": "B324",
                            "evidence": "hashlib.md5(cmd.encode())",
                            "description": "Insecure MD5 hash.",
                        },
                    ],
                }
            },
        ),
        AgentExecutionOutput("test_coverage_agent", "Test-Coverage Agent", "deepseek-flash", "completed", "ok", tool_results={"passed": 1, "failed": 0}),
    ]
    st_retain = ReviewState(
        review_id="rev-rm-retain",
        repository_id="r1",
        repository_name="org/svc",
        source_type="local",
        base_commit="HEAD~1",
        target_commit="HEAD",
        workspace_dir=tmp_path,
        diff_text="diff --git a/service.py b/service.py\n+subprocess.run(cmd, shell=True)\n",
        changed_files=[{"path": "service.py", "changed_lines": [5, 6]}],
        policy={},
        agent_configs=configs,
        review_plan={"risk_tier": "high"},
        agent_results={r.agent_name: r.to_dict() for r in retain_outputs},
        cache_dir=tmp_path / "_cache",
    )
    seeder2 = _RmSeeder(st_retain, retain_outputs)
    rm_exec2 = ReviewerManagerExecutor(_capture_emit)
    rm_sink2 = _PassSink()
    wf2 = WorkflowBuilder(start_executor=seeder2).add_edge(seeder2, rm_exec2).add_edge(rm_exec2, rm_sink2).build()
    await wf2.run("go")
    assert rm_sink2.states
    out_retain = rm_sink2.states[0]
    retained_rules = {f.get("rule_id") for f in out_retain.findings}
    assert {"B602", "B324"} <= retained_rules
    assert all(f.get("verification_status") == "Verified" for f in out_retain.findings if f.get("rule_id") in {"B602", "B324"})


@pytest.mark.asyncio
async def test_subagent_fix_suggestion_symbol_snap_non_duplicate_stair_and_filter(tmp_path: Path, monkeypatch):
    from app.agents.fix_suggestion_agent import (
        FixSuggestionAgentExecutor,
        _assemble_corrected_file,
        _find_enclosing_symbol_span,
        _select_target_findings,
    )
    from app.config import AGENT_METADATA
    from app.intelligence.context_builder import build_agent_context
    from app.intelligence.structure_indexer import build_structure_index
    from app.orchestration.shared_state import AgentExecutionConfig

    await _arun_git("init", cwd=tmp_path)
    await _arun_git("config", "user.email", "dev@example.com", cwd=tmp_path)
    await _arun_git("config", "user.name", "Dev", cwd=tmp_path)

    # 1. Verify _select_target_findings skips non-patchable rules & records reasons
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Doc\n", encoding="utf-8")
    skipped: list[dict[str, str]] = []
    empty_targets = _select_target_findings(
        tmp_path,
        [
            {"file_path": "app.py", "rule_id": "COVERAGE-GAP", "severity": "Medium", "category": "testing", "verification_status": "Verified", "evidence_ids": ["EV-001"]},
            {"file_path": "app.py", "rule_id": "STYLE-FILE-SIZE", "severity": "Medium", "category": "style", "verification_status": "Verified", "evidence_ids": ["EV-002"]},
            {"file_path": "README.md", "rule_id": "DOC-RULE", "severity": "Medium", "category": "docs", "verification_status": "Verified", "evidence_ids": ["EV-003"]},
        ],
        skipped_out=skipped,
    )
    assert empty_targets == []
    assert len(skipped) == 3

    # 2. Verify symbol-span snapping + STAIR exclude_span non-duplication on >500 line file
    padding = "\n".join(f"def helper_{i}() -> int:\n    return {i}\n" for i in range(180))
    big_code = (
        "import subprocess\n\n"
        + padding
        + "\ndef run_vuln(cmd: str) -> None:\n"
        + "    subprocess.run(cmd, shell=True)\n"
        + "    print('done')\n"
    )
    big_file = tmp_path / "big.py"
    big_file.write_text(big_code, encoding="utf-8")
    await _arun_git("add", ".", cwd=tmp_path)
    await _arun_git("commit", "-m", "add big.py", cwd=tmp_path)

    all_lines = big_code.splitlines(keepends=True)
    target_line = next(i for i, ln in enumerate(all_lines, start=1) if "subprocess.run(cmd, shell=True)" in ln)
    s_idx = build_structure_index(tmp_path, [{"path": "big.py", "changed_lines": [target_line]}])
    ws, we, scope_label = _find_enclosing_symbol_span(s_idx, "big.py", target_line, len(all_lines))
    assert "run_vuln" in scope_label
    assert ws < target_line <= we and (we - ws) <= 10

    stair_ctx = build_agent_context(
        role="fix_suggestion_agent",
        workspace_dir=tmp_path,
        structure_index=s_idx,
        changed_files=[{"path": "big.py", "changed_lines": [target_line]}],
        diff_text="",
        findings=[{"file_path": "big.py", "line_number": target_line}],
        target_files=["big.py"],
        exclude_span=("big.py", ws, we),
    )
    assert f"L{target_line}:" not in stair_ctx["context_text"]

    # Markdown code fence stripping preserves file assembly cleanly
    fenced = "```python\ndef f():\n    return 1\n```"
    assembled = _assemble_corrected_file(["def f():\n", "    return 0\n"], 1, 2, 2, fenced)
    assert "```" not in assembled and assembled.endswith("\n")

    # 3. Full FixSuggestionAgentExecutor run emits tool_results & verified patch without fence leakage
    emitted: list[tuple[str, dict[str, object]]] = []

    async def _capture_emit(_rid: str, ev: str, pl: dict[str, object]) -> None:
        emitted.append((ev, pl))

    async def _fake_fix_llm(*_args, **_kwargs):
        return {
            "title": "Avoid shell=True in run_vuln",
            "corrected_code": "```python\ndef run_vuln(cmd: str) -> None:\n    subprocess.run(cmd.split(), shell=False)\n    print('done')\n```",
            "explanation": "Use argument list instead of shell=True.",
            "regression_test_code": "def test_safe_fix():\n    assert callable(__import__('big').run_vuln)\n",
            "_token_usage": {"prompt_tokens": 110, "completion_tokens": 45, "total_tokens": 155},
        }

    monkeypatch.setattr("app.agents.fix_suggestion_agent.run_structured_agent", _fake_fix_llm)
    configs = {
        k: AgentExecutionConfig(
            agent_name=k,
            label=m["label"],
            model=m["default_model"],
            base_url="https://api.deepseek.com",
            api_key="sk-test-key",
        )
        for k, m in AGENT_METADATA.items()
    }

    class _FixSink(Executor):
        def __init__(self) -> None:
            super().__init__(id="fix_sink")
            self.states: list[ReviewState] = []

        @handler
        async def take(self, msg: ReviewState, ctx: WorkflowContext[ReviewState]) -> None:
            self.states.append(msg)

    fix_exec = FixSuggestionAgentExecutor(_capture_emit)
    fix_sink = _FixSink()
    wf = WorkflowBuilder(start_executor=fix_exec).add_edge(fix_exec, fix_sink).build()
    st = ReviewState(
        review_id="rev-fix-big",
        repository_id="r1",
        repository_name="org/big",
        source_type="local",
        base_commit="HEAD~1",
        target_commit="HEAD",
        workspace_dir=tmp_path,
        diff_text="",
        changed_files=[{"path": "big.py", "changed_lines": [target_line]}],
        structure_index=s_idx,
        findings=[
            {
                "title": "Unsafe subprocess shell=True",
                "severity": "High",
                "category": "security",
                "rule_id": "TAINT-CMD-INJECTION",
                "tool_name": "security-taint",
                "file_path": "big.py",
                "line_number": target_line,
                "evidence": "subprocess.run(cmd, shell=True)",
                "description": "User input reaches shell=True.",
                "verification_status": "Verified",
                "evidence_ids": ["EV-001"],
            }
        ],
        policy={},
        agent_configs=configs,
        cache_dir=tmp_path / "_cache",
    )
    await wf.run(st)
    assert len(st.patch_proposals) == 1
    prop = st.patch_proposals[0]
    assert prop["applicability_verified"] is True
    assert "```" not in prop["proposed_code"]
    assert "subprocess.run(cmd.split(), shell=False)" in prop["proposed_code"]
    fix_tr = st.agent_results["fix_suggestion_agent"]["tool_results"]
    assert fix_tr["verified_patches"] == 1
    assert fix_tr["token_usage"]["total_tokens"] == 155
    fix_events = [pl for ev, pl in emitted if ev == "fix_suggestion_completed"]
    assert fix_events and fix_events[-1].get("tool_results", {}).get("verified_patches") == 1


@pytest.mark.asyncio
async def test_test_tools_external_dep_isolation_stair_budget_and_scanner_categories(tmp_path: Path):
    from app.intelligence.context_builder import build_agent_context
    from app.intelligence.structure_indexer import build_structure_index
    from app.scanners.test_tools import run_test_and_coverage
    from app.scanners.tool_runner import check_installed_scanners

    await _arun_git("init", cwd=tmp_path)
    (tmp_path / "calc.py").write_text("def mul(a: int, b: int) -> int:\n    return a * b\n", encoding="utf-8")
    (tmp_path / "test_ok.py").write_text(
        "from calc import mul\ndef test_mul():\n    assert mul(3, 4) == 12\n",
        encoding="utf-8",
    )
    (tmp_path / "test_ext_blocked.py").write_text(
        "import scrapling_missing_pkg_xyz_999\ndef test_ext():\n    assert True\n",
        encoding="utf-8",
    )
    await _arun_git("add", ".", cwd=tmp_path)
    await _arun_git("commit", "-m", "init", cwd=tmp_path)

    tres = await run_test_and_coverage(
        tmp_path,
        ["calc.py"],
        plan={"selective_test_mode": False},
    )
    assert tres["status"] == "completed"
    assert tres["passed"] == 1
    assert tres["failed"] == 0
    assert tres["skipped_env_tests"] == ["test_ext_blocked.py"]

    # STAIR strict token_estimate <= token_budget enforcement
    idx = build_structure_index(tmp_path, [{"path": "calc.py", "changed_lines": [1, 2]}])
    ctx = build_agent_context(
        role="style_agent",
        workspace_dir=tmp_path,
        structure_index=idx,
        changed_files=[{"path": "calc.py", "changed_lines": [1, 2]}],
        diff_text="",
        target_files=["calc.py"],
        token_budget=220,
    )
    assert ctx["token_estimate"] <= 220

    scanners = await check_installed_scanners()
    assert scanners["git"]["category"] == "core" and scanners["git"]["optional"] is False
    assert scanners["eslint"]["category"] == "optional" and scanners["eslint"]["optional"] is True
    assert bool(scanners["eslint"]["install_hint"])


@pytest.mark.asyncio
async def test_coordinator_incremental_tool_telemetry_and_file_snapshots(tmp_path: Path, monkeypatch):
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    import app.database.session as db_sess
    import app.orchestration.coordinator as coord_mod
    from app.config import AGENT_METADATA
    from app.database.session import Base
    from app.models.tables import AgentRun, CodeChange, Repository, Review, User
    from app.orchestration.coordinator import ReviewCoordinator, seed_agent_runs
    from app.orchestration.shared_state import AgentExecutionConfig

    repo_dir = tmp_path / "local_repo"
    repo_dir.mkdir()
    await _arun_git("init", cwd=repo_dir)
    await _arun_git("config", "user.email", "dev@example.com", cwd=repo_dir)
    await _arun_git("config", "user.name", "Dev", cwd=repo_dir)
    (repo_dir / "app.py").write_text("def greet() -> str:\n    return 'hi'\n", encoding="utf-8")
    await _arun_git("add", ".", cwd=repo_dir)
    await _arun_git("commit", "-m", "init", cwd=repo_dir)
    head_sha = (await _arun_git_out("rev-parse", "HEAD", cwd=repo_dir)).strip()

    db_file = tmp_path / "coord_tel.db"
    test_engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}", connect_args={"check_same_thread": False})
    test_session_maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(db_sess, "engine", test_engine)
    monkeypatch.setattr(db_sess, "async_session_maker", test_session_maker)
    monkeypatch.setattr(coord_mod, "async_session_maker", test_session_maker)

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    configs = {
        k: AgentExecutionConfig(
            agent_name=k,
            label=m["label"],
            model=m["default_model"],
            base_url="https://api.deepseek.com",
            api_key="sk-test",
        )
        for k, m in AGENT_METADATA.items()
    }

    async def _fake_load_configs(_db):
        return configs

    monkeypatch.setattr(coord_mod, "load_effective_agent_configs", _fake_load_configs)

    def _fake_build_workflow(emit_fn):
        class _FakeWorkflow:
            async def run(self, state: ReviewState):
                await emit_fn(
                    state.review_id,
                    "agent_completed",
                    {
                        "agent_name": "diff_agent",
                        "status": "completed",
                        "duration_ms": 42,
                        "summary": "Diff complete",
                        "tool_results": {"file_count": 1, "llm_skipped_token_saver": True},
                    },
                )
                raise RuntimeError("simulated mid-review interruption")

        return _FakeWorkflow()

    monkeypatch.setattr(coord_mod, "build_review_workflow", _fake_build_workflow)

    async with test_session_maker() as db:
        user = User(email="tel@reviewboard.local", name="Dev", password_hash="x")
        db.add(user)
        await db.flush()
        repo = Repository(
            user_id=user.id,
            name="local_repo",
            owner="org",
            full_name="org/local_repo",
            source_type="local",
            local_path=str(repo_dir),
        )
        db.add(repo)
        await db.flush()
        cc = CodeChange(
            repository_id=repo.id,
            source_mode="local_diff",
            base_branch="main",
            target_branch="main",
            base_commit=head_sha,
            target_commit=head_sha,
            diff_text="diff --git a/app.py b/app.py\n+def greet() -> str:\n",
            changed_files=[{"path": "app.py", "status": "modified", "changed_lines": [1]}],
            file_snapshots={},
        )
        db.add(cc)
        await db.flush()
        rev = Review(
            repository_id=repo.id,
            code_change_id=cc.id,
            triggered_by="test",
            base_commit=head_sha,
            target_commit=head_sha,
            review_status="queued",
            recommendation="Pending",
        )
        db.add(rev)
        await db.flush()
        await seed_agent_runs(db, rev.id, configs)
        await db.commit()
        review_id = rev.id
        cc_id = cc.id

    await ReviewCoordinator.execute_review(review_id)

    async with test_session_maker() as db:
        saved_cc = (await db.execute(select(CodeChange).where(CodeChange.id == cc_id))).scalar_one()
        assert "app.py" in (saved_cc.file_snapshots or {})
        diff_run = (
            await db.execute(
                select(AgentRun).where(AgentRun.review_id == review_id, AgentRun.agent_name == "diff_agent")
            )
        ).scalar_one()
        assert diff_run.status == "completed"
        assert diff_run.duration_ms == 42
        assert diff_run.tool_results == {"file_count": 1, "llm_skipped_token_saver": True}

    await test_engine.dispose()


@pytest.mark.asyncio
async def test_subagent_llm_timeout_resilience_no_incomplete_blocking(tmp_path: Path, monkeypatch):
    from app.agents.diff_agent import DiffAgentExecutor
    from app.agents.fix_suggestion_agent import FixSuggestionAgentExecutor
    from app.agents.reviewer_manager import ReviewerManagerExecutor
    from app.agents.security_agent import SecurityAgentExecutor
    from app.agents.style_agent import StyleAgentExecutor
    from app.agents.test_coverage_agent import TestCoverageAgentExecutor
    from app.config import AGENT_METADATA
    from app.intelligence.structure_indexer import build_structure_index
    from app.orchestration.shared_state import AgentExecutionConfig
    from app.planning.review_planner import build_review_plan

    await _arun_git("init", cwd=tmp_path)
    await _arun_git("config", "user.email", "dev@example.com", cwd=tmp_path)
    await _arun_git("config", "user.name", "Dev", cwd=tmp_path)

    src = (
        "import subprocess\n"
        "import os\n\n"
        "def run_cmd(user_arg: str) -> None:\n"
        "    unused_x = 1\n"
        "    subprocess.run(user_arg, shell=True)\n"
    )
    (tmp_path / "svc.py").write_text(src, encoding="utf-8")
    (tmp_path / "test_svc.py").write_text(
        "def test_basic():\n    assert 1 + 1 == 2\n",
        encoding="utf-8",
    )
    await _arun_git("add", ".", cwd=tmp_path)
    await _arun_git("commit", "-m", "initial commit", cwd=tmp_path)
    diff_patch = await _arun_git_out("show", "--format=", "HEAD", cwd=tmp_path)

    configs = {
        k: AgentExecutionConfig(
            agent_name=k,
            label=m["label"],
            model=m["default_model"],
            base_url="https://api.deepseek.com",
            api_key="sk-test-key",
        )
        for k, m in AGENT_METADATA.items()
    }
    changed = [
        {"path": "svc.py", "status": "added", "changed_lines": [1, 2, 4, 5, 6]},
        {"path": "test_svc.py", "status": "added", "changed_lines": [1, 2]},
    ]
    s_idx = build_structure_index(tmp_path, changed)
    plan = build_review_plan(changed_files=changed, structure_index=s_idx, diff_text=diff_patch)

    async def _always_timeout(cfg, **_kwargs):
        raise TimeoutError(f"{cfg.label} ({cfg.model}) exceeded 110s response timeout.")

    for target_mod in (
        "app.agents.diff_agent.run_structured_agent",
        "app.agents.style_agent.run_structured_agent",
        "app.agents.security_agent.run_structured_agent",
        "app.agents.test_coverage_agent.run_structured_agent",
        "app.agents.reviewer_manager.run_structured_agent",
        "app.agents.fix_suggestion_agent.run_structured_agent",
    ):
        monkeypatch.setattr(target_mod, _always_timeout)

    emitted: list[tuple[str, dict[str, object]]] = []

    async def _noop_emit(_rid: str, ev: str, pl: dict[str, object]) -> None:
        emitted.append((ev, pl))

    class _FanOutSink(Executor):
        def __init__(self) -> None:
            super().__init__(id="timeout_fanout_sink")
            self.outputs: list[AgentExecutionOutput] = []

        @handler
        async def take(self, msg: AgentExecutionOutput, ctx: WorkflowContext[AgentExecutionOutput]) -> None:
            self.outputs.append(msg)

    base_state = ReviewState(
        review_id="rev-timeout-resilience",
        repository_id="r-res",
        repository_name="org/svc",
        source_type="local",
        base_commit="EMPTY_TREE",
        target_commit="HEAD",
        workspace_dir=tmp_path,
        diff_text=diff_patch,
        changed_files=changed,
        structure_index=s_idx,
        review_plan=plan,
        policy={},
        agent_configs=configs,
        cache_dir=tmp_path / "_cache",
    )

    fanout_results: list[AgentExecutionOutput] = []
    for exec_cls in (DiffAgentExecutor, StyleAgentExecutor, SecurityAgentExecutor, TestCoverageAgentExecutor):
        ex = exec_cls(_noop_emit)
        sk = _FanOutSink()
        wf = WorkflowBuilder(start_executor=ex).add_edge(ex, sk).build()
        await wf.run(base_state)
        assert sk.outputs, f"{exec_cls.__name__} emitted no output"
        out = sk.outputs[0]
        # Deterministic engines succeeded -> agent must NOT become failed/incomplete on LLM timeout!
        assert out.status == "completed", f"{out.agent_name} failed on timeout: {out.error_message}"
        fanout_results.append(out)

    sec_out = next(r for r in fanout_results if r.agent_name == "security_agent")
    assert sec_out.tool_results.get("llm_degraded"), "security_agent should record llm_degraded telemetry"
    assert len(sec_out.findings) >= 1, "Bandit/taint deterministic hits must be preserved on LLM timeout"

    # Inject extra low Ruff lints to verify passthrough optimization + ReviewerManager graceful timeout
    style_out = next(r for r in fanout_results if r.agent_name == "style_agent")
    for idx_i in range(45):
        style_out.tool_results.setdefault("ruff", {"status": "completed", "findings": []})["findings"].append(
            {
                "tool": "ruff",
                "rule_id": f"UP{idx_i:03d}",
                "file_path": "svc.py",
                "line_number": (idx_i % 6) + 1,
                "severity": "Low",
                "message": f"Minor style hint {idx_i}",
            }
        )

    class _RmSink(Executor):
        def __init__(self) -> None:
            super().__init__(id="timeout_rm_sink")
            self.states: list[ReviewState] = []

        @handler
        async def take(self, msg: ReviewState, ctx: WorkflowContext[ReviewState]) -> None:
            self.states.append(msg)

    class _RmSeeder(Executor):
        def __init__(self, st: ReviewState, res: list[AgentExecutionOutput]) -> None:
            super().__init__(id="timeout_rm_seeder")
            self._st = st
            self._res = res

        @handler
        async def go(self, _t: str, ctx: WorkflowContext[list[AgentExecutionOutput]]) -> None:
            ctx.set_state("review_state", self._st)
            await ctx.send_message(self._res)

    rm_exec = ReviewerManagerExecutor(_noop_emit)
    rm_sink = _RmSink()
    seeder = _RmSeeder(base_state, fanout_results)
    await WorkflowBuilder(start_executor=seeder).add_edge(seeder, rm_exec).add_edge(rm_exec, rm_sink).build().run("go")
    st_after_rm = rm_sink.states[0]
    rm_res = st_after_rm.agent_results["reviewer_manager"]
    assert rm_res["status"] == "completed"
    assert rm_res["tool_results"].get("llm_degraded")
    assert rm_res["tool_results"]["passthrough_verified_count"] >= 40
    # Must NOT become Incomplete — Request Changes because Verified High shell=True finding exists
    assert st_after_rm.recommendation == "Request Changes"

    # Fix-Suggestion Agent degrades per target without crashing or marking review Incomplete
    fix_exec = FixSuggestionAgentExecutor(_noop_emit)

    class _FixSink(Executor):
        def __init__(self) -> None:
            super().__init__(id="timeout_fix_sink")
            self.states: list[ReviewState] = []

        @handler
        async def take(self, msg: ReviewState, ctx: WorkflowContext[ReviewState]) -> None:
            self.states.append(msg)

    await WorkflowBuilder(start_executor=fix_exec).add_edge(fix_exec, _FixSink()).build().run(st_after_rm)
    fix_res = st_after_rm.agent_results["fix_suggestion_agent"]
    assert fix_res["status"] == "completed"
    assert fix_res["tool_results"].get("llm_degraded_targets")
    assert st_after_rm.recommendation == "Request Changes"


@pytest.mark.asyncio
async def test_llm_factory_streaming_and_adaptive_timeout():
    from types import SimpleNamespace

    from app.agents.llm_factory import _run_with_stream_fallback, effective_agent_timeout
    from app.orchestration.shared_state import AgentExecutionConfig

    pro_cfg = AgentExecutionConfig("security_agent", "Security Agent", "deepseek-v4-pro", "https://api.deepseek.com", "sk-x")
    flash_cfg = AgentExecutionConfig("diff_agent", "Diff Agent", "deepseek-flash", "https://api.deepseek.com", "sk-x")
    assert effective_agent_timeout(pro_cfg, 75.0) >= 110.0
    assert effective_agent_timeout(flash_cfg, 75.0) == 75.0

    class _FakeStream:
        def __init__(self) -> None:
            self.closed = False
            self._items = [SimpleNamespace(text='{"ok": '), SimpleNamespace(text="true}")]

        def __aiter__(self):
            self._idx = 0
            return self

        async def __anext__(self):
            if self._idx >= len(self._items):
                raise StopAsyncIteration
            val = self._items[self._idx]
            self._idx += 1
            return val

        async def get_final_response(self):
            return SimpleNamespace(text='{"ok": true}', usage_details={"input_tokens": 10, "output_tokens": 5})

        async def close(self):
            self.closed = True

    class _FakeAgent:
        def run(self, _prompt: str, *, stream: bool = False):
            assert stream is True
            return _FakeStream()

    resp = await _run_with_stream_fallback(_FakeAgent(), "hello", rid="", timeout_seconds=10.0)
    assert resp.text == '{"ok": true}'


@pytest.mark.asyncio
async def test_coordinator_timeout_cleans_running_agent_runs(tmp_path: Path, monkeypatch):
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    import app.database.session as db_sess
    import app.orchestration.coordinator as coord_mod
    from app.config import AGENT_METADATA
    from app.database.session import Base
    from app.models.tables import AgentRun, CodeChange, Repository, Review, User
    from app.orchestration.coordinator import ReviewCoordinator, seed_agent_runs
    from app.orchestration.shared_state import AgentExecutionConfig

    repo_dir = tmp_path / "repo_to"
    repo_dir.mkdir()
    await _arun_git("init", cwd=repo_dir)
    await _arun_git("config", "user.email", "dev@example.com", cwd=repo_dir)
    await _arun_git("config", "user.name", "Dev", cwd=repo_dir)
    (repo_dir / "main.py").write_text("x = 1\n", encoding="utf-8")
    await _arun_git("add", ".", cwd=repo_dir)
    await _arun_git("commit", "-m", "init", cwd=repo_dir)
    head_sha = (await _arun_git_out("rev-parse", "HEAD", cwd=repo_dir)).strip()

    db_file = tmp_path / "coord_to.db"
    test_engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}", connect_args={"check_same_thread": False})
    test_session_maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(db_sess, "engine", test_engine)
    monkeypatch.setattr(db_sess, "async_session_maker", test_session_maker)
    monkeypatch.setattr(coord_mod, "async_session_maker", test_session_maker)

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    configs = {
        k: AgentExecutionConfig(k, m["label"], m["default_model"], "https://api.deepseek.com", "sk-t")
        for k, m in AGENT_METADATA.items()
    }

    async def _fake_cfg(_db):
        return configs

    monkeypatch.setattr(coord_mod, "load_effective_agent_configs", _fake_cfg)

    def _timeout_wf(emit_fn):
        class _FakeWf:
            async def run(self, state: ReviewState):
                await emit_fn(state.review_id, "agent_started", {"agent_name": "fix_suggestion_agent"})
                raise TimeoutError()

        return _FakeWf()

    monkeypatch.setattr(coord_mod, "build_review_workflow", _timeout_wf)

    async with test_session_maker() as db:
        u = User(email="to@reviewboard.local", name="Dev", password_hash="x")
        db.add(u)
        await db.flush()
        repo = Repository(user_id=u.id, name="repo_to", owner="org", full_name="org/repo_to", source_type="local", local_path=str(repo_dir))
        db.add(repo)
        await db.flush()
        cc = CodeChange(repository_id=repo.id, source_mode="local_diff", base_branch="main", target_branch="main", base_commit=head_sha, target_commit=head_sha, diff_text="diff --git a/main.py b/main.py\n+x = 1\n", changed_files=[{"path": "main.py", "status": "added", "changed_lines": [1]}], file_snapshots={})
        db.add(cc)
        await db.flush()
        rev = Review(repository_id=repo.id, code_change_id=cc.id, triggered_by="test", base_commit=head_sha, target_commit=head_sha, review_status="queued", recommendation="Pending")
        db.add(rev)
        await db.flush()
        await seed_agent_runs(db, rev.id, configs)
        await db.commit()
        rid = rev.id

    await ReviewCoordinator.execute_review(rid)

    async with test_session_maker() as db:
        saved_rev = (await db.execute(select(Review).where(Review.id == rid))).scalar_one()
        assert saved_rev.recommendation_reason == "Review execution error: TimeoutError"
        fix_run = (
            await db.execute(select(AgentRun).where(AgentRun.review_id == rid, AgentRun.agent_name == "fix_suggestion_agent"))
        ).scalar_one()
        assert fix_run.status == "incomplete"
        assert fix_run.error_message == "TimeoutError"

    await test_engine.dispose()









