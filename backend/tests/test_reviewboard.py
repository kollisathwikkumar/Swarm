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
            assert detail["review"]["recommendation"] == "Incomplete"
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
    assert "security guard" in val_msg.lower()


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







