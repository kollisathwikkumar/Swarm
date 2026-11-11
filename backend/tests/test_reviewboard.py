from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))
sys.path.insert(0, str(REPO_ROOT / "local-companion"))

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
from repository_reader import is_sensitive_path, validate_repo_path


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
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
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
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
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
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Dev"], cwd=repo_dir, check=True)
    (repo_dir / "app.py").write_text("def greet(name: str) -> str:\n    return f'hi {name}'\n", encoding="utf-8")
    (repo_dir / "test_app.py").write_text("from app import greet\ndef test_greet():\n    assert greet('a') == 'hi a'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True, capture_output=True)

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
    from datetime import datetime, timedelta, timezone

    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

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

        base_t = datetime.now(timezone.utc)
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





