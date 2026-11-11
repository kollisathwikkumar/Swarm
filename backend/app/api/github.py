from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, resolve_github_token
from app.config import get_settings
from app.database.session import get_db
from app.integrations.github_client import GitHubAPIError, GitHubClient, parse_github_repo_input
from app.models.tables import (
    CodeChange,
    ConnectedAccount,
    Finding,
    Repository,
    Review,
    ReviewArtifact,
    User,
)
from app.orchestration.coordinator import launch_review_job
from app.scanners.git_diff_tool import parse_unified_diff
from app.scanners.tool_runner import resolve_binary, run_command_capture
from app.services.crypto import encrypt_secret
from app.services.git_workspace import probe_github_remote_head
from app.services.github_sync import sync_repository_open_prs

router = APIRouter(prefix="/api/github", tags=["github"])


class ConnectPATRequest(BaseModel):
    token: str = Field(min_length=10, max_length=500)


class OAuthExchangeRequest(BaseModel):
    code: str = Field(min_length=4, max_length=500)


class SyncGitHubRepoRequest(BaseModel):
    full_name: str = Field(min_length=3, max_length=500)  # owner/repo or https://github.com/owner/repo
    auto_review_webhooks: bool = True


class RegisterWebhookRequest(BaseModel):
    webhook_url: str = Field(min_length=8, max_length=500)
    secret: str | None = None


class DevicePollRequest(BaseModel):
    device_code: str = Field(min_length=4, max_length=200)


class PublishReviewRequest(BaseModel):
    include_inline_comments: bool = True
    include_commit_status: bool = True
    custom_body: str | None = None


@router.get("/accounts")
async def list_connected_accounts(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    res = await db.execute(
        select(ConnectedAccount)
        .where(ConnectedAccount.user_id == user.id, ConnectedAccount.provider == "github")
        .order_by(ConnectedAccount.updated_at.desc())
    )
    accounts = [
        {
            "id": a.id,
            "provider": a.provider,
            "auth_mode": a.auth_mode,
            "username": a.username,
            "avatar_url": a.avatar_url,
            "scopes": a.scopes,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in res.scalars().all()
    ]
    env_pat_configured = bool(get_settings().github_token.strip())
    return {"accounts": accounts, "env_token_configured": env_pat_configured}


@router.post("/connect/pat")
async def connect_github_pat(
    payload: ConnectPATRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    gh = GitHubClient(payload.token.strip())
    try:
        gh_user, scopes = await gh.get_authenticated_user()
    except GitHubAPIError as exc:
        raise HTTPException(status_code=400, detail=f"GitHub rejected token: {exc.message}")

    provider_uid = str(gh_user["id"])
    existing = (
        await db.execute(
            select(ConnectedAccount).where(
                ConnectedAccount.user_id == user.id,
                ConnectedAccount.provider == "github",
                ConnectedAccount.provider_user_id == provider_uid,
            )
        )
    ).scalar_one_or_none()

    enc = encrypt_secret(payload.token.strip())
    if existing:
        existing.auth_mode = "pat"
        existing.username = gh_user["login"]
        existing.avatar_url = gh_user.get("avatar_url")
        existing.scopes = scopes
        existing.encrypted_access_token = enc
        acct = existing
    else:
        acct = ConnectedAccount(
            user_id=user.id,
            provider="github",
            auth_mode="pat",
            provider_user_id=provider_uid,
            username=gh_user["login"],
            avatar_url=gh_user.get("avatar_url"),
            scopes=scopes,
            encrypted_access_token=enc,
        )
        db.add(acct)
    await db.commit()
    await db.refresh(acct)

    return {
        "account": {
            "id": acct.id,
            "username": acct.username,
            "avatar_url": acct.avatar_url,
            "scopes": acct.scopes,
            "auth_mode": acct.auth_mode,
        }
    }


@router.delete("/accounts/{account_id}")
async def disconnect_github_account(
    account_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    acct = (
        await db.execute(
            select(ConnectedAccount).where(
                ConnectedAccount.id == account_id, ConnectedAccount.user_id == user.id
            )
        )
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(status_code=404, detail="Connected account not found")
    await db.delete(acct)
    await db.commit()
    return {"deleted": True}


@router.get("/oauth/url")
async def get_github_oauth_url(user: User = Depends(get_current_user)) -> dict:
    settings = get_settings()
    if not settings.github_client_id:
        return {"configured": False, "url": None}
    params = urlencode(
        {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_oauth_redirect_uri,
            "scope": "repo read:user",
            "state": user.id,
        }
    )
    return {"configured": True, "url": f"https://github.com/login/oauth/authorize?{params}"}


@router.post("/oauth/exchange")
async def exchange_github_oauth(
    payload: OAuthExchangeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    settings = get_settings()
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(status_code=400, detail="GitHub OAuth Client ID/Secret not configured")
    try:
        token_data = await GitHubClient.exchange_oauth_code(
            settings.github_client_id,
            settings.github_client_secret,
            payload.code,
            settings.github_oauth_redirect_uri,
        )
        access_token = token_data["access_token"]
        gh = GitHubClient(access_token)
        gh_user, scopes = await gh.get_authenticated_user()
    except GitHubAPIError as exc:
        raise HTTPException(status_code=400, detail=f"GitHub OAuth failed: {exc.message}")

    acct = ConnectedAccount(
        user_id=user.id,
        provider="github",
        auth_mode="oauth",
        provider_user_id=str(gh_user["id"]),
        username=gh_user["login"],
        avatar_url=gh_user.get("avatar_url"),
        scopes=scopes or token_data.get("scope", ""),
        encrypted_access_token=encrypt_secret(access_token),
    )
    db.add(acct)
    await db.commit()
    return {"connected": True, "username": acct.username}


@router.get("/remote-repos")
async def list_remote_github_repos(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    token = await resolve_github_token(user.id, db)
    if not token:
        raise HTTPException(
            status_code=400,
            detail="No GitHub token configured. Connect a GitHub Personal Access Token in Repositories or Settings.",
        )
    gh = GitHubClient(token)
    try:
        repos = await gh.list_repositories(per_page=60)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    return {
        "repositories": [
            {
                "github_repo_id": r["id"],
                "full_name": r["full_name"],
                "owner": r["owner"]["login"],
                "name": r["name"],
                "description": r.get("description"),
                "default_branch": r.get("default_branch", "main"),
                "private": r.get("private", False),
                "clone_url": r.get("clone_url"),
                "html_url": r.get("html_url"),
                "updated_at": r.get("updated_at"),
            }
            for r in repos
        ]
    }


@router.get("/gh-cli/status")
async def get_gh_cli_status(user: User = Depends(get_current_user)) -> dict:
    from pathlib import Path

    gh_bin = resolve_binary("gh")
    if not gh_bin:
        return {"installed": False, "authenticated": False}
    res = await run_command_capture([gh_bin, "auth", "status"], cwd=Path("."), timeout=10)
    combined = (res["stdout"] + "\n" + res["stderr"]).strip()
    return {
        "installed": True,
        "authenticated": res["returncode"] == 0,
        "details": combined[:300],
    }


@router.post("/connect/gh-cli")
async def connect_via_gh_cli(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    from pathlib import Path

    gh_bin = resolve_binary("gh")
    if not gh_bin:
        raise HTTPException(status_code=400, detail="GitHub CLI (gh) is not installed on this machine")
    tok_res = await run_command_capture([gh_bin, "auth", "token"], cwd=Path("."), timeout=10)
    token = tok_res["stdout"].strip()
    if tok_res["returncode"] != 0 or not token:
        raise HTTPException(
            status_code=400,
            detail="GitHub CLI is not authenticated. Run `gh auth login` in your terminal first.",
        )
    gh = GitHubClient(token)
    try:
        gh_user, scopes = await gh.get_authenticated_user()
    except GitHubAPIError as exc:
        raise HTTPException(status_code=400, detail=f"GitHub rejected gh CLI token: {exc.message}")

    provider_uid = str(gh_user["id"])
    existing = (
        await db.execute(
            select(ConnectedAccount).where(
                ConnectedAccount.user_id == user.id,
                ConnectedAccount.provider == "github",
                ConnectedAccount.provider_user_id == provider_uid,
            )
        )
    ).scalar_one_or_none()
    enc = encrypt_secret(token)
    if existing:
        existing.auth_mode = "gh_cli"
        existing.username = gh_user["login"]
        existing.avatar_url = gh_user.get("avatar_url")
        existing.scopes = scopes or "gh_cli"
        existing.encrypted_access_token = enc
        acct = existing
    else:
        acct = ConnectedAccount(
            user_id=user.id,
            provider="github",
            auth_mode="gh_cli",
            provider_user_id=provider_uid,
            username=gh_user["login"],
            avatar_url=gh_user.get("avatar_url"),
            scopes=scopes or "gh_cli",
            encrypted_access_token=enc,
        )
        db.add(acct)
    await db.commit()
    await db.refresh(acct)
    return {
        "account": {
            "id": acct.id,
            "username": acct.username,
            "avatar_url": acct.avatar_url,
            "scopes": acct.scopes,
            "auth_mode": acct.auth_mode,
        }
    }


@router.post("/device-flow/start")
async def start_github_device_flow(user: User = Depends(get_current_user)) -> dict:
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(status_code=400, detail="GITHUB_CLIENT_ID is not configured in .env")
    try:
        return await GitHubClient.start_device_flow(settings.github_client_id)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post("/device-flow/poll")
async def poll_github_device_flow(
    payload: DevicePollRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(status_code=400, detail="GITHUB_CLIENT_ID is not configured in .env")
    data = await GitHubClient.poll_device_flow(settings.github_client_id, payload.device_code)
    if "access_token" not in data:
        return {"authorized": False, "error": data.get("error", "authorization_pending")}
    access_token = data["access_token"]
    gh = GitHubClient(access_token)
    gh_user, scopes = await gh.get_authenticated_user()
    acct = ConnectedAccount(
        user_id=user.id,
        provider="github",
        auth_mode="oauth_device",
        provider_user_id=str(gh_user["id"]),
        username=gh_user["login"],
        avatar_url=gh_user.get("avatar_url"),
        scopes=scopes or data.get("scope", ""),
        encrypted_access_token=encrypt_secret(access_token),
    )
    db.add(acct)
    await db.commit()
    return {"authorized": True, "username": acct.username}


@router.post("/sync-repo")
async def sync_github_repository(
    payload: SyncGitHubRepoRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        parsed_ref = parse_github_repo_input(payload.full_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    owner, name = parsed_ref["owner"], parsed_ref["name"]
    token = await resolve_github_token(user.id, db)
    gh = GitHubClient(token)
    r: dict | None = None
    try:
        r = await gh.get_repository(owner, name)
    except GitHubAPIError as exc:
        # Fallback to Git smart HTTP protocol (ls-remote) when GitHub REST API is rate-limited
        clone_url = f"https://github.com/{owner}/{name}.git"
        ok, default_br, ls_err = await probe_github_remote_head(clone_url, github_token=token)
        if not ok:
            raise HTTPException(
                status_code=exc.status_code,
                detail=f"GitHub sync failed: {exc.message} (Git fallback: {ls_err})",
            )
        r = {
            "id": None,
            "full_name": f"{owner}/{name}",
            "owner": {"login": owner},
            "name": name,
            "description": "Synced via Git protocol",
            "default_branch": default_br,
            "clone_url": clone_url,
            "html_url": f"https://github.com/{owner}/{name}",
            "private": False,
        }

    existing = (
        await db.execute(
            select(Repository).where(
                Repository.user_id == user.id,
                Repository.source_type == "github",
                Repository.full_name == r["full_name"],
            )
        )
    ).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if existing:
        existing.default_branch = r.get("default_branch", "main")
        existing.description = r.get("description")
        existing.remote_url = r.get("clone_url")
        existing.html_url = r.get("html_url")
        existing.is_private = bool(r.get("private", False))
        existing.github_repo_id = r["id"]
        existing.auto_review_webhooks = payload.auto_review_webhooks
        existing.last_synced_at = now
        repo = existing
    else:
        repo = Repository(
            user_id=user.id,
            source_type="github",
            full_name=r["full_name"],
            owner=r["owner"]["login"],
            name=r["name"],
            description=r.get("description"),
            default_branch=r.get("default_branch", "main"),
            remote_url=r.get("clone_url"),
            html_url=r.get("html_url"),
            github_repo_id=r["id"],
            is_private=bool(r.get("private", False)),
            auto_review_webhooks=payload.auto_review_webhooks,
            last_synced_at=now,
        )
        db.add(repo)

    await db.commit()
    await db.refresh(repo)
    return {
        "repository": {
            "id": repo.id,
            "full_name": repo.full_name,
            "source_type": repo.source_type,
            "default_branch": repo.default_branch,
            "html_url": repo.html_url,
            "is_private": repo.is_private,
            "last_synced_at": repo.last_synced_at.isoformat() if repo.last_synced_at else None,
        },
        "detected_pr_number": parsed_ref.get("pr_number"),
        "detected_commit_sha": parsed_ref.get("commit_sha"),
    }


async def _get_github_repo_and_client(
    repo_id: str, user: User, db: AsyncSession
) -> tuple[Repository, GitHubClient]:
    repo = (
        await db.execute(
            select(Repository).where(Repository.id == repo_id, Repository.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not repo or repo.source_type != "github":
        raise HTTPException(status_code=404, detail="GitHub repository not found")
    token = await resolve_github_token(user.id, db)
    return repo, GitHubClient(token)


@router.get("/repos/{repo_id}/branches")
async def get_repo_branches(
    repo_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo, gh = await _get_github_repo_and_client(repo_id, user, db)
    try:
        branches = await gh.list_branches(repo.owner, repo.name)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    return {
        "branches": [
            {"name": b["name"], "commit_sha": b["commit"]["sha"], "protected": b.get("protected", False)}
            for b in branches
        ]
    }


@router.get("/repos/{repo_id}/commits")
async def get_repo_commits(
    repo_id: str,
    sha: str | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo, gh = await _get_github_repo_and_client(repo_id, user, db)
    try:
        commits = await gh.list_commits(repo.owner, repo.name, sha=sha)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    return {
        "commits": [
            {
                "sha": c["sha"],
                "message": (c.get("commit") or {}).get("message", "").splitlines()[0],
                "author": ((c.get("commit") or {}).get("author") or {}).get("name", ""),
                "date": ((c.get("commit") or {}).get("author") or {}).get("date"),
            }
            for c in commits
        ]
    }


@router.get("/repos/{repo_id}/pulls")
async def get_repo_pulls(
    repo_id: str,
    state: str = "open",
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo, gh = await _get_github_repo_and_client(repo_id, user, db)
    try:
        prs = await gh.list_pull_requests(repo.owner, repo.name, state=state)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    return {
        "pulls": [
            {
                "number": p["number"],
                "title": p["title"],
                "state": p["state"],
                "html_url": p["html_url"],
                "author": (p.get("user") or {}).get("login", ""),
                "base_branch": p["base"]["ref"],
                "base_commit": p["base"]["sha"],
                "head_branch": p["head"]["ref"],
                "head_commit": p["head"]["sha"],
                "updated_at": p.get("updated_at"),
            }
            for p in prs
        ]
    }


@router.get("/repos/{repo_id}/pulls/{pr_number}/diff")
async def get_pr_diff_preview(
    repo_id: str,
    pr_number: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo, gh = await _get_github_repo_and_client(repo_id, user, db)
    try:
        pr = await gh.get_pull_request(repo.owner, repo.name, pr_number)
        diff_text, files = await gh.get_pull_request_diff(repo.owner, repo.name, pr_number)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    parsed = parse_unified_diff(diff_text)
    return {
        "pr_number": pr_number,
        "title": pr["title"],
        "base_branch": pr["base"]["ref"],
        "base_commit": pr["base"]["sha"],
        "head_branch": pr["head"]["ref"],
        "target_commit": pr["head"]["sha"],
        "diff_text": diff_text,
        "changed_files": [p.to_dict() for p in parsed] if parsed else [
            {
                "path": f["filename"],
                "status": f.get("status", "modified"),
                "additions": f.get("additions", 0),
                "deletions": f.get("deletions", 0),
                "changed_lines": [],
                "patch": f.get("patch", ""),
            }
            for f in files
        ],
    }


@router.get("/repos/{repo_id}/compare")
async def compare_repo_refs(
    repo_id: str,
    base: str,
    head: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo, gh = await _get_github_repo_and_client(repo_id, user, db)
    try:
        cmp_data = await gh.compare_commits(repo.owner, repo.name, base, head)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    diff_text = cmp_data.get("diff_text", "")
    parsed = parse_unified_diff(diff_text)
    commits = cmp_data.get("commits", [])
    base_sha = (cmp_data.get("base_commit") or {}).get("sha", base)
    target_sha = commits[-1]["sha"] if commits else (cmp_data.get("merge_base_commit") or {}).get("sha", head)
    return {
        "base_commit": base_sha,
        "target_commit": target_sha,
        "diff_text": diff_text,
        "changed_files": [p.to_dict() for p in parsed],
    }


@router.get("/repos/{repo_id}/commits/{sha}/diff")
async def get_commit_diff_preview(
    repo_id: str,
    sha: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo, gh = await _get_github_repo_and_client(repo_id, user, db)
    try:
        c_data = await gh.get_commit_diff(repo.owner, repo.name, sha)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    parsed = parse_unified_diff(c_data["diff_text"])
    return {
        "base_commit": c_data["base_commit"],
        "target_commit": c_data["target_commit"],
        "message": c_data["message"],
        "diff_text": c_data["diff_text"],
        "changed_files": [p.to_dict() for p in parsed],
    }


@router.post("/repos/{repo_id}/sync-prs")
async def sync_open_pull_requests(
    repo_id: str,
    auto_review: bool = True,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo = (
        await db.execute(
            select(Repository).where(Repository.id == repo_id, Repository.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not repo or repo.source_type != "github":
        raise HTTPException(status_code=404, detail="GitHub repository not found")
    token = await resolve_github_token(user.id, db)
    try:
        return await sync_repository_open_prs(
            repo, token, db, auto_trigger_new_commits=auto_review
        )
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post("/repos/{repo_id}/register-webhook")
async def register_repo_webhook(
    repo_id: str,
    payload: RegisterWebhookRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo, gh = await _get_github_repo_and_client(repo_id, user, db)
    if not gh.token:
        raise HTTPException(status_code=400, detail="GitHub token with admin:repo_hook or repo scope required")
    secret = payload.secret or get_settings().github_webhook_secret
    try:
        hook = await gh.create_repo_webhook(
            repo.owner,
            repo.name,
            webhook_url=payload.webhook_url.strip(),
            secret=secret,
        )
        return {"registered": True, "hook_id": hook.get("id"), "url": payload.webhook_url}
    except GitHubAPIError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post("/reviews/{review_id}/publish")
async def publish_review_to_github(
    review_id: str,
    payload: PublishReviewRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    rev = (await db.execute(select(Review).where(Review.id == review_id))).scalar_one_or_none()
    if not rev:
        raise HTTPException(status_code=404, detail="Review not found")
    repo = (
        await db.execute(
            select(Repository).where(Repository.id == rev.repository_id, Repository.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not repo or repo.source_type != "github":
        raise HTTPException(status_code=400, detail="Review does not belong to a GitHub repository")
    cc = (await db.execute(select(CodeChange).where(CodeChange.id == rev.code_change_id))).scalar_one()

    token = await resolve_github_token(user.id, db)
    if not token:
        raise HTTPException(status_code=400, detail="No GitHub token connected to publish review")
    gh = GitHubClient(token)

    artifact = (
        await db.execute(
            select(ReviewArtifact).where(
                ReviewArtifact.review_id == rev.id,
                ReviewArtifact.artifact_type == "consolidated_report_md",
            )
        )
    ).scalar_one_or_none()
    body = payload.custom_body or (artifact.content if artifact else f"ReviewBoard Recommendation: **{rev.recommendation}**\n\n{rev.recommendation_reason}")

    published_info: dict = {}
    if cc.pr_number:
        inline_comments: list[dict] = []
        if payload.include_inline_comments:
            valid_lines_by_file = {
                cf.get("path"): set(cf.get("changed_lines") or [])
                for cf in (cc.changed_files or [])
            }
            findings = (
                await db.execute(select(Finding).where(Finding.review_id == rev.id).order_by(Finding.priority_rank))
            ).scalars().all()
            for f in findings[:20]:
                if f.line_number and f.line_number in valid_lines_by_file.get(f.file_path, set()):
                    inline_comments.append(
                        {
                            "path": f.file_path,
                            "line": f.line_number,
                            "side": "RIGHT",
                            "body": (
                                f"**[{f.severity}] {f.title}** ({f.verification_status})\n"
                                f"- **Agent:** {f.agent} (`{f.tool_name or 'analysis'}`)\n"
                                f"- **Evidence:** `{f.evidence[:200]}`\n"
                                f"- **Recommendation:** {f.recommendation}"
                            ),
                        }
                    )

        gh_event = (
            "APPROVE"
            if rev.recommendation == "Approve"
            else "REQUEST_CHANGES"
            if rev.recommendation == "Request Changes"
            else "COMMENT"
        )
        try:
            pr_review = await gh.create_pull_request_review(
                repo.owner,
                repo.name,
                cc.pr_number,
                commit_id=rev.target_commit,
                body=body[:60000],
                event=gh_event,
                comments=inline_comments or None,
            )
            rev.github_review_id = pr_review.get("id")
            rev.github_published_at = datetime.now(timezone.utc)
            published_info["pr_review_id"] = pr_review.get("id")
            published_info["pr_review_url"] = pr_review.get("html_url")
            published_info["inline_comments_posted"] = len(inline_comments)
        except GitHubAPIError as exc:
            raise HTTPException(status_code=exc.status_code, detail=f"Failed posting PR review: {exc.message}")

    if payload.include_commit_status and len(rev.target_commit) >= 7:
        gh_state = (
            "success"
            if rev.recommendation == "Approve"
            else "failure"
            if rev.recommendation == "Request Changes"
            else "error"
        )
        try:
            st = await gh.create_commit_status(
                repo.owner,
                repo.name,
                rev.target_commit,
                state=gh_state,
                description=f"ReviewBoard: {rev.recommendation} — {rev.recommendation_reason[:90]}",
            )
            published_info["commit_status_id"] = st.get("id")
        except GitHubAPIError as exc:
            published_info["commit_status_error"] = exc.message

    await db.commit()
    return {"published": True, **published_info}


@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    settings = get_settings()
    raw_body = await request.body()
    if settings.github_webhook_secret and not GitHubClient.verify_webhook_signature(
        raw_body, x_hub_signature_256, settings.github_webhook_secret
    ):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")

    payload = await request.json()
    if x_github_event == "ping":
        return {"ok": True, "event": "ping"}

    repo_info = payload.get("repository") or {}
    full_name = repo_info.get("full_name")
    if not full_name:
        return {"ignored": True, "reason": "No repository in webhook payload"}

    repo = (
        await db.execute(
            select(Repository).where(
                Repository.full_name == full_name,
                Repository.source_type == "github",
                Repository.auto_review_webhooks.is_(True),
            )
        )
    ).scalar_one_or_none()
    if not repo:
        return {"ignored": True, "reason": f"Repository {full_name} is not registered for auto-review"}

    token = await resolve_github_token(repo.user_id, db)
    gh = GitHubClient(token)

    if x_github_event == "pull_request" and payload.get("action") in ("opened", "synchronize", "reopened"):
        pr = payload["pull_request"]
        pr_number = int(pr["number"])
        diff_text, _files = await gh.get_pull_request_diff(repo.owner, repo.name, pr_number)
        parsed = parse_unified_diff(diff_text)
        base_sha = pr["base"]["sha"]
        head_sha = pr["head"]["sha"]
        cc = CodeChange(
            repository_id=repo.id,
            source_mode="github_pr",
            pr_number=pr_number,
            pr_title=pr.get("title"),
            pr_url=pr.get("html_url"),
            base_branch=pr["base"]["ref"],
            target_branch=pr["head"]["ref"],
            base_commit=base_sha,
            target_commit=head_sha,
            diff_text=diff_text,
            changed_files=[p.to_dict() for p in parsed] if parsed else [],
        )
        db.add(cc)
        await db.flush()
        rev = Review(
            repository_id=repo.id,
            code_change_id=cc.id,
            triggered_by=f"github_webhook:pr#{pr_number}",
            base_commit=base_sha,
            target_commit=head_sha,
            review_status="queued",
            recommendation="Pending",
        )
        db.add(rev)
        await db.commit()
        launch_review_job(rev.id)
        return {"triggered": True, "review_id": rev.id, "pr_number": pr_number}

    if x_github_event == "push":
        before = payload.get("before", "")
        after = payload.get("after", "")
        if not before or not after or after == "0" * 40:
            return {"ignored": True, "reason": "Branch deletion or empty push"}
        cmp_data = await gh.compare_commits(repo.owner, repo.name, before, after)
        diff_text = cmp_data.get("diff_text", "")
        parsed = parse_unified_diff(diff_text)
        branch = str(payload.get("ref", "")).replace("refs/heads/", "")
        cc = CodeChange(
            repository_id=repo.id,
            source_mode="github_compare",
            base_branch=branch,
            target_branch=branch,
            base_commit=before,
            target_commit=after,
            diff_text=diff_text,
            changed_files=[p.to_dict() for p in parsed],
        )
        db.add(cc)
        await db.flush()
        rev = Review(
            repository_id=repo.id,
            code_change_id=cc.id,
            triggered_by=f"github_webhook:push:{branch}",
            base_commit=before,
            target_commit=after,
            review_status="queued",
            recommendation="Pending",
        )
        db.add(rev)
        await db.commit()
        launch_review_job(rev.id)
        return {"triggered": True, "review_id": rev.id, "branch": branch}

    return {"ignored": True, "event": x_github_event}
