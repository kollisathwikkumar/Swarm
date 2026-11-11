from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Any
from urllib.parse import urlparse

import httpx


class GitHubAPIError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"GitHub API {status_code}: {message}")


def parse_github_repo_input(raw_input: str) -> dict[str, Any]:
    """
    Parse flexible GitHub inputs into {owner, name, full_name, pr_number, commit_sha}.
    Supports:
      - owner/repo
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
      - https://github.com/owner/repo/pull/12
      - https://github.com/owner/repo/commit/<sha>
      - git@github.com:owner/repo.git
    """
    text = (raw_input or "").strip()
    if not text:
        raise ValueError("Repository input cannot be empty")

    # Handle SSH git@github.com:owner/repo(.git)
    ssh_match = re.match(r"^git@github\.com:([^/]+)/([^/\s]+?)(?:\.git)?/?$", text, re.IGNORECASE)
    if ssh_match:
        owner, name = ssh_match.group(1), ssh_match.group(2)
        return {"owner": owner, "name": name, "full_name": f"{owner}/{name}", "pr_number": None, "commit_sha": None}

    # Handle HTTP(S) URLs
    if text.startswith(("http://", "https://", "github.com/")):
        normalized = text if text.startswith("http") else f"https://{text}"
        parsed = urlparse(normalized)
        if "github.com" not in (parsed.netloc or "").lower():
            raise ValueError("Only github.com repository URLs are supported")
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 2:
            raise ValueError("URL must include owner and repository name (e.g. https://github.com/owner/repo)")
        owner = parts[0]
        name = parts[1].removesuffix(".git")
        pr_number = None
        commit_sha = None
        if len(parts) >= 4 and parts[2] == "pull" and parts[3].isdigit():
            pr_number = int(parts[3])
        elif len(parts) >= 4 and parts[2] == "commit":
            commit_sha = parts[3]
        return {
            "owner": owner,
            "name": name,
            "full_name": f"{owner}/{name}",
            "pr_number": pr_number,
            "commit_sha": commit_sha,
        }

    # Handle plain owner/repo
    cleaned = text.removesuffix(".git")
    parts = [p for p in cleaned.strip("/").split("/") if p]
    if len(parts) != 2:
        raise ValueError("Enter owner/repo or a full https://github.com/owner/repo URL")
    owner, name = parts
    return {"owner": owner, "name": name, "full_name": f"{owner}/{name}", "pr_number": None, "commit_sha": None}


class GitHubClient:
    """Async GitHub REST API v3 client for repo sync, PR diffs, commits, webhooks, and review publishing."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: str = "") -> None:
        self.token = token.strip()

    def _headers(self, accept: str = "application/vnd.github+json") -> dict[str, str]:
        headers = {
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Swarm-MultiAgent/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        accept: str = "application/vnd.github+json",
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        raw_text: bool = False,
    ) -> Any:
        url = path if path.startswith("http") else f"{self.BASE_URL}{path}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(
                method,
                url,
                headers=self._headers(accept),
                params=params,
                json=json_body,
            )
        if resp.status_code >= 400:
            try:
                err_json = resp.json()
                msg = err_json.get("message") or resp.text
            except ValueError:
                msg = resp.text
            raise GitHubAPIError(resp.status_code, msg)
        if raw_text:
            return resp.text
        return resp.json() if resp.content else {}

    @staticmethod
    async def exchange_oauth_code(
        client_id: str, client_secret: str, code: str, redirect_uri: str
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                json={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
            )
        data = resp.json()
        if resp.status_code >= 400 or "error" in data:
            raise GitHubAPIError(resp.status_code, data.get("error_description") or str(data))
        return data

    @staticmethod
    async def start_device_flow(client_id: str, scope: str = "repo read:user") -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                "https://github.com/login/device/code",
                headers={"Accept": "application/json"},
                data={"client_id": client_id, "scope": scope},
            )
        data = resp.json()
        if resp.status_code >= 400 or "error" in data:
            raise GitHubAPIError(resp.status_code, data.get("error_description") or str(data))
        return data

    @staticmethod
    async def poll_device_flow(client_id: str, device_code: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": client_id,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
            )
        return resp.json()

    async def get_authenticated_user(self) -> tuple[dict[str, Any], str]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(f"{self.BASE_URL}/user", headers=self._headers())
        if resp.status_code >= 400:
            raise GitHubAPIError(resp.status_code, resp.text)
        scopes = resp.headers.get("X-OAuth-Scopes", "")
        return resp.json(), scopes

    async def list_repositories(self, per_page: int = 50) -> list[dict[str, Any]]:
        return await self._request(
            "GET",
            "/user/repos",
            params={"sort": "updated", "affiliation": "owner,collaborator,organization_member", "per_page": per_page},
        )

    async def get_repository(self, owner: str, repo: str) -> dict[str, Any]:
        return await self._request("GET", f"/repos/{owner}/{repo}")

    async def list_branches(self, owner: str, repo: str) -> list[dict[str, Any]]:
        return await self._request("GET", f"/repos/{owner}/{repo}/branches", params={"per_page": 100})

    async def list_commits(
        self, owner: str, repo: str, sha: str | None = None, per_page: int = 30
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"per_page": per_page}
        if sha:
            params["sha"] = sha
        return await self._request("GET", f"/repos/{owner}/{repo}/commits", params=params)

    async def get_commit_diff(self, owner: str, repo: str, sha: str) -> dict[str, Any]:
        commit_json = await self._request("GET", f"/repos/{owner}/{repo}/commits/{sha}")
        diff_text = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/commits/{sha}",
            accept="application/vnd.github.v3.diff",
            raw_text=True,
        )
        parents = commit_json.get("parents") or []
        base_sha = parents[0]["sha"] if parents else commit_json["sha"]
        return {
            "base_commit": base_sha,
            "target_commit": commit_json["sha"],
            "message": (commit_json.get("commit") or {}).get("message", ""),
            "diff_text": diff_text,
            "files": commit_json.get("files", []),
        }

    async def list_pull_requests(
        self, owner: str, repo: str, state: str = "open"
    ) -> list[dict[str, Any]]:
        return await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls",
            params={"state": state, "sort": "updated", "direction": "desc", "per_page": 50},
        )

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> dict[str, Any]:
        return await self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}")

    async def get_pull_request_diff(
        self, owner: str, repo: str, pr_number: int
    ) -> tuple[str, list[dict[str, Any]]]:
        diff_text = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pr_number}",
            accept="application/vnd.github.v3.diff",
            raw_text=True,
        )
        files = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
            params={"per_page": 100},
        )
        return diff_text, files

    async def compare_commits(
        self, owner: str, repo: str, base: str, head: str
    ) -> dict[str, Any]:
        compare_json = await self._request(
            "GET", f"/repos/{owner}/{repo}/compare/{base}...{head}"
        )
        diff_text = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/compare/{base}...{head}",
            accept="application/vnd.github.v3.diff",
            raw_text=True,
        )
        compare_json["diff_text"] = diff_text
        return compare_json

    async def get_file_content(
        self, owner: str, repo: str, path: str, ref: str
    ) -> tuple[str, str]:
        data = await self._request(
            "GET", f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref}
        )
        encoded = data.get("content", "")
        sha = data.get("sha", "")
        if not encoded and sha and data.get("size", 0) > 0:
            # Files >1MB via Contents API need Git Blobs API
            blob = await self._request("GET", f"/repos/{owner}/{repo}/git/blobs/{sha}")
            encoded = blob.get("content", "")
        decoded = base64.b64decode(encoded).decode("utf-8", errors="replace") if encoded else ""
        return decoded, sha

    async def get_repo_tree(
        self, owner: str, repo: str, ref: str
    ) -> dict[str, Any]:
        # Resolve ref -> commit/tree SHA first via branches or commits
        tree_data = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/git/trees/{ref}",
            params={"recursive": "1"},
        )
        return tree_data

    async def create_pull_request_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        *,
        commit_id: str,
        body: str,
        event: str,
        comments: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "commit_id": commit_id,
            "body": body,
            "event": event,
        }
        if comments:
            payload["comments"] = comments
        return await self._request(
            "POST", f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews", json_body=payload
        )

    async def create_commit_status(
        self,
        owner: str,
        repo: str,
        sha: str,
        *,
        state: str,
        description: str,
        target_url: str | None = None,
        context: str = "Swarm / Multi-Agent Review",
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "state": state,
            "description": description[:140],
            "context": context,
        }
        if target_url:
            payload["target_url"] = target_url
        return await self._request(
            "POST", f"/repos/{owner}/{repo}/statuses/{sha}", json_body=payload
        )

    async def create_pr_comment_suggestion(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        *,
        commit_id: str,
        path: str,
        line: int,
        suggestion_code: str,
        explanation: str,
        start_line: int | None = None,
    ) -> dict[str, Any]:
        body = f"**Swarm Fix Suggestion**\n\n{explanation}\n\n```suggestion\n{suggestion_code}\n```"
        payload: dict[str, Any] = {
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line,
            "side": "RIGHT",
        }
        if start_line is not None and start_line < line:
            payload["start_line"] = start_line
            payload["start_side"] = "RIGHT"
        return await self._request(
            "POST", f"/repos/{owner}/{repo}/pulls/{pr_number}/comments", json_body=payload
        )

    async def commit_file_update(
        self,
        owner: str,
        repo: str,
        *,
        path: str,
        branch: str,
        message: str,
        new_content: str,
        file_sha: str,
    ) -> dict[str, Any]:
        encoded = base64.b64encode(new_content.encode("utf-8")).decode("ascii")
        payload = {
            "message": message,
            "content": encoded,
            "sha": file_sha,
            "branch": branch,
        }
        return await self._request("PUT", f"/repos/{owner}/{repo}/contents/{path}", json_body=payload)

    async def create_repo_webhook(
        self,
        owner: str,
        repo: str,
        *,
        webhook_url: str,
        secret: str = "",
    ) -> dict[str, Any]:
        config: dict[str, Any] = {
            "url": webhook_url,
            "content_type": "json",
            "insecure_ssl": "0",
        }
        if secret:
            config["secret"] = secret
        payload = {
            "name": "web",
            "active": True,
            "events": ["pull_request", "push"],
            "config": config,
        }
        return await self._request("POST", f"/repos/{owner}/{repo}/hooks", json_body=payload)

    @staticmethod
    def verify_webhook_signature(payload_body: bytes, signature_header: str | None, secret: str) -> bool:
        if not secret or not signature_header or not signature_header.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(
            secret.encode("utf-8"), payload_body, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature_header)
