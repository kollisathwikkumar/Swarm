from __future__ import annotations

import hmac
import secrets
import time
from urllib.parse import urlparse

import httpx
from diff_extractor import extract_diff
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from repository_reader import inspect_repository, validate_repo_path


class PairingTokenManager:
    def __init__(self, ttl_seconds: int = 1800) -> None:
        self.ttl_seconds = ttl_seconds
        self.token = secrets.token_urlsafe(24)
        self.expires_at = time.time() + ttl_seconds

    def rotate(self) -> tuple[str, float]:
        self.token = secrets.token_urlsafe(24)
        self.expires_at = time.time() + self.ttl_seconds
        return self.token, self.expires_at

    def verify(self, candidate: str | None) -> bool:
        if not candidate or time.time() > self.expires_at:
            return False
        return hmac.compare_digest(self.token, candidate.strip())


pairing_manager = PairingTokenManager()

app = FastAPI(title="Swarm Local Review Companion", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_pairing(x_pairing_token: str | None = Header(default=None)) -> None:
    if not pairing_manager.verify(x_pairing_token):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired pairing token. Check the Local Review Companion terminal for the current token.",
        )


class InspectRequest(BaseModel):
    local_path: str = Field(min_length=1, max_length=1000)


class DiffRequest(BaseModel):
    local_path: str = Field(min_length=1, max_length=1000)
    mode: str = "working_tree"
    base_ref: str = "HEAD~1"
    target_ref: str = "HEAD"


class SubmitReviewRequest(DiffRequest):
    backend_url: str = "http://127.0.0.1:8000"
    auth_token: str | None = None

    @field_validator("backend_url")
    @classmethod
    def _validate_backend_url(cls, val: str) -> str:
        parsed = urlparse(val.strip())
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "https" and parsed.netloc:
            return val.strip()
        if parsed.scheme == "http" and host in ("127.0.0.1", "localhost", "::1"):
            return val.strip()
        raise ValueError("backend_url must use https:// or http://localhost / http://127.0.0.1")


@app.get("/health")
def health() -> dict:
    ttl_left = max(0, int(pairing_manager.expires_at - time.time()))
    return {
        "status": "ok",
        "service": "reviewboard-local-companion",
        "bind": "127.0.0.1",
        "token_ttl_seconds": ttl_left,
    }


@app.post("/repos/inspect", dependencies=[Depends(require_pairing)])
def inspect_repo_endpoint(payload: InspectRequest) -> dict:
    try:
        repo_path = validate_repo_path(payload.local_path)
        return inspect_repository(repo_path)
    except (PermissionError, ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/repos/diff", dependencies=[Depends(require_pairing)])
def extract_diff_endpoint(payload: DiffRequest) -> dict:
    try:
        repo_path = validate_repo_path(payload.local_path)
        return extract_diff(
            repo_path,
            mode=payload.mode,
            base_ref=payload.base_ref,
            target_ref=payload.target_ref,
        )
    except (PermissionError, ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/repos/submit", dependencies=[Depends(require_pairing)])
async def submit_to_backend_endpoint(payload: SubmitReviewRequest) -> dict:
    try:
        repo_path = validate_repo_path(payload.local_path)
        diff_data = extract_diff(
            repo_path,
            mode=payload.mode,
            base_ref=payload.base_ref,
            target_ref=payload.target_ref,
        )
    except (PermissionError, ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not diff_data["diff_text"].strip():
        raise HTTPException(status_code=400, detail="No changes found to submit.")

    url = payload.backend_url.rstrip("/") + "/api/repositories/companion/submit"
    headers = {"Authorization": f"Bearer {payload.auth_token}"} if payload.auth_token else {}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            url,
            headers=headers,
            json={
                "repository_name": diff_data["repository_name"],
                "local_path": diff_data["local_path"],
                "base_branch": diff_data["base_branch"],
                "target_branch": diff_data["target_branch"],
                "base_commit": diff_data["base_commit"],
                "target_commit": diff_data["target_commit"],
                "diff_text": diff_data["diff_text"],
                "file_snapshots": diff_data["file_snapshots"],
            },
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()
