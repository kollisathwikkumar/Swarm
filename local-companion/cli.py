#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent))

from diff_extractor import extract_diff
from local_service import app, pairing_manager
from repository_reader import inspect_repository, validate_repo_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Swarm Local Review Companion CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_p = sub.add_parser("serve", help="Run the Local Review Companion daemon on 127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8765)

    insp_p = sub.add_parser("inspect", help="Inspect a local Git repository")
    insp_p.add_argument("path")

    sub_p = sub.add_parser("submit", help="Extract local Git diff and submit to Swarm backend")
    sub_p.add_argument("path")
    sub_p.add_argument("--backend", default="http://127.0.0.1:8000")
    sub_p.add_argument("--token", default="", help="Optional Swarm JWT Bearer token")
    sub_p.add_argument("--mode", default="working_tree", choices=["working_tree", "staged", "unstaged", "commits"])
    sub_p.add_argument("--base", default="HEAD~1")
    sub_p.add_argument("--target", default="HEAD")

    args = parser.parse_args()

    if args.command == "serve":
        token, _ = pairing_manager.rotate()
        print("=" * 64)
        print("Swarm Local Review Companion running on http://127.0.0.1:" + str(args.port))
        print(f"Pairing Token (valid 30 min): {token}")
        print("=" * 64)
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="info")
    elif args.command == "inspect":
        repo_path = validate_repo_path(args.path)
        print(json.dumps(inspect_repository(repo_path), indent=2))
    elif args.command == "submit":
        repo_path = validate_repo_path(args.path)
        diff_data = extract_diff(repo_path, mode=args.mode, base_ref=args.base, target_ref=args.target)
        if not diff_data["diff_text"].strip():
            print("No changes detected to submit.", file=sys.stderr)
            sys.exit(1)
        resp = httpx.post(
            args.backend.rstrip("/") + "/api/repositories/companion/submit",
            headers={"Authorization": f"Bearer {args.token}"} if args.token else {},
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
            timeout=30.0,
        )
        print(resp.status_code, resp.text)
        sys.exit(0 if resp.status_code < 400 else 1)


if __name__ == "__main__":
    main()
