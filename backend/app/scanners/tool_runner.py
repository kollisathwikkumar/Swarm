from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any


def resolve_binary(name: str) -> str | None:
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.exists() and os.access(venv_bin, os.X_OK):
        return str(venv_bin)
    for extra_dir in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"):
        candidate = Path(extra_dir) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def sanitized_subprocess_env(extra_paths: list[str] | None = None) -> dict[str, str]:
    """Build a clean environment for running repository scanners/tests without exposing Swarm secrets."""
    venv_bin = str(Path(sys.executable).parent)
    base_path = os.environ.get("PATH", "/usr/bin:/bin")
    path_parts = [venv_bin, "/opt/homebrew/bin", "/usr/local/bin", base_path]
    if extra_paths:
        path_parts = extra_paths + path_parts
    env = {
        "PATH": ":".join(path_parts),
        "HOME": os.environ.get("HOME") or tempfile.gettempdir(),
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    return env


async def run_command_capture(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd),
        env=env or sanitized_subprocess_env(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        timed_out = False
    except asyncio.CancelledError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(ProcessLookupError, OSError):
            await proc.wait()
        raise
    except TimeoutError:
        proc.kill()
        stdout_b, stderr_b = await proc.communicate()
        timed_out = True
    return {
        "returncode": 124 if timed_out else (proc.returncode or 0),
        "stdout": stdout_b.decode("utf-8", errors="replace"),
        "stderr": stderr_b.decode("utf-8", errors="replace"),
        "timed_out": timed_out,
    }


_TOOL_VERSION_CACHE: dict[str, str] = {}


async def get_tool_version(name: str, args: tuple[str, ...] = ("--version",)) -> str:
    """Return a cached single-line version string for deterministic scanner cache keys."""
    if name in _TOOL_VERSION_CACHE:
        return _TOOL_VERSION_CACHE[name]
    bin_path = resolve_binary(name)
    if not bin_path:
        _TOOL_VERSION_CACHE[name] = "missing"
        return "missing"
    res = await run_command_capture(
        [bin_path, *args],
        cwd=Path(tempfile.gettempdir()),
        timeout=8,
    )
    first_line = next((ln.strip() for ln in (res["stdout"] or res["stderr"] or "").splitlines() if ln.strip()), "unknown")
    ver = first_line[:120]
    _TOOL_VERSION_CACHE[name] = ver
    return ver


async def check_installed_scanners() -> dict[str, dict[str, Any]]:
    tools = ["git", "semgrep", "gitleaks", "bandit", "osv-scanner", "ruff", "pytest", "coverage", "node"]
    status: dict[str, dict[str, Any]] = {}
    for tool in tools:
        path = resolve_binary(tool)
        status[tool] = {"available": path is not None, "path": path or ""}
    return status
