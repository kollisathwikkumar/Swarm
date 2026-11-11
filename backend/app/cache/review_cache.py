from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCANNER_CACHE_SCHEMA_VERSION = "swarm-scanner-cache-v1"
STRUCTURE_INDEX_SCHEMA_VERSION = "swarm-structure-index-v1"


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def hash_config_dict(cfg: dict[str, Any] | None) -> str:
    serialized = json.dumps(cfg or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def hash_files_content(workspace_dir: Path, rel_paths: list[str]) -> str:
    """Compute a deterministic SHA-256 digest over all targeted files' paths and bytes."""
    hasher = hashlib.sha256()
    for rel in sorted(dict.fromkeys(rel_paths)):
        target = (workspace_dir / rel).resolve()
        try:
            ws_res = workspace_dir.resolve()
            if ws_res not in target.parents or not target.exists() or not target.is_file():
                hasher.update(f"{rel}:MISSING\n".encode())
                continue
            hasher.update(f"{rel}:".encode())
            hasher.update(target.read_bytes())
            hasher.update(b"\n")
        except OSError:
            hasher.update(f"{rel}:ERR\n".encode())
    return hasher.hexdigest()


def compute_cache_key(
    *,
    content_hash: str,
    tool_version: str,
    configuration_hash: str,
    commit_context: str,
) -> str:
    """
    Deterministic cache invalidation contract:
      sha256(content_hash + tool_version + configuration_hash + commit_context)
    """
    payload = f"{content_hash}|{tool_version}|{configuration_hash}|{commit_context}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    writes: int = 0
    invalidations: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "invalidations": self.invalidations,
        }


class ReviewCache:
    """
    Content-addressed on-disk incremental JSON cache under `_cache/<namespace>/`.
    Entries automatically miss whenever file contents, tool version/rules,
    policy configuration, or commit context change.
    """

    def __init__(self, cache_root: Path, max_entries_per_ns: int = 250) -> None:
        self.root = cache_root
        self.max_entries_per_ns = max_entries_per_ns
        self.stats = CacheStats()

    def _entry_path(self, namespace: str, cache_key: str) -> Path:
        safe_ns = "".join(ch for ch in namespace if ch.isalnum() or ch in ("_", "-")) or "default"
        safe_key = "".join(ch for ch in cache_key if ch.isalnum())[:64]
        return self.root / safe_ns / f"{safe_key}.json"

    def get(
        self,
        namespace: str,
        *,
        content_hash: str,
        tool_version: str,
        configuration_hash: str,
        commit_context: str,
    ) -> Any | None:
        key = compute_cache_key(
            content_hash=content_hash,
            tool_version=tool_version,
            configuration_hash=configuration_hash,
            commit_context=commit_context,
        )
        path = self._entry_path(namespace, key)
        if not path.exists():
            self.stats.misses += 1
            return None
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            meta = envelope.get("contract") or {}
            if (
                meta.get("content_hash") != content_hash
                or meta.get("tool_version") != tool_version
                or meta.get("configuration_hash") != configuration_hash
                or meta.get("commit_context") != commit_context
            ):
                self.stats.invalidations += 1
                self.stats.misses += 1
                path.unlink(missing_ok=True)
                return None
            # Touch mtime for simple LRU ordering
            os.utime(path, None)
            self.stats.hits += 1
            return envelope.get("value")
        except (OSError, ValueError, TypeError) as exc:
            logger.debug("Invalidating corrupted cache entry %s: %s", path, exc)
            path.unlink(missing_ok=True)
            self.stats.invalidations += 1
            self.stats.misses += 1
            return None

    def set(
        self,
        namespace: str,
        *,
        content_hash: str,
        tool_version: str,
        configuration_hash: str,
        commit_context: str,
        value: Any,
    ) -> str:
        key = compute_cache_key(
            content_hash=content_hash,
            tool_version=tool_version,
            configuration_hash=configuration_hash,
            commit_context=commit_context,
        )
        path = self._entry_path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        envelope = {
            "contract": {
                "content_hash": content_hash,
                "tool_version": tool_version,
                "configuration_hash": configuration_hash,
                "commit_context": commit_context,
            },
            "value": value,
        }
        payload = json.dumps(envelope, separators=(",", ":"), default=str)
        fd, tmp_name = tempfile.mkstemp(prefix=".cache_", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp_name, path)
            self.stats.writes += 1
        except OSError as exc:
            logger.debug("Cache write skipped for %s: %s", path, exc)
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError as rm_exc:
                _ = rm_exc
            return key
        self._prune_namespace(path.parent)
        return key

    def _prune_namespace(self, ns_dir: Path) -> None:
        try:
            entries = sorted(
                (p for p in ns_dir.glob("*.json") if p.is_file()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for stale in entries[self.max_entries_per_ns :]:
                stale.unlink(missing_ok=True)
        except OSError as exc:
            logger.debug("Cache pruning skipped for %s: %s", ns_dir, exc)
