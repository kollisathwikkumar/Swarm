"""Incremental caching layer keyed by content, tool version, configuration, and commit context."""

from app.cache.review_cache import (
    CacheStats,
    ReviewCache,
    compute_cache_key,
    hash_config_dict,
    hash_files_content,
    hash_text,
)

__all__ = [
    "CacheStats",
    "ReviewCache",
    "compute_cache_key",
    "hash_config_dict",
    "hash_files_content",
    "hash_text",
]
