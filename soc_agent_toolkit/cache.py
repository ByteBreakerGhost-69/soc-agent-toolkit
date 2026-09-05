"""
cache.py — Simple TTL cache for enrichment lookups.

Default backend is a process-local in-memory dict (zero setup, fine for a
single CLI run or a single agent process). If SOC_REDIS_URL is set, uses
Redis instead so a cache can be shared across multiple agent workers/processes.

Usage:
    from .cache import get_cache
    cache = get_cache()
    hit = cache.get("ip:1.2.3.4")
    if hit is None:
        hit = do_expensive_lookup()
        cache.set("ip:1.2.3.4", hit, ttl_seconds=3600)
"""

from __future__ import annotations

import json
import time
from typing import Any

from . import config
from .logging_setup import get_logger

logger = get_logger(__name__)


class InMemoryTTLCache:
    """Process-local cache: dict of key -> (expires_at_epoch, value)."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if time.time() >= expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        self._store[key] = (time.time() + ttl_seconds, value)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


class RedisTTLCache:
    """Thin wrapper around redis-py giving the same get/set interface, JSON-serialized."""

    def __init__(self, url: str) -> None:
        import redis  # imported lazily so redis isn't a hard dependency

        self._client = redis.Redis.from_url(url)

    def get(self, key: str) -> Any | None:
        raw = self._client.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        self._client.set(key, json.dumps(value, default=str), ex=ttl_seconds)

    def clear(self) -> None:
        logger.warning("RedisTTLCache.clear() is a no-op by design (would affect shared cache); flush manually if needed.")


_CACHE_INSTANCE: InMemoryTTLCache | RedisTTLCache | None = None


def get_cache() -> InMemoryTTLCache | RedisTTLCache:
    """Return the process-wide cache instance, choosing backend based on config.REDIS_URL."""
    global _CACHE_INSTANCE
    if _CACHE_INSTANCE is not None:
        return _CACHE_INSTANCE

    if config.REDIS_URL:
        try:
            _CACHE_INSTANCE = RedisTTLCache(config.REDIS_URL)
            logger.info("Using Redis cache backend at %s", config.REDIS_URL)
            return _CACHE_INSTANCE
        except Exception:
            logger.exception("Failed to connect to Redis; falling back to in-memory cache")

    _CACHE_INSTANCE = InMemoryTTLCache()
    logger.info("Using in-memory cache backend")
    return _CACHE_INSTANCE
