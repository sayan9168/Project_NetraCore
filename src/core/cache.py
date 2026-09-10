"""
Two-tier cache: Redis when available, in-memory TTL fallback otherwise.

API is async-first so call sites don't care which backend is active.
Synchronous helpers are provided for non-async contexts (CLI, seeders).
"""

import json
import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger("netra.cache")


class MemoryCache:
    """Thread-safe in-memory TTL cache."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            expires_at, value = item
            if expires_at < time.time():
                self._store.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any, ttl: int = 300) -> None:
        with self._lock:
            self._prune_locked()
            self._store[key] = (time.time() + max(ttl, 1), value)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def _prune_locked(self) -> None:
        if len(self._store) < 2000:
            return
        now = time.time()
        expired = [k for k, (exp, _) in self._store.items() if exp < now]
        for k in expired:
            self._store.pop(k, None)


class Cache:
    """
    Unified cache facade. Prefers Redis (``REDIS_URL``) and degrades to
    :class:`MemoryCache` when Redis is unreachable or not installed.
    """

    def __init__(self, redis_url: str = "", default_ttl: int = 300) -> None:
        self.default_ttl = default_ttl
        self.backend = "memory"
        self._memory = MemoryCache()
        self._redis = None
        url = redis_url or os.getenv("REDIS_URL", "")
        if url:
            try:
                import redis  # type: ignore

                client = redis.Redis.from_url(url, socket_connect_timeout=2)
                client.ping()
                self._redis = client
                self.backend = "redis"
                logger.info(f"Cache backend: redis ({url.split('@')[-1]})")
            except Exception as exc:  # pragma: no cover - environment dependent
                logger.warning(f"Redis unavailable ({exc}); using in-memory cache")
        else:
            logger.info("Cache backend: memory (set REDIS_URL for shared cache)")

    # ── sync core ─────────────────────────────────────────────────────────
    def get(self, key: str) -> Any | None:
        if self._redis is not None:
            try:
                raw = self._redis.get(key)
                return json.loads(raw) if raw is not None else None
            except Exception:
                pass
        return self._memory.get(key)

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        ttl = self.default_ttl if ttl is None else ttl
        if self._redis is not None:
            try:
                self._redis.setex(key, max(ttl, 1), json.dumps(value, default=str))
                return
            except Exception:
                pass
        self._memory.set(key, value, ttl)

    def delete(self, key: str) -> None:
        if self._redis is not None:
            try:
                self._redis.delete(key)
            except Exception:
                pass
        self._memory.delete(key)

    def invalidate_prefix(self, prefix: str) -> int:
        """Delete all keys starting with prefix. Returns count removed (memory backend)."""
        count = 0
        if self._redis is not None:
            try:
                for key in self._redis.scan_iter(f"{prefix}*"):
                    self._redis.delete(key)
                    count += 1
            except Exception:
                pass
        with self._memory._lock:
            doomed = [k for k in self._memory._store if k.startswith(prefix)]
            for k in doomed:
                self._memory._store.pop(k, None)
                count += 1
        return count

    # ── async wrappers ────────────────────────────────────────────────────
    async def aget(self, key: str) -> Any | None:
        return self.get(key)

    async def aset(self, key: str, value: Any, ttl: int | None = None) -> None:
        self.set(key, value, ttl)

    async def adelete(self, key: str) -> None:
        self.delete(key)


_cache: Cache | None = None


def get_cache() -> Cache:
    global _cache
    if _cache is None:
        _cache = Cache()
    return _cache
