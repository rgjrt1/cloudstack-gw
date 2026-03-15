"""
Cache backends for provisioning results.

Supported backends:
  - MemoryCache: process-local dict with TTL, suitable for single instances.
  - RedisCache: Redis-backed cache using JSON serialisation, suitable for
    multi-replica deployments.

Both backends share the same interface defined by :class:`BaseCache`.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Optional

from .models import AppConfig, CacheEntry

logger = logging.getLogger(__name__)


class BaseCache(ABC):
    """Abstract cache interface."""

    @abstractmethod
    async def get(self, key: str) -> Optional[CacheEntry]:
        """Return the cached entry or ``None`` if missing/expired."""

    @abstractmethod
    async def set(self, key: str, entry: CacheEntry) -> None:
        """Store an entry in the cache."""

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Remove an entry from the cache."""

    @abstractmethod
    async def clear(self) -> None:
        """Remove all entries from the cache."""

    @abstractmethod
    async def close(self) -> None:
        """Release any held resources."""


# ---------------------------------------------------------------------------
# Memory cache
# ---------------------------------------------------------------------------

class MemoryCache(BaseCache):
    """Simple in-process dict-based cache with per-entry TTL."""

    def __init__(self, ttl: int = 300) -> None:
        self._ttl = ttl
        # key → (expiry_timestamp, CacheEntry)
        self._store: dict[str, tuple[float, CacheEntry]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[CacheEntry]:
        async with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            expiry, entry = item
            if time.monotonic() > expiry:
                del self._store[key]
                return None
            return entry

    async def set(self, key: str, entry: CacheEntry) -> None:
        async with self._lock:
            self._store[key] = (time.monotonic() + self._ttl, entry)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    async def close(self) -> None:
        pass  # nothing to release

    def __len__(self) -> int:
        return len(self._store)


# ---------------------------------------------------------------------------
# Redis cache
# ---------------------------------------------------------------------------

class RedisCache(BaseCache):
    """Redis-backed cache using JSON serialisation.

    Requires the ``redis`` package (``pip install redis``).
    The TTL is set natively in Redis using SETEX.
    """

    def __init__(self, redis_url: str, ttl: int = 300) -> None:
        self._redis_url = redis_url
        self._ttl = ttl
        self._client: "redis.asyncio.Redis | None" = None  # type: ignore[name-defined]

    async def _ensure_client(self) -> "redis.asyncio.Redis":  # type: ignore[name-defined]
        if self._client is None:
            try:
                import redis.asyncio as aioredis  # type: ignore[import]
            except ImportError as exc:
                raise ImportError(
                    "redis package is required for RedisCache. "
                    "Install it with: pip install redis"
                ) from exc
            self._client = aioredis.from_url(
                self._redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
        return self._client

    async def get(self, key: str) -> Optional[CacheEntry]:
        client = await self._ensure_client()
        raw = await client.get(key)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            return CacheEntry.model_validate(data)
        except Exception:
            logger.warning("Failed to deserialise cache entry for key %s", key)
            return None

    async def set(self, key: str, entry: CacheEntry) -> None:
        client = await self._ensure_client()
        raw = entry.model_dump_json()
        await client.setex(key, self._ttl, raw)

    async def delete(self, key: str) -> None:
        client = await self._ensure_client()
        await client.delete(key)

    async def clear(self) -> None:
        client = await self._ensure_client()
        await client.flushdb(asynchronous=True)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_cache(config: AppConfig) -> BaseCache:
    """Instantiate the configured cache backend."""
    cfg = config.cache
    if cfg.type == "redis":
        logger.info("Using Redis cache backend at %s", cfg.redis_url)
        return RedisCache(redis_url=cfg.redis_url, ttl=cfg.ttl)
    logger.info("Using in-memory cache backend (ttl=%ds)", cfg.ttl)
    return MemoryCache(ttl=cfg.ttl)
