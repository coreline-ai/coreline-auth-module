"""Optional Redis-backed rate limiter adapter."""

from __future__ import annotations

from typing import Any

from .rate_limit import RateLimitDecision
from .security import hash_secret


class RedisFixedWindowRateLimiter:
    """Distributed fixed-window limiter using Redis atomic Lua evaluation.

    The adapter intentionally depends on a duck-typed Redis client instead of a
    hard dependency. Pass a client that exposes `eval(script, numkeys, *args)`,
    such as `redis.Redis` or a compatible wrapper.
    """

    scope = "distributed"

    _LUA = """
local current = redis.call('get', KEYS[1])
if current and tonumber(current) >= tonumber(ARGV[1]) then
  local ttl = redis.call('ttl', KEYS[1])
  return {0, ttl}
end
local count = redis.call('incr', KEYS[1])
if count == 1 then
  redis.call('expire', KEYS[1], ARGV[2])
end
local ttl = redis.call('ttl', KEYS[1])
return {1, ttl}
"""

    def __init__(self, redis_client: Any, *, key_prefix: str = "coreline-auth:rate-limit:") -> None:
        self.redis = redis_client
        self.key_prefix = key_prefix

    def check(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
        redis_key = self.key_prefix + hash_secret(key)
        raw = self.redis.eval(self._LUA, 1, redis_key, int(limit), int(window_seconds))
        allowed = bool(_as_int(raw[0]))
        ttl = _as_int(raw[1]) if len(raw) > 1 else int(window_seconds)
        if allowed:
            return RateLimitDecision(True)
        return RateLimitDecision(False, max(1, ttl))


def _as_int(value: Any) -> int:
    if isinstance(value, bytes):
        return int(value.decode("ascii"))
    return int(value)
