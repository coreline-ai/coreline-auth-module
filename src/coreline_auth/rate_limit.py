"""Small in-process fixed-window rate limiter for v0.1."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from time import monotonic


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int | None = None


class RateLimiter(Protocol):
    """Pluggable rate limiter contract.

    The built-in implementation is process-local. Production multi-worker hosts
    can inject a shared implementation with the same ``check`` method.
    """

    def check(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision: ...


class FixedWindowRateLimiter:
    """In-process fixed-window limiter.

    This is safe for single-process demos and apps. It is intentionally explicit
    about process-local scope so callers do not mistake it for a distributed
    brute-force control in multi-worker deployments.
    """

    scope = "process"

    def __init__(self, *, max_buckets: int = 10_000) -> None:
        self._buckets: dict[str, tuple[int, float]] = {}
        self.max_buckets = max_buckets

    def check(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
        now = monotonic()
        self.cleanup_expired(now=now)
        if key not in self._buckets and len(self._buckets) >= self.max_buckets:
            oldest_key = min(self._buckets, key=lambda bucket_key: self._buckets[bucket_key][1])
            self._buckets.pop(oldest_key, None)
        count, reset_at = self._buckets.get(key, (0, now + window_seconds))
        if now >= reset_at:
            count, reset_at = 0, now + window_seconds
        if count >= limit:
            return RateLimitDecision(False, max(1, int(reset_at - now)))
        self._buckets[key] = (count + 1, reset_at)
        return RateLimitDecision(True)

    def cleanup_expired(self, *, now: float | None = None) -> int:
        current = monotonic() if now is None else now
        expired = [key for key, (_, reset_at) in self._buckets.items() if current >= reset_at]
        for key in expired:
            self._buckets.pop(key, None)
        return len(expired)

    @property
    def bucket_count(self) -> int:
        return len(self._buckets)
