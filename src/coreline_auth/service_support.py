"""Small helper object for `CorelineAuthService` cross-cutting concerns."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from .email import EmailSender
from .errors import AuthenticationFailed, AuthorizationDenied
from .models import AuditEvent, AuthUser, AuthProfile, UserStatus, now_utc
from .observability import MetricSink
from .rate_limit import RateLimiter
from .security import normalize_email_address
from .storage.audit import redact_audit_metadata
from .storage.base import AuthStorage

AuditSink = Callable[[AuditEvent], None]
logger = logging.getLogger("coreline_auth")


@dataclass(slots=True)
class AuthServiceSupport:
    """Cross-cutting service helpers kept outside the public service facade."""

    storage: AuthStorage
    config: Any
    rate_limiter: RateLimiter
    audit_sink: AuditSink | None = None
    metric_sink: MetricSink | None = None

    def check_rate_limit(self, key: str, *, limit: int) -> None:
        decision = self.rate_limiter.check(key, limit=limit, window_seconds=60)
        if not decision.allowed:
            self.metric("auth.rate_limited", {"retry_after_seconds": decision.retry_after_seconds or 0})
            logger.info("coreline_auth.rate_limited", extra={"retry_after_seconds": decision.retry_after_seconds})
            raise AuthenticationFailed("rate limited")

    def record_login(self, user: AuthUser) -> None:
        self.storage.update_user(replace(user, last_login_at=now_utc(), updated_at=now_utc()))

    def require_user(self, user_id: str) -> AuthUser:
        user = self.storage.get_user(user_id)
        if user is None:
            raise AuthenticationFailed("user not found")
        return user

    def enforce_profile_login(self, user: AuthUser) -> None:
        if self.config.profile == AuthProfile.SINGLE_OWNER:
            self.assert_owner_email(user.primary_email)
        if self.config.require_email_verified and not user.primary_email_verified:
            raise AuthenticationFailed("email is not verified")

    def assert_owner_email(self, email: str) -> None:
        if self.config.owner_email is None or email.lower() != self.config.owner_email.lower():
            raise AuthorizationDenied("single_owner profile only allows the configured owner")

    def normalize_email(self, email: str) -> str:
        return normalize_email_address(email)

    def send_email_best_effort(self, kind: str, send: Callable[[], object]) -> None:
        try:
            send()
        except Exception as exc:  # pragma: no cover - specific sender failures are adapter-defined
            self.metric("auth.email_send_failed", {"kind": kind})
            logger.warning("coreline_auth.email_send_failed", extra={"kind": kind, "error_type": type(exc).__name__})

    def metric(self, name: str, values: dict[str, object] | None = None) -> None:
        if self.metric_sink is None:
            return
        try:
            self.metric_sink(name, dict(values or {}))
        except Exception as exc:  # pragma: no cover - host sinks must never break auth flows
            logger.warning("coreline_auth.metric_sink_failed", extra={"metric": name, "error_type": type(exc).__name__})

    def audit(self, action: str, *, actor_user_id: str | None = None, target_user_id: str | None = None, metadata: dict[str, object] | None = None) -> None:
        event = AuditEvent(action=action, actor_user_id=actor_user_id, target_user_id=target_user_id, metadata=redact_audit_metadata(dict(metadata or {})))
        try:
            self.storage.record_audit_event(event)
        except Exception as exc:
            logger.warning("coreline_auth.audit_write_failed", extra={"action": action, "error_type": type(exc).__name__})
        if self.audit_sink is not None:
            try:
                self.audit_sink(event)
            except Exception as exc:
                logger.warning("coreline_auth.audit_sink_failed", extra={"action": action, "error_type": type(exc).__name__})
