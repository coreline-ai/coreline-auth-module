"""Async Coreline Auth service scaffold for pooled production storage."""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import timedelta
from typing import Callable
from uuid import uuid4

from .email import EmailSender
from .errors import AuthConfigurationError, AuthenticationFailed, AuthorizationDenied, AuthValidationError
from .models import (
    AuditEvent,
    AuthCredential,
    AuthIdentity,
    AuthProfile,
    AuthSession,
    AuthUser,
    CredentialType,
    FlowType,
    IssuedSession,
    LoginFlow,
    MagicLinkChallenge,
    Principal,
    RequestContext,
    Role,
    UserStatus,
    now_utc,
)
from .observability import MetricSink
from .permissions import PolicyEngine
from .rate_limit import FixedWindowRateLimiter, RateLimiter
from .security import SafeReturnToPolicy, generate_token, hash_optional_context, hash_password, hash_secret, verify_dummy_password, verify_password
from .service import CorelineAuthConfig
from .storage.async_base import AsyncAuthStorage
from .storage.audit import redact_audit_metadata

AuditSink = Callable[[AuditEvent], None]
logger = logging.getLogger("coreline_auth")


class AsyncCorelineAuthService:
    """Async service for production storage adapters.

    This class intentionally starts with core auth/session flows. The sync
    `CorelineAuthService` remains the stable full-featured embedded API while
    v0.6 grows async parity behind this additive class.
    """

    def __init__(
        self,
        *,
        storage: AsyncAuthStorage,
        config: CorelineAuthConfig,
        audit_sink: AuditSink | None = None,
        metric_sink: MetricSink | None = None,
        email_sender: EmailSender | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        config.validate()
        self.storage = storage
        self.config = config
        self.policy = PolicyEngine(profile=config.profile, owner_email=config.owner_email)
        self.return_to_policy = SafeReturnToPolicy()
        self.audit_sink = audit_sink
        self.metric_sink = metric_sink
        self.email_sender = email_sender
        self.rate_limiter = rate_limiter or FixedWindowRateLimiter()

    async def bootstrap_owner(self, *, email: str, password: str | None = None, display_name: str | None = None) -> AuthUser:
        normalized = self._normalize_email(email)
        self._assert_owner_email(normalized)
        existing = await self.storage.get_user_by_email(normalized)
        if existing is not None:
            if password:
                await self.set_password(existing.id, password)
            return existing
        user = await self.create_user(email=normalized, role=Role.OWNER, password=password, email_verified=True, display_name=display_name)
        await self._audit("auth.owner.bootstrap", target_user_id=user.id)
        return user

    async def create_user(self, *, email: str, role: Role = Role.USER, password: str | None = None, email_verified: bool = False, display_name: str | None = None) -> AuthUser:
        normalized_email = self._normalize_email(email)
        if self.config.profile == AuthProfile.SINGLE_OWNER:
            self._assert_owner_email(normalized_email)
            role = Role.OWNER
            email_verified = True
        user = AuthUser(id=f"usr_{uuid4().hex}", primary_email=normalized_email, primary_email_verified=email_verified, role=role, display_name=display_name)
        created = await self.storage.create_user(user)
        await self.storage.upsert_identity(AuthIdentity(id=f"idn_{uuid4().hex}", user_id=created.id, provider="email", provider_subject=normalized_email, email=normalized_email, email_verified=email_verified))
        if password:
            await self.set_password(created.id, password)
        await self._audit("auth.user.create", target_user_id=created.id, metadata={"role": role.value})
        return created

    async def set_password(self, user_id: str, password: str) -> AuthCredential:
        user = await self._require_user(user_id)
        existing = await self.storage.get_password_credential(user.id)
        credential = replace(existing, password_hash=hash_password(password), updated_at=now_utc(), revoked_at=None) if existing else AuthCredential(id=f"cred_{uuid4().hex}", user_id=user.id, credential_type=CredentialType.PASSWORD, password_hash=hash_password(password))
        saved = await self.storage.upsert_credential(credential)
        await self._audit("auth.password.set", target_user_id=user.id)
        return saved

    async def login_password(self, *, email: str, password: str, context: RequestContext | None = None) -> IssuedSession:
        normalized_email = self._normalize_email(email)
        self._check_rate_limit(f"login:{hash_secret(normalized_email)}", limit=self.config.login_limit_per_minute)
        user = await self.storage.get_user_by_email(normalized_email)
        if user is None or user.status != UserStatus.ACTIVE:
            verify_dummy_password(password)
            await self._audit("auth.login.failed", metadata={"reason": "user_not_found_or_inactive"})
            raise AuthenticationFailed("invalid email or password")
        self._enforce_profile_login(user)
        credential = await self.storage.get_password_credential(user.id)
        if credential is None or not credential.password_hash:
            verify_dummy_password(password)
            await self._audit("auth.login.failed", target_user_id=user.id, metadata={"reason": "missing_password_credential"})
            raise AuthenticationFailed("invalid email or password")
        if not verify_password(credential.password_hash, password):
            await self._audit("auth.login.failed", target_user_id=user.id, metadata={"reason": "bad_password"})
            raise AuthenticationFailed("invalid email or password")
        issued = await self.issue_session(user, provider="email", context=context)
        await self._record_login(user)
        await self._audit("auth.login.password", target_user_id=user.id)
        return issued

    async def request_magic_link(self, *, email: str, return_to: str = "/") -> MagicLinkChallenge:
        normalized_email = self._normalize_email(email)
        return_to = self.return_to_policy.validate(return_to)
        if self.config.profile == AuthProfile.SINGLE_OWNER:
            self._assert_owner_email(normalized_email)
        self._check_rate_limit(f"magic:{hash_secret(normalized_email)}", limit=self.config.magic_link_limit_per_minute)
        token = generate_token()
        now = now_utc()
        flow = LoginFlow(id=f"flow_{uuid4().hex}", flow_type=FlowType.MAGIC_LINK, provider="email", state_hash=hash_secret(token), email=normalized_email, return_to=return_to, created_at=now, expires_at=now + timedelta(seconds=self.config.login_flow_ttl_seconds))
        saved = await self.storage.create_login_flow(flow)
        if self.email_sender is not None:
            self._send_email_best_effort("magic_link", lambda: self.email_sender.send_magic_link(email=normalized_email, token=token, return_to=return_to))
        await self._audit("auth.magic_link.request", metadata={"email_hash": hash_secret(normalized_email)})
        return MagicLinkChallenge(token=token, flow=saved)

    async def consume_magic_link(self, *, token: str, context: RequestContext | None = None) -> IssuedSession:
        now = now_utc()
        flow = await self.storage.consume_login_flow_by_state_hash(hash_secret(token), flow_type=FlowType.MAGIC_LINK, provider="email", now=now)
        if flow is None:
            raise AuthenticationFailed("invalid or expired magic link")
        if not flow.email:
            raise AuthenticationFailed("invalid magic link")
        user = await self.storage.get_user_by_email(flow.email)
        if user is None:
            user = await self.create_user(email=flow.email, email_verified=True, role=Role.OWNER if self.config.profile == AuthProfile.SINGLE_OWNER else Role.USER)
        self._enforce_profile_login(user)
        issued = await self.issue_session(user, provider="email", context=context)
        await self._record_login(user)
        await self._audit("auth.magic_link.consume", target_user_id=user.id)
        return issued

    async def issue_session(self, user: AuthUser, *, provider: str | None, context: RequestContext | None = None) -> IssuedSession:
        now = now_utc()
        role = Role.OWNER if self.config.profile == AuthProfile.SINGLE_OWNER else user.role
        permissions = self.policy.permissions_for(role=role, email=user.primary_email)
        token = generate_token()
        session = AuthSession(id=f"sess_{uuid4().hex}", session_token_hash=hash_secret(token), user_id=user.id, subject=user.id, email=user.primary_email, provider=provider, role=role, permissions=tuple(permissions), created_at=now, expires_at=now + timedelta(seconds=self.config.session_ttl_seconds), idle_expires_at=now + timedelta(seconds=self.config.session_idle_ttl_seconds) if self.config.session_idle_ttl_seconds else None, last_seen_at=now, user_agent_hash=hash_optional_context(context.user_agent if context else None), ip_hash=hash_optional_context(context.ip if context else None))
        await self.storage.create_session(session)
        return IssuedSession(token=token, session=session)

    async def verify_session(self, token: str, *, required_permission: str | None = None) -> Principal:
        session = await self.storage.get_session_by_token_hash(hash_secret(token))
        now = now_utc()
        if session is None or session.revoked_at is not None:
            raise AuthenticationFailed("invalid session")
        if session.expires_at <= now or (session.idle_expires_at is not None and session.idle_expires_at <= now):
            raise AuthenticationFailed("session expired")
        user = await self._require_user(session.user_id)
        if user.status != UserStatus.ACTIVE:
            raise AuthenticationFailed("user inactive")
        if required_permission and not self.policy.allows(session.permissions, required_permission):
            raise AuthorizationDenied(f"missing permission: {required_permission}")
        should_touch = (
            self.config.session_touch_interval_seconds == 0
            or session.last_seen_at is None
            or (now - session.last_seen_at).total_seconds() >= self.config.session_touch_interval_seconds
        )
        refreshed = session
        if should_touch:
            refreshed = replace(session, last_seen_at=now, idle_expires_at=now + timedelta(seconds=self.config.session_idle_ttl_seconds) if self.config.session_idle_ttl_seconds else None)
            await self.storage.update_session(refreshed)
        return Principal(user=user, session=refreshed)

    async def logout(self, token: str) -> None:
        session = await self.storage.get_session_by_token_hash(hash_secret(token))
        if session is not None:
            await self.storage.revoke_session(session.id)
            await self._audit("auth.logout", actor_user_id=session.user_id)

    async def cleanup_expired(self) -> dict[str, int]:
        return await self.storage.cleanup_expired(now=now_utc())

    async def list_audit_events(self, *, action: str | None = None, actor_user_id: str | None = None, target_user_id: str | None = None, limit: int = 100, offset: int = 0) -> list[AuditEvent]:
        return await self.storage.list_audit_events(action=action, actor_user_id=actor_user_id, target_user_id=target_user_id, limit=limit, offset=offset)

    async def _record_login(self, user: AuthUser) -> None:
        await self.storage.update_user(replace(user, last_login_at=now_utc(), updated_at=now_utc()))

    async def _require_user(self, user_id: str) -> AuthUser:
        user = await self.storage.get_user(user_id)
        if user is None:
            raise AuthValidationError("user not found")
        return user

    async def _audit(self, action: str, *, actor_user_id: str | None = None, target_user_id: str | None = None, metadata: dict[str, object] | None = None) -> None:
        event = AuditEvent(action=action, actor_user_id=actor_user_id, target_user_id=target_user_id, metadata=redact_audit_metadata(metadata or {}))
        try:
            await self.storage.record_audit_event(event)
        except Exception as exc:
            logger.warning("coreline_auth.audit_write_failed", extra={"action": action, "error_type": type(exc).__name__})
        if self.audit_sink is not None:
            try:
                self.audit_sink(event)
            except Exception as exc:
                logger.warning("coreline_auth.audit_sink_failed", extra={"action": action, "error_type": type(exc).__name__})

    def _send_email_best_effort(self, kind: str, send: Callable[[], object]) -> None:
        try:
            send()
        except Exception as exc:  # pragma: no cover - sender failures are adapter-defined
            self._metric("auth.email_send_failed", {"kind": kind})
            logger.warning("coreline_auth.email_send_failed", extra={"kind": kind, "error_type": type(exc).__name__})

    def _metric(self, name: str, values: dict[str, object] | None = None) -> None:
        if self.metric_sink is None:
            return
        try:
            self.metric_sink(name, dict(values or {}))
        except Exception as exc:  # pragma: no cover - host sinks must never break auth flows
            logger.warning("coreline_auth.metric_sink_failed", extra={"metric": name, "error_type": type(exc).__name__})

    def _check_rate_limit(self, key: str, *, limit: int) -> None:
        decision = self.rate_limiter.check(key, limit=limit, window_seconds=60)
        if not decision.allowed:
            raise AuthenticationFailed("rate limited")

    def _assert_owner_email(self, email: str) -> None:
        if self.config.owner_email and email != self.config.owner_email.lower():
            raise AuthorizationDenied("email is not allowed for single_owner profile")

    def _enforce_profile_login(self, user: AuthUser) -> None:
        if self.config.profile == AuthProfile.SINGLE_OWNER:
            self._assert_owner_email(user.primary_email)
        if self.config.require_email_verified and not user.primary_email_verified:
            raise AuthenticationFailed("email is not verified")

    @staticmethod
    def _normalize_email(email: str) -> str:
        normalized = email.strip().lower()
        if "@" not in normalized:
            raise AuthValidationError("invalid email")
        return normalized
