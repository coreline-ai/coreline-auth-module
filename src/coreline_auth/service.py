"""Coreline Auth service layer."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Callable
from uuid import uuid4

from .email import EmailSender
from .errors import AuthConfigurationError, AuthenticationFailed, AuthorizationDenied, AuthValidationError
from .mfa import InMemoryMfaSecretVault, MfaSecretVault, generate_recovery_code, generate_totp_secret, totp_counter_for_code
from .models import (
    AuditEvent,
    AuthAssuranceLevel,
    AuthCredential,
    AuthIdentity,
    AuthMfaFactor,
    AuthProfile,
    AuthRecoveryCode,
    AuthSession,
    AuthUser,
    CredentialType,
    FlowType,
    IssuedSession,
    LoginFlow,
    MagicLinkChallenge,
    MfaFactorType,
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
from .social import SocialProfile
from .storage.base import AuthStorage
from .service_support import AuditSink, AuthServiceSupport


@dataclass(frozen=True, slots=True)
class CorelineAuthConfig:
    issuer: str = "coreline-auth"
    profile: AuthProfile = AuthProfile.SINGLE_OWNER
    owner_email: str | None = None
    require_email_verified: bool = True
    session_ttl_seconds: int = 60 * 60 * 24 * 7
    session_idle_ttl_seconds: int | None = 60 * 60 * 12
    session_touch_interval_seconds: int = 60
    login_flow_ttl_seconds: int = 60 * 10
    login_limit_per_minute: int = 10
    magic_link_limit_per_minute: int = 5
    social_email_linking_requires_verified: bool = True
    revoke_sessions_on_password_change: bool = True

    def validate(self) -> None:
        if self.profile == AuthProfile.SINGLE_OWNER and not self.owner_email:
            raise AuthConfigurationError("single_owner profile requires owner_email")
        if self.session_ttl_seconds <= 0:
            raise AuthConfigurationError("session_ttl_seconds must be positive")
        if self.session_touch_interval_seconds < 0:
            raise AuthConfigurationError("session_touch_interval_seconds must be non-negative")
        if self.login_flow_ttl_seconds <= 0:
            raise AuthConfigurationError("login_flow_ttl_seconds must be positive")


class CorelineAuthService:
    def __init__(
        self,
        *,
        storage: AuthStorage,
        config: CorelineAuthConfig,
        audit_sink: AuditSink | None = None,
        metric_sink: MetricSink | None = None,
        email_sender: EmailSender | None = None,
        rate_limiter: RateLimiter | None = None,
        mfa_secret_vault: MfaSecretVault | None = None,
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
        self.mfa_secret_vault = mfa_secret_vault or InMemoryMfaSecretVault()
        self.support = AuthServiceSupport(storage=storage, config=config, rate_limiter=self.rate_limiter, audit_sink=audit_sink, metric_sink=metric_sink)

    def bootstrap_owner(self, *, email: str, password: str | None = None, display_name: str | None = None) -> AuthUser:
        self._assert_owner_email(self._normalize_email(email))
        existing = self.storage.get_user_by_email(email)
        if existing is not None:
            if password:
                self.set_password(existing.id, password)
            return existing
        user = self.create_user(email=email, role=Role.OWNER, password=password, email_verified=True, display_name=display_name)
        self._audit("auth.owner.bootstrap", target_user_id=user.id)
        return user

    def create_user(self, *, email: str, role: Role = Role.USER, password: str | None = None, email_verified: bool = False, display_name: str | None = None) -> AuthUser:
        normalized_email = self._normalize_email(email)
        if self.config.profile == AuthProfile.SINGLE_OWNER:
            self._assert_owner_email(normalized_email)
            role = Role.OWNER
            email_verified = True
        user = AuthUser(id=f"usr_{uuid4().hex}", primary_email=normalized_email, primary_email_verified=email_verified, role=role, display_name=display_name)
        created = self.storage.create_user(user)
        self.storage.upsert_identity(AuthIdentity(id=f"idn_{uuid4().hex}", user_id=created.id, provider="email", provider_subject=normalized_email, email=normalized_email, email_verified=email_verified))
        if password:
            self.set_password(created.id, password)
        self._audit("auth.user.create", target_user_id=created.id, metadata={"role": role.value})
        return created

    def set_password(self, user_id: str, password: str) -> AuthCredential:
        user = self._require_user(user_id)
        existing = self.storage.get_password_credential(user.id)
        credential = replace(existing, password_hash=hash_password(password), updated_at=now_utc(), revoked_at=None) if existing else AuthCredential(id=f"cred_{uuid4().hex}", user_id=user.id, credential_type=CredentialType.PASSWORD, password_hash=hash_password(password))
        saved = self.storage.upsert_credential(credential)
        self._audit("auth.password.set", target_user_id=user.id)
        return saved

    def login_password(self, *, email: str, password: str, context: RequestContext | None = None) -> IssuedSession:
        normalized_email = self._normalize_email(email)
        self._check_rate_limit(f"login:{hash_secret(normalized_email)}", limit=self.config.login_limit_per_minute)
        user = self.storage.get_user_by_email(normalized_email)
        if user is None or user.status != UserStatus.ACTIVE:
            verify_dummy_password(password)
            self._audit("auth.login.failed", metadata={"reason": "user_not_found_or_inactive"})
            raise AuthenticationFailed("invalid email or password")
        self._enforce_profile_login(user)
        credential = self.storage.get_password_credential(user.id)
        if credential is None or not credential.password_hash:
            verify_dummy_password(password)
            self._audit("auth.login.failed", target_user_id=user.id, metadata={"reason": "missing_password_credential"})
            raise AuthenticationFailed("invalid email or password")
        if not verify_password(credential.password_hash, password):
            self._audit("auth.login.failed", target_user_id=user.id, metadata={"reason": "bad_password"})
            raise AuthenticationFailed("invalid email or password")
        issued = self.issue_session(user, provider="email", context=context)
        self._record_login(user)
        self._audit("auth.login.password", target_user_id=user.id)
        return issued

    def request_magic_link(self, *, email: str, return_to: str = "/") -> MagicLinkChallenge:
        normalized_email = self._normalize_email(email)
        return_to = self.return_to_policy.validate(return_to)
        if self.config.profile == AuthProfile.SINGLE_OWNER:
            self._assert_owner_email(normalized_email)
        self._check_rate_limit(f"magic:{hash_secret(normalized_email)}", limit=self.config.magic_link_limit_per_minute)
        token = generate_token()
        now = now_utc()
        flow = LoginFlow(id=f"flow_{uuid4().hex}", flow_type=FlowType.MAGIC_LINK, provider="email", state_hash=hash_secret(token), email=normalized_email, return_to=return_to, created_at=now, expires_at=now + timedelta(seconds=self.config.login_flow_ttl_seconds))
        saved = self.storage.create_login_flow(flow)
        if self.email_sender is not None:
            self._send_email_best_effort("magic_link", lambda: self.email_sender.send_magic_link(email=normalized_email, token=token, return_to=return_to))
        self._audit("auth.magic_link.request", metadata={"email_hash": hash_secret(normalized_email)})
        return MagicLinkChallenge(token=token, flow=saved)

    def consume_magic_link(self, *, token: str, context: RequestContext | None = None) -> IssuedSession:
        now = now_utc()
        flow = self.storage.consume_login_flow_by_state_hash(hash_secret(token), flow_type=FlowType.MAGIC_LINK, provider="email", now=now)
        if flow is None:
            self._metric("auth.magic_link.consume_failed", {"reason": "invalid_expired_or_consumed"})
            raise AuthenticationFailed("invalid or expired magic link")
        if not flow.email:
            raise AuthenticationFailed("invalid magic link")
        user = self.storage.get_user_by_email(flow.email)
        if user is None:
            user = self.create_user(email=flow.email, email_verified=True, role=Role.OWNER if self.config.profile == AuthProfile.SINGLE_OWNER else Role.USER)
        self._enforce_profile_login(user)
        issued = self.issue_session(user, provider="email", context=context)
        self._record_login(user)
        self._audit("auth.magic_link.consume", target_user_id=user.id)
        return issued

    def request_email_verification(self, user_id: str | None = None, email: str | None = None) -> MagicLinkChallenge:
        if (user_id is None) == (email is None):
            raise AuthValidationError("provide exactly one of user_id or email")
        user = self._require_user(user_id) if user_id is not None else self.storage.get_user_by_email(self._normalize_email(email or ""))
        if user is None:
            raise AuthenticationFailed("user not found")
        if user.status != UserStatus.ACTIVE:
            raise AuthenticationFailed("user inactive")
        if self.config.profile == AuthProfile.SINGLE_OWNER:
            self._assert_owner_email(user.primary_email)
        self._check_rate_limit(f"email_verify:{hash_secret(user.primary_email)}", limit=self.config.magic_link_limit_per_minute)
        token = generate_token()
        now = now_utc()
        flow = LoginFlow(id=f"flow_{uuid4().hex}", flow_type=FlowType.EMAIL_VERIFICATION, provider="email", state_hash=hash_secret(token), email=user.primary_email, return_to="/", created_at=now, expires_at=now + timedelta(seconds=self.config.login_flow_ttl_seconds), metadata={"user_id": user.id})
        saved = self.storage.create_login_flow(flow)
        if self.email_sender is not None:
            self._send_email_best_effort("email_verification", lambda: self.email_sender.send_email_verification(email=user.primary_email, token=token))
        self._audit("auth.email_verification.request", target_user_id=user.id, metadata={"email_hash": hash_secret(user.primary_email)})
        return MagicLinkChallenge(token=token, flow=saved)

    def consume_email_verification(self, token: str) -> AuthUser:
        now = now_utc()
        flow = self.storage.consume_login_flow_by_state_hash(hash_secret(token), flow_type=FlowType.EMAIL_VERIFICATION, provider="email", now=now)
        if flow is None:
            raise AuthenticationFailed("invalid or expired email verification token")
        user_id = flow.metadata.get("user_id")
        user = self.storage.get_user(user_id) if isinstance(user_id, str) else None
        if user is None and flow.email:
            user = self.storage.get_user_by_email(flow.email)
        if user is None or user.status != UserStatus.ACTIVE:
            raise AuthenticationFailed("invalid email verification token")
        if flow.email and self._normalize_email(user.primary_email) != self._normalize_email(flow.email):
            raise AuthenticationFailed("invalid email verification token")
        updated = replace(user, primary_email_verified=True, updated_at=now)
        self.storage.update_user(updated)
        identity = self.storage.get_identity("email", updated.primary_email)
        if identity is not None:
            self.storage.upsert_identity(replace(identity, email_verified=True, last_seen_at=now))
        self._audit("auth.email_verification.consume", target_user_id=updated.id)
        return updated

    def request_password_reset(self, email: str) -> MagicLinkChallenge:
        normalized_email = self._normalize_email(email)
        self._check_rate_limit(f"password_reset:{hash_secret(normalized_email)}", limit=self.config.magic_link_limit_per_minute)
        token = generate_token()
        now = now_utc()
        user = self.storage.get_user_by_email(normalized_email)
        allowed_by_profile = self.config.profile != AuthProfile.SINGLE_OWNER or normalized_email == (self.config.owner_email or "").lower()
        should_send = user is not None and user.status == UserStatus.ACTIVE and allowed_by_profile
        flow = LoginFlow(id=f"flow_{uuid4().hex}", flow_type=FlowType.PASSWORD_RESET, provider="email", state_hash=hash_secret(token), email=normalized_email, return_to="/", created_at=now, expires_at=now + timedelta(seconds=self.config.login_flow_ttl_seconds), metadata={"user_id": user.id} if should_send else {})
        saved = self.storage.create_login_flow(flow) if should_send else flow
        if should_send and self.email_sender is not None:
            self._send_email_best_effort("password_reset", lambda: self.email_sender.send_password_reset(email=normalized_email, token=token))
        if not should_send:
            # Keep the negative path expensive enough to reduce password-reset
            # email enumeration through timing side channels.
            verify_dummy_password(token)
        self._audit("auth.password_reset.request", metadata={"email_hash": hash_secret(normalized_email), "sent": should_send})
        return MagicLinkChallenge(token=token, flow=saved)

    def consume_password_reset(self, token: str, new_password: str) -> AuthUser:
        now = now_utc()
        flow = self.storage.consume_login_flow_by_state_hash(hash_secret(token), flow_type=FlowType.PASSWORD_RESET, provider="email", now=now)
        if flow is None:
            raise AuthenticationFailed("invalid or expired password reset token")
        user_id = flow.metadata.get("user_id")
        user = self.storage.get_user(user_id) if isinstance(user_id, str) else None
        if user is None and flow.email:
            user = self.storage.get_user_by_email(flow.email)
        if user is None or user.status != UserStatus.ACTIVE:
            raise AuthenticationFailed("invalid password reset token")
        if self.config.profile == AuthProfile.SINGLE_OWNER:
            self._assert_owner_email(user.primary_email)
        self.set_password(user.id, new_password)
        if self.config.revoke_sessions_on_password_change:
            revoked = self.storage.revoke_sessions_for_user(user.id)
            self._audit("auth.password_reset.sessions_revoked", target_user_id=user.id, metadata={"revoked_count": revoked})
        self._audit("auth.password_reset.consume", target_user_id=user.id)
        return user

    def begin_social_login(self, *, provider: str, return_to: str = "/") -> str:
        return_to = self.return_to_policy.validate(return_to)
        state = generate_token()
        now = now_utc()
        self.storage.create_login_flow(
            LoginFlow(
                id=f"flow_{uuid4().hex}",
                flow_type=FlowType.OAUTH,
                provider=provider,
                state_hash=hash_secret(state),
                return_to=return_to,
                created_at=now,
                expires_at=now + timedelta(seconds=self.config.login_flow_ttl_seconds),
            )
        )
        return state

    def login_social(self, *, profile: SocialProfile, state: str | None = None, context: RequestContext | None = None) -> IssuedSession:
        if state is not None:
            flow = self.storage.consume_login_flow_by_state_hash(hash_secret(state), flow_type=FlowType.OAUTH, provider=profile.provider, now=now_utc())
            if flow is None:
                raise AuthenticationFailed("invalid or expired social login state")
        identity = self.storage.get_identity(profile.provider, profile.provider_subject)
        if identity is not None:
            user = self._require_user(identity.user_id)
        else:
            if not profile.email:
                raise AuthenticationFailed("provider did not return an email")
            existing = self.storage.get_user_by_email(profile.email)
            if existing is not None and self.config.social_email_linking_requires_verified and not profile.email_verified:
                self._audit("auth.social.link_rejected", target_user_id=existing.id, metadata={"provider": profile.provider, "reason": "unverified_email"})
                raise AuthenticationFailed("provider email is not verified")
            if existing is None:
                role = Role.OWNER if self.config.profile == AuthProfile.SINGLE_OWNER else Role.USER
                existing = self.create_user(email=profile.email, role=role, email_verified=profile.email_verified, display_name=profile.display_name)
            self.storage.upsert_identity(
                AuthIdentity(
                    id=f"idn_{uuid4().hex}",
                    user_id=existing.id,
                    provider=profile.provider,
                    provider_subject=profile.provider_subject,
                    email=profile.email,
                    email_verified=profile.email_verified,
                )
            )
            user = existing
        self._enforce_profile_login(user)
        issued = self.issue_session(user, provider=profile.provider, context=context)
        self._record_login(user)
        self._audit("auth.login.social", target_user_id=user.id, metadata={"provider": profile.provider})
        return issued

    def issue_session(self, user: AuthUser, *, provider: str | None, context: RequestContext | None = None) -> IssuedSession:
        now = now_utc()
        role = Role.OWNER if self.config.profile == AuthProfile.SINGLE_OWNER else user.role
        permissions = self.policy.permissions_for(role=role, email=user.primary_email)
        token = generate_token()
        session = AuthSession(id=f"sess_{uuid4().hex}", session_token_hash=hash_secret(token), user_id=user.id, subject=user.id, email=user.primary_email, provider=provider, role=role, permissions=tuple(permissions), assurance_level=AuthAssuranceLevel.AAL1, created_at=now, expires_at=now + timedelta(seconds=self.config.session_ttl_seconds), idle_expires_at=now + timedelta(seconds=self.config.session_idle_ttl_seconds) if self.config.session_idle_ttl_seconds else None, last_seen_at=now, user_agent_hash=hash_optional_context(context.user_agent if context else None), ip_hash=hash_optional_context(context.ip if context else None))
        self.storage.create_session(session)
        return IssuedSession(token=token, session=session)

    def verify_session(self, token: str, *, required_permission: str | None = None) -> Principal:
        session = self.storage.get_session_by_token_hash(hash_secret(token))
        now = now_utc()
        if session is None or session.revoked_at is not None:
            raise AuthenticationFailed("invalid session")
        if session.expires_at <= now or (session.idle_expires_at is not None and session.idle_expires_at <= now):
            raise AuthenticationFailed("session expired")
        user = self._require_user(session.user_id)
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
            self.storage.update_session(refreshed)
        return Principal(user=user, session=refreshed)

    def logout(self, token: str) -> None:
        session = self.storage.get_session_by_token_hash(hash_secret(token))
        if session is not None:
            self.storage.revoke_session(session.id)
            self._audit("auth.logout", actor_user_id=session.user_id)

    def revoke_session(self, session_id: str, *, actor_user_id: str | None = None) -> None:
        self.storage.revoke_session(session_id)
        self._audit("auth.session.revoke", actor_user_id=actor_user_id, metadata={"session_id": session_id})

    def cleanup_expired(self) -> dict[str, int]:
        return self.storage.cleanup_expired(now=now_utc())

    def list_audit_events(
        self,
        *,
        action: str | None = None,
        actor_user_id: str | None = None,
        target_user_id: str | None = None,
        since=None,
        until=None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        return self.storage.list_audit_events(action=action, actor_user_id=actor_user_id, target_user_id=target_user_id, since=since, until=until, limit=limit, offset=offset)

    def begin_totp_enrollment(self, user_id: str, *, name: str = "Authenticator") -> tuple[AuthMfaFactor, str]:
        user = self._require_user(user_id)
        secret = generate_totp_secret()
        factor = AuthMfaFactor(
            id=f"mfa_{uuid4().hex}",
            user_id=user.id,
            factor_type=MfaFactorType.TOTP,
            name=name,
            secret_hash=hash_secret(secret),
            enabled=False,
        )
        self.storage.create_mfa_factor(factor)
        self.mfa_secret_vault.store_totp_secret(factor_id=factor.id, secret=secret)
        self._audit("auth.mfa.totp_enroll_begin", target_user_id=user.id, metadata={"factor_id": factor.id})
        return factor, secret

    def verify_totp_enrollment(self, *, user_id: str, factor_id: str, code: str) -> AuthMfaFactor:
        factor = self._require_totp_factor(user_id=user_id, factor_id=factor_id)
        if factor.enabled:
            return factor
        self._verify_factor_code(factor, code)
        updated = replace(factor, enabled=True, last_used_at=now_utc())
        self.storage.update_mfa_factor(updated)
        self._audit("auth.mfa.totp_enroll_verify", target_user_id=user_id, metadata={"factor_id": factor.id})
        return updated

    def verify_totp(self, *, user_id: str, code: str) -> AuthMfaFactor:
        for factor in self.storage.list_mfa_factors(user_id):
            if factor.factor_type != MfaFactorType.TOTP or not factor.enabled:
                continue
            counter = self._factor_code_counter(factor, code)
            if counter is None:
                continue
            if factor.last_used_counter is not None and counter <= factor.last_used_counter:
                self._metric("auth.mfa.totp_replay_blocked", {"factor_id": factor.id})
                continue
            updated = replace(factor, last_used_at=now_utc(), last_used_counter=counter)
            self.storage.update_mfa_factor(updated)
            return updated
        raise AuthenticationFailed("invalid mfa code")

    def step_up_totp(self, session_token: str, *, code: str) -> Principal:
        principal = self.verify_session(session_token)
        factor = self.verify_totp(user_id=principal.user_id, code=code)
        updated_session = replace(principal.session, assurance_level=AuthAssuranceLevel.AAL2, last_seen_at=now_utc())
        self.storage.update_session(updated_session)
        self._audit("auth.mfa.step_up", actor_user_id=principal.user_id, metadata={"factor_id": factor.id, "method": "totp"})
        return Principal(user=principal.user, session=updated_session)

    def generate_recovery_codes(self, user_id: str, *, count: int = 10) -> list[str]:
        user = self._require_user(user_id)
        raw_codes: list[str] = []
        for _ in range(count):
            raw = generate_recovery_code()
            raw_codes.append(raw)
            self.storage.create_recovery_code(AuthRecoveryCode(id=f"rc_{uuid4().hex}", user_id=user.id, code_hash=hash_secret(raw)))
        self._audit("auth.mfa.recovery_codes_create", target_user_id=user.id, metadata={"count": count})
        return raw_codes

    def step_up_recovery_code(self, session_token: str, *, code: str) -> Principal:
        principal = self.verify_session(session_token)
        code_hash = hash_secret(code)
        for saved in self.storage.list_recovery_codes(principal.user_id):
            if saved.used_at is None and saved.code_hash == code_hash:
                try:
                    self.storage.mark_recovery_code_used(saved.id, used_at=now_utc())
                except AuthValidationError as exc:
                    raise AuthenticationFailed("invalid recovery code") from exc
                updated_session = replace(principal.session, assurance_level=AuthAssuranceLevel.AAL2, last_seen_at=now_utc())
                self.storage.update_session(updated_session)
                self._audit("auth.mfa.step_up", actor_user_id=principal.user_id, metadata={"method": "recovery_code"})
                return Principal(user=principal.user, session=updated_session)
        raise AuthenticationFailed("invalid recovery code")

    def require_aal2(self, session_token: str) -> Principal:
        principal = self.verify_session(session_token)
        if principal.session.assurance_level != AuthAssuranceLevel.AAL2:
            raise AuthorizationDenied("aal2 required")
        return principal

    def _require_totp_factor(self, *, user_id: str, factor_id: str) -> AuthMfaFactor:
        factor = self.storage.get_mfa_factor(factor_id)
        if factor is None or factor.user_id != user_id or factor.factor_type != MfaFactorType.TOTP:
            raise AuthenticationFailed("mfa factor not found")
        return factor

    def _verify_factor_code(self, factor: AuthMfaFactor, code: str) -> None:
        if self._factor_code_counter(factor, code) is None:
            raise AuthenticationFailed("invalid mfa code")

    def _factor_code_counter(self, factor: AuthMfaFactor, code: str) -> int | None:
        secret = self.mfa_secret_vault.load_totp_secret(factor_id=factor.id)
        if secret is None or factor.secret_hash != hash_secret(secret):
            return None
        return totp_counter_for_code(secret, code)

    def _check_rate_limit(self, key: str, *, limit: int) -> None:
        self.support.check_rate_limit(key, limit=limit)

    def _record_login(self, user: AuthUser) -> None:
        self.support.record_login(user)

    def _require_user(self, user_id: str) -> AuthUser:
        return self.support.require_user(user_id)

    def _enforce_profile_login(self, user: AuthUser) -> None:
        self.support.enforce_profile_login(user)

    def _assert_owner_email(self, email: str) -> None:
        self.support.assert_owner_email(email)

    def _normalize_email(self, email: str) -> str:
        return self.support.normalize_email(email)

    def health_check(self) -> None:
        self.storage.health_check()

    def _send_email_best_effort(self, kind: str, send: Callable[[], object]) -> None:
        self.support.send_email_best_effort(kind, send)

    def _metric(self, name: str, values: dict[str, object] | None = None) -> None:
        self.support.metric(name, values)

    def _audit(self, action: str, *, actor_user_id: str | None = None, target_user_id: str | None = None, metadata: dict[str, object] | None = None) -> None:
        self.support.audit(action, actor_user_id=actor_user_id, target_user_id=target_user_id, metadata=metadata)
