from __future__ import annotations

import pytest

from coreline_auth import AuthConfigurationError, AuthProfile, AuthenticationFailed, CorelineAdminService, CorelineAuthConfig, CorelineAuthService, CsrfProtector, InMemoryEmailSender, Role
from coreline_auth.rate_limit import FixedWindowRateLimiter
from coreline_auth.storage import MemoryAuthStorage


def test_csrf_token_round_trip() -> None:
    protector = CsrfProtector(secret_key="R4ndomLookingCsrfKey_20260524_Value!")
    token = protector.issue(session_token_hash="session-hash")
    protector.verify(token.value, session_token_hash="session-hash")
    with pytest.raises(Exception):
        protector.verify(token.value, session_token_hash="other-session")
    with pytest.raises(AuthConfigurationError):
        CsrfProtector(secret_key="short")
    with pytest.raises(AuthConfigurationError):
        CsrfProtector(secret_key="x" * 32)
    CsrfProtector(secret_key="x" * 32, allow_weak_dev_secret=True)


def test_magic_link_uses_email_sender_and_login_rate_limit() -> None:
    sender = InMemoryEmailSender()
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.SINGLE_OWNER, owner_email="owner@example.com", login_limit_per_minute=1), email_sender=sender)
    challenge = auth.request_magic_link(email="owner@example.com", return_to="/dashboard")
    assert sender.sent_magic_links[0].token == challenge.token
    auth.bootstrap_owner(email="owner@example.com", password="correct horse battery")
    with pytest.raises(AuthenticationFailed):
        auth.login_password(email="owner@example.com", password="bad-password")
    with pytest.raises(AuthenticationFailed, match="rate limited"):
        auth.login_password(email="owner@example.com", password="bad-password")


def test_admin_service_updates_role_and_revokes_session() -> None:
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.ADMIN_VIEWER, owner_email=None, require_email_verified=False))
    auth.create_user(email="admin@example.com", role=Role.ADMIN, password="correct horse battery", email_verified=True)
    viewer = auth.create_user(email="viewer@example.com", role=Role.VIEWER, password="correct horse battery", email_verified=True)
    owner_session = auth.login_password(email="admin@example.com", password="correct horse battery")
    viewer_session = auth.login_password(email="viewer@example.com", password="correct horse battery")
    admin = CorelineAdminService(auth)
    assert admin.update_user_role(actor_session_token=owner_session.token, user_id=viewer.id, role=Role.ADMIN).role == Role.ADMIN
    admin.revoke_session(actor_session_token=owner_session.token, session_id=viewer_session.session.id)
    assert auth.storage.get_session_by_token_hash(viewer_session.session.session_token_hash).revoked_at is not None


def test_rate_limiter_cleans_expired_buckets_and_caps_new_keys() -> None:
    limiter = FixedWindowRateLimiter(max_buckets=2)
    assert limiter.check("a", limit=1, window_seconds=10).allowed
    assert limiter.check("b", limit=1, window_seconds=10).allowed
    assert limiter.check("c", limit=1, window_seconds=10).allowed
    assert limiter.bucket_count == 2

    removed = limiter.cleanup_expired(now=float("inf"))

    assert removed == 2
    assert limiter.bucket_count == 0


def test_login_flow_model_does_not_expose_pkce_verifier_storage() -> None:
    # PKCE verifiers are returned to the host integration at authorization
    # start time. The core model intentionally does not provide a persistence
    # field with a misleading "_encrypted" suffix.
    from coreline_auth import LoginFlow

    assert "pkce_verifier_encrypted" not in LoginFlow.__dataclass_fields__


def test_fixed_window_rate_limiter_documents_process_local_scope() -> None:
    assert FixedWindowRateLimiter.scope == "process"
