from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Thread

import pytest

from coreline_auth import AuthProfile, AuthenticationFailed, AuthorizationDenied, CorelineAuthConfig, CorelineAuthService, RequestContext, Role, SocialProfile
from coreline_auth.errors import AuthValidationError
from coreline_auth.security import hash_secret
from coreline_auth.models import now_utc
from coreline_auth.storage import MemoryAuthStorage, SQLiteAuthStorage


class CountingMemoryAuthStorage(MemoryAuthStorage):
    def __init__(self) -> None:
        super().__init__()
        self.session_updates = 0

    def touch_session(self, session_id, *, last_seen_at, idle_expires_at):
        self.session_updates += 1
        return super().touch_session(session_id, last_seen_at=last_seen_at, idle_expires_at=idle_expires_at)


def make_service(storage=None, *, owner_email: str = "owner@example.com") -> CorelineAuthService:
    return CorelineAuthService(storage=storage or MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.SINGLE_OWNER, owner_email=owner_email))


def test_import_guard_no_host_project_imports() -> None:
    src = Path(__file__).parents[1] / "src" / "coreline_auth"
    offenders = [path.relative_to(src) for path in src.rglob("*.py") if "coremcp" in path.read_text().lower()]
    assert offenders == []


def test_single_owner_password_login_and_session_hash_only() -> None:
    service = make_service()
    service.bootstrap_owner(email="owner@example.com", password="correct horse battery")
    issued = service.login_password(email="OWNER@example.com", password="correct horse battery", context=RequestContext(ip="127.0.0.1", user_agent="pytest"))
    assert issued.token != issued.session.session_token_hash
    assert issued.session.session_token_hash == hash_secret(issued.token)
    principal = service.verify_session(issued.token, required_permission="services:write")
    assert principal.email == "owner@example.com"
    assert principal.session.role == Role.OWNER


def test_wrong_password_and_other_email_rejected() -> None:
    service = make_service()
    service.bootstrap_owner(email="owner@example.com", password="correct horse battery")
    with pytest.raises(AuthenticationFailed):
        service.login_password(email="owner@example.com", password="bad-password")
    with pytest.raises(AuthorizationDenied):
        service.create_user(email="other@example.com", password="correct horse battery")


def test_email_addresses_are_validated_and_normalized() -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))

    user = service.create_user(email="USER@EXAMPLE.COM", password="correct horse battery", email_verified=True)

    assert user.primary_email == "user@example.com"
    with pytest.raises(AuthValidationError):
        service.create_user(email="bad\r\n@example.com", password="correct horse battery")
    with pytest.raises(AuthValidationError):
        service.create_user(email="user@example..com", password="correct horse battery")
    with pytest.raises(AuthValidationError):
        service.create_user(email="user@localhost", password="correct horse battery")


def test_bootstrap_owner_uses_normalized_existing_email() -> None:
    service = make_service()
    created = service.bootstrap_owner(email="owner@example.com", password="correct horse battery")

    existing = service.bootstrap_owner(email="OWNER@EXAMPLE.COM", password="new correct horse")

    assert existing.id == created.id
    assert service.login_password(email="owner@example.com", password="new correct horse").session.user_id == created.id


def test_magic_link_is_one_time_and_hash_only() -> None:
    service = make_service()
    challenge = service.request_magic_link(email="owner@example.com")
    flow = service.storage.get_login_flow_by_state_hash(hash_secret(challenge.token))
    assert flow is not None
    assert challenge.token != flow.state_hash
    issued = service.consume_magic_link(token=challenge.token)
    assert service.verify_session(issued.token).email == "owner@example.com"
    with pytest.raises(AuthenticationFailed):
        service.consume_magic_link(token=challenge.token)


def test_return_to_open_redirect_rejected() -> None:
    service = make_service()
    with pytest.raises(AuthValidationError):
        service.request_magic_link(email="owner@example.com", return_to="https://evil.example/callback")
    with pytest.raises(AuthValidationError):
        service.request_magic_link(email="owner@example.com", return_to="//evil.example/callback")
    with pytest.raises(AuthValidationError):
        service.request_magic_link(email="owner@example.com", return_to="/dashboard' onclick='alert(1)")
    with pytest.raises(AuthValidationError):
        service.request_magic_link(email="owner@example.com", return_to="/dashboard\r\nX-Injected: 1")


def test_sqlite_storage_does_not_store_raw_session_token_or_password(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    storage = SQLiteAuthStorage(db_path)
    try:
        service = make_service(storage=storage)
        service.bootstrap_owner(email="owner@example.com", password="correct horse battery")
        issued = service.login_password(email="owner@example.com", password="correct horse battery")
    finally:
        storage.close()
    raw = db_path.read_bytes()
    assert issued.token.encode() not in raw
    assert b"correct horse battery" not in raw
    db = sqlite3.connect(db_path)
    try:
        stored_hash = db.execute("SELECT session_token_hash FROM auth_sessions").fetchone()[0]
        assert stored_hash == hash_secret(issued.token)
    finally:
        db.close()


def test_password_can_be_rotated_sqlite(tmp_path: Path) -> None:
    storage = SQLiteAuthStorage(tmp_path / "auth.sqlite3")
    try:
        service = make_service(storage=storage)
        service.bootstrap_owner(email="owner@example.com", password="correct horse battery")
        service.bootstrap_owner(email="owner@example.com", password="new correct horse")
        issued = service.login_password(email="owner@example.com", password="new correct horse")
        assert service.verify_session(issued.token).email == "owner@example.com"
        with pytest.raises(AuthenticationFailed):
            service.login_password(email="owner@example.com", password="correct horse battery")
    finally:
        storage.close()


def test_login_missing_user_runs_dummy_password_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    calls: list[str] = []

    def fake_dummy(password: str) -> None:
        calls.append(password)

    monkeypatch.setattr("coreline_auth.service.verify_dummy_password", fake_dummy)

    with pytest.raises(AuthenticationFailed):
        service.login_password(email="missing@example.com", password="wrong password")

    assert calls == ["wrong password"]


def test_password_reset_revokes_existing_sessions() -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    service.create_user(email="user@example.com", password="old correct horse", email_verified=True)
    old_session = service.login_password(email="user@example.com", password="old correct horse")
    token = service.request_password_reset("user@example.com").token

    service.consume_password_reset(token, "new correct horse")

    with pytest.raises(AuthenticationFailed):
        service.verify_session(old_session.token)
    assert service.login_password(email="user@example.com", password="new correct horse").session.user_id == old_session.session.user_id


def test_set_password_revokes_sessions_by_default_and_can_preserve_current() -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    user = service.create_user(email="user@example.com", password="old correct horse", email_verified=True)
    first = service.login_password(email="user@example.com", password="old correct horse")
    second = service.login_password(email="user@example.com", password="old correct horse")

    service.set_password(user.id, "new correct horse", except_session_id=second.session.id)

    with pytest.raises(AuthenticationFailed):
        service.verify_session(first.token)
    assert service.verify_session(second.token).user_id == user.id
    assert service.login_password(email="user@example.com", password="new correct horse").session.user_id == user.id

    service.set_password(user.id, "third correct horse")
    with pytest.raises(AuthenticationFailed):
        service.verify_session(second.token)


def test_social_login_does_not_link_unverified_provider_email_to_existing_user() -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    existing = service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)

    with pytest.raises(AuthenticationFailed):
        service.login_social(
            profile=SocialProfile(
                provider="google",
                provider_subject="google-sub",
                email="user@example.com",
                email_verified=False,
            )
        )

    assert service.storage.get_identity("google", "google-sub") is None
    assert service.storage.get_user_by_email("user@example.com") == existing


def test_social_login_state_binds_nonce_and_is_one_time() -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    state = service.begin_social_login(provider="google", return_to="/dashboard", nonce="nonce-1")

    with pytest.raises(AuthenticationFailed):
        service.consume_social_login_state(provider="google", state=state, nonce="wrong-nonce")

    flow = service.consume_social_login_state(provider="google", state=state, nonce="nonce-1")

    assert flow.return_to == "/dashboard"
    with pytest.raises(AuthenticationFailed):
        service.consume_social_login_state(provider="google", state=state, nonce="nonce-1")


def test_session_touch_interval_throttles_touch_session() -> None:
    storage = CountingMemoryAuthStorage()
    service = CorelineAuthService(
        storage=storage,
        config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False, session_touch_interval_seconds=60),
    )
    service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")

    service.verify_session(issued.token)

    assert storage.session_updates == 0


def test_session_touch_interval_zero_touches_session() -> None:
    storage = CountingMemoryAuthStorage()
    service = CorelineAuthService(
        storage=storage,
        config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False, session_touch_interval_seconds=0),
    )
    service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")

    service.verify_session(issued.token)

    assert storage.session_updates == 1



def test_stale_touch_does_not_resurrect_revoked_session() -> None:
    class BlockingTouchStorage(MemoryAuthStorage):
        def __init__(self) -> None:
            super().__init__()
            self.before_touch = Event()
            self.allow_touch = Event()

        def touch_session(self, session_id, *, last_seen_at, idle_expires_at):
            self.before_touch.set()
            assert self.allow_touch.wait(timeout=2)
            return super().touch_session(session_id, last_seen_at=last_seen_at, idle_expires_at=idle_expires_at)

    storage = BlockingTouchStorage()
    service = CorelineAuthService(
        storage=storage,
        config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False, session_touch_interval_seconds=0),
    )
    service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")
    failures: list[Exception] = []

    def verify() -> None:
        try:
            service.verify_session(issued.token)
        except Exception as exc:  # noqa: BLE001 - test captures auth failure from racing revoke
            failures.append(exc)

    thread = Thread(target=verify)
    thread.start()
    assert storage.before_touch.wait(timeout=2)
    service.logout(issued.token)
    storage.allow_touch.set()
    thread.join(timeout=2)

    assert isinstance(failures[0], AuthenticationFailed)
    assert storage.get_session_by_token_hash(issued.session.session_token_hash).revoked_at is not None


def test_update_session_preserves_existing_revocation() -> None:
    storage = MemoryAuthStorage()
    service = CorelineAuthService(storage=storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")

    storage.revoke_session(issued.session.id)
    storage.update_session(replace(issued.session, last_seen_at=now_utc() + timedelta(seconds=30)))

    assert storage.get_session_by_token_hash(issued.session.session_token_hash).revoked_at is not None

def test_cleanup_expired_revokes_sessions_and_removes_login_flows() -> None:
    storage = MemoryAuthStorage()
    service = CorelineAuthService(storage=storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")
    expired = replace(issued.session, expires_at=now_utc() - timedelta(seconds=1))
    storage.update_session(expired)
    challenge = service.request_password_reset("user@example.com")
    flow = storage.get_login_flow_by_state_hash(hash_secret(challenge.token))
    assert flow is not None
    storage.update_login_flow(replace(flow, expires_at=now_utc() - timedelta(seconds=1)))

    result = service.cleanup_expired()

    assert result == {"sessions": 1, "login_flows": 1}
    assert storage.get_session_by_token_hash(issued.session.session_token_hash).revoked_at is not None
    assert storage.get_login_flow_by_state_hash(hash_secret(challenge.token)) is None


def test_sqlite_storage_pragmas_indexes_and_list_filters(tmp_path: Path) -> None:
    storage = SQLiteAuthStorage(tmp_path / "auth.sqlite3")
    try:
        service = CorelineAuthService(storage=storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
        service.create_user(email="viewer@example.com", role=Role.VIEWER, password="correct horse battery", email_verified=True, display_name="Viewer")
        service.create_user(email="user2@example.com", role=Role.USER, password="correct horse battery", email_verified=True, display_name="User Two")

        assert storage.db.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        assert storage.db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        index_names = {row[1] for row in storage.db.execute("PRAGMA index_list(auth_sessions)").fetchall()}
        assert "ix_auth_sessions_expires" in index_names
        assert [user.primary_email for user in storage.list_users(role=Role.USER)] == ["user2@example.com"]
        assert [user.primary_email for user in storage.list_users(query="view", limit=1)] == ["viewer@example.com"]
    finally:
        storage.close()


def test_sqlite_concurrent_session_verify_smoke(tmp_path: Path) -> None:
    storage = SQLiteAuthStorage(tmp_path / "auth.sqlite3")
    try:
        service = CorelineAuthService(
            storage=storage,
            config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False, session_touch_interval_seconds=0),
        )
        service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
        issued = service.login_password(email="user@example.com", password="correct horse battery")

        with ThreadPoolExecutor(max_workers=4) as pool:
            emails = list(pool.map(lambda _: service.verify_session(issued.token).email, range(12)))

        assert emails == ["user@example.com"] * 12
    finally:
        storage.close()


def test_sqlite_audit_events_persist_after_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    storage = SQLiteAuthStorage(db_path)
    try:
        service = CorelineAuthService(storage=storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
        user = service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
        service._audit("auth.test.persist", target_user_id=user.id, metadata={"refresh_token": "raw-refresh-token"})
    finally:
        storage.close()

    reopened = SQLiteAuthStorage(db_path)
    try:
        events = reopened.list_audit_events(action="auth.test.persist")
        assert len(events) == 1
        assert events[0].target_user_id == user.id
        assert events[0].metadata["refresh_token"] == "[REDACTED]"
    finally:
        reopened.close()
